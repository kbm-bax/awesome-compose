"""Security spec for Redis services that the compose samples publish.

An unauthenticated client of a Redis port published by these samples must
not be able to read or write keys, and must not be able to run Python or
operating-system commands inside the Redis container.

The tests start the Redis service from each compose file and attempt both
operations with no credentials. They fail while that client can still do
either one.
"""

import os
import shutil
import socket
import subprocess
import time
import unittest


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLES = ("flask-redis", "nginx-nodejs-redis")
MARKER_DIR = "/tmp"
PROBE_KEY = "cursor_unauth_probe"
PROBE_VALUE = "cursor-probe-value"
READY_LINE = b"Ready to accept connections"
START_TIMEOUT_SECONDS = 60


def _docker_prefix():
    docker = shutil.which("docker")
    if docker is None:
        raise unittest.SkipTest("docker is not installed")
    probe = subprocess.run(
        [docker, "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if probe.returncode == 0:
        return [docker]
    sudo = shutil.which("sudo")
    if sudo is None:
        raise AssertionError("docker is installed but this user cannot access the daemon")
    return [sudo, "-n", docker]


DOCKER = None


def docker(*args, cwd, check=True, timeout=180):
    global DOCKER
    if DOCKER is None:
        DOCKER = _docker_prefix()
    completed = subprocess.run(
        [*DOCKER, *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            "docker command failed: {cmd}\nstdout:\n{out}\nstderr:\n{err}".format(
                cmd=" ".join(args),
                out=completed.stdout.decode("utf-8", "replace"),
                err=completed.stderr.decode("utf-8", "replace"),
            )
        )
    return completed


def _encode(*parts):
    body = "*{n}\r\n".format(n=len(parts)).encode()
    for part in parts:
        encoded = part.encode()
        body += "${n}\r\n".format(n=len(encoded)).encode()
        body += encoded + b"\r\n"
    return body


def _published_endpoints(sample_dir):
    identity = docker("compose", "ps", "-q", "redis", cwd=sample_dir, check=False)
    container_id = identity.stdout.decode("utf-8", "replace").strip()
    if not container_id:
        return []
    completed = docker("port", container_id, cwd=sample_dir, check=False)
    text = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not text:
        return []
    endpoints = []
    for line in text.splitlines():
        line = line.strip()
        if "->" in line:
            line = line.split("->", 1)[1].strip()
        if not line or ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        host = host.strip("[]")
        if host in ("0.0.0.0", ""):
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        endpoints.append((host, int(port)))
    return endpoints


def _redis_command(host, port, *parts):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(8)
    try:
        connection.connect((host, port))
        connection.sendall(_encode(*parts))
        chunks = []
        while True:
            try:
                chunk = connection.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) > 65536:
                break
        return b"".join(chunks)
    finally:
        connection.close()


def _wait_until_ready(sample_dir):
    deadline = time.time() + START_TIMEOUT_SECONDS
    last_logs = b""
    while time.time() < deadline:
        state = docker(
            "compose",
            "ps",
            "--status",
            "running",
            "-q",
            "redis",
            cwd=sample_dir,
            check=False,
        )
        logs = docker("compose", "logs", "redis", cwd=sample_dir, check=False)
        last_logs = logs.stdout + logs.stderr
        if state.stdout.strip() and READY_LINE in last_logs:
            return
        exited = docker(
            "compose",
            "ps",
            "--status",
            "exited",
            "-q",
            "redis",
            cwd=sample_dir,
            check=False,
        )
        if exited.stdout.strip():
            raise AssertionError(
                "redis container exited before accepting connections:\n"
                + last_logs.decode("utf-8", "replace")
            )
        time.sleep(0.5)
    raise AssertionError(
        "redis did not become ready:\n" + last_logs.decode("utf-8", "replace")
    )


def _marker_present(sample_dir, marker_path):
    completed = docker(
        "compose",
        "exec",
        "-T",
        "redis",
        "/bin/bash",
        "-lc",
        "if test -f {path}; then echo PRESENT; else echo ABSENT; fi".format(path=marker_path),
        cwd=sample_dir,
        check=False,
    )
    output = completed.stdout.decode("utf-8", "replace")
    if "PRESENT" in output:
        return True
    if "ABSENT" in output:
        return False
    raise AssertionError(
        "could not check whether the code-execution marker was created\n"
        + completed.stderr.decode("utf-8", "replace")
    )


class PublishedRedisRejectsUnauthenticatedAccess(unittest.TestCase):
    def tearDown(self):
        sample_dir = getattr(self, "_sample_dir", None)
        if sample_dir:
            docker("compose", "down", "--remove-orphans", cwd=sample_dir, check=False)

    def test_each_published_redismod_service(self):
        for sample in SAMPLES:
            with self.subTest(sample=sample):
                self._assert_sample_rejects_unauthenticated_client(sample)

    def _assert_sample_rejects_unauthenticated_client(self, sample):
        sample_dir = os.path.join(REPO_ROOT, sample)
        self._sample_dir = sample_dir
        docker("compose", "down", "--remove-orphans", cwd=sample_dir, check=False)
        docker("compose", "up", "-d", "redis", cwd=sample_dir, timeout=300)
        try:
            _wait_until_ready(sample_dir)
            endpoints = _published_endpoints(sample_dir)
            if not endpoints:
                self.assertFalse(
                    _marker_present(sample_dir, MARKER_DIR + "/cursor-redis-exec-marker"),
                    "redis wrote an execution marker without publishing a port",
                )
                return

            failures = []
            for host, port in endpoints:
                failures.extend(self._attempt(sample_dir, host, port))
            if failures:
                self.fail(
                    "{sample} accepts unauthenticated Redis access:\n{details}".format(
                        sample=sample,
                        details="\n".join(failures),
                    )
                )
        finally:
            docker("compose", "down", "--remove-orphans", cwd=sample_dir, check=False)
            self._sample_dir = None

    def _attempt(self, sample_dir, host, port):
        failures = []
        try:
            write_reply = _redis_command(host, port, "SET", PROBE_KEY, PROBE_VALUE)
            read_reply = _redis_command(host, port, "GET", PROBE_KEY)
        except OSError:
            # The published address does not accept a TCP connection.
            return []

        write_text = write_reply.decode("utf-8", "replace")
        read_text = read_reply.decode("utf-8", "replace")
        if write_reply.startswith(b"+OK") or PROBE_VALUE.encode() in read_reply:
            failures.append(
                "{host}:{port} stored a key without authentication\nSET {write}\nGET {read}".format(
                    host=host,
                    port=port,
                    write=write_text,
                    read=read_text,
                )
            )

        marker_path = "{directory}/cursor-redis-exec-marker-{port}-{which}".format(
            directory=MARKER_DIR,
            port=port,
            which="v6" if ":" in host else "v4",
        )
        script = (
            "open('{path}','w').write('executed')\n"
            "import os\n"
            "raise Exception('OSOUT:' + os.popen('id').read())\n"
        ).format(path=marker_path)
        try:
            exec_reply = _redis_command(host, port, "rg.pyexecute", script)
        except OSError as exc:
            exec_reply = str(exc).encode()
        exec_text = exec_reply.decode("utf-8", "replace")
        marker_present = _marker_present(sample_dir, marker_path)
        if marker_present or b"OSOUT:" in exec_reply or b"uid=" in exec_reply:
            failures.append(
                "{host}:{port} ran attacker Python inside Redis "
                "(marker_present={marker})\n{reply}".format(
                    host=host,
                    port=port,
                    marker=marker_present,
                    reply=exec_text,
                )
            )
        return failures


if __name__ == "__main__":
    unittest.main()
