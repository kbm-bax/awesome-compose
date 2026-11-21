#!/usr/bin/env python3
"""Published Redis in the Compose samples must reject unauthenticated clients.

These tests start the redis service from each sample Compose file and, from
the host, send Redis commands with no AUTH. They fail while that client can
read or write keys or run the RedisGears Python command. They pass once a
host connection is refused, or the server rejects the commands before running
them and before creating the probe file inside the container.

Run from the repository root:

    python3 tests/test_published_redis_requires_auth.py
"""

import json
import socket
import subprocess
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_PATH = "/tmp/unauth-redis-probe"
# Executed only if RedisGears accepts RG.PYEXECUTE. The file is the
# side-effect oracle: a reply that looks like a refusal still fails the
# test when this file was created.
PROBE_SCRIPT = (
    "f=open('%s','w')\n"
    "f.write('ran')\n"
    "f.close()\n" % PROBE_PATH
)
KEY_COMMANDS = (
    ("SET", "unauth-probe-key", "ran"),
    ("GET", "unauth-probe-key"),
    ("DEL", "unauth-probe-key"),
)
SAMPLES = (
    {
        "name": "nginx-nodejs-redis",
        "compose_file": "nginx-nodejs-redis/compose.yaml",
    },
    {
        "name": "flask-redis",
        "compose_file": "flask-redis/compose.yaml",
    },
)


def docker_base():
    probe = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if probe.returncode == 0:
        return ["docker"]
    if "permission denied" in probe.stderr.lower() or "cannot connect" in probe.stderr.lower():
        sudo = subprocess.run(
            ["sudo", "-n", "docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if sudo.returncode == 0:
            return ["sudo", "-n", "docker"]
    raise AssertionError(
        "docker is not usable: %s" % (probe.stderr.strip() or "docker info failed")
    )


DOCKER = None


def docker(*args, check=True, timeout=180):
    global DOCKER
    if DOCKER is None:
        DOCKER = docker_base()
    completed = subprocess.run(
        DOCKER + list(args),
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            "command failed: %s\nstdout:\n%s\nstderr:\n%s"
            % (" ".join(DOCKER + list(args)), completed.stdout, completed.stderr)
        )
    return completed


def compose(compose_file, project, *args, check=True, timeout=180):
    return docker(
        "compose",
        "-f",
        compose_file,
        "-p",
        project,
        *args,
        check=check,
        timeout=timeout,
    )


class RespError(Exception):
    pass


def _recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise RespError("connection closed")
        buf += chunk
    return buf


def _read_line(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise RespError("connection closed")
        buf += chunk
        if len(buf) > 1024 * 1024:
            raise RespError("reply line too long")
    return buf[:-2]


def read_resp(sock):
    prefix = _recv_exact(sock, 1)
    if prefix == b"+":
        return ("simple", _read_line(sock).decode("utf-8", "replace"))
    if prefix == b"-":
        return ("error", _read_line(sock).decode("utf-8", "replace"))
    if prefix == b":":
        return ("int", int(_read_line(sock)))
    if prefix == b"$":
        length = int(_read_line(sock))
        if length < 0:
            return ("bulk", None)
        data = _recv_exact(sock, length)
        _recv_exact(sock, 2)
        return ("bulk", data)
    if prefix == b"*":
        length = int(_read_line(sock))
        if length < 0:
            return ("array", None)
        return ("array", [read_resp(sock) for _ in range(length)])
    raise RespError("unexpected reply prefix %r" % prefix)


def encode_command(args):
    parts = [b"*%d\r\n" % len(args)]
    for arg in args:
        raw = arg.encode("utf-8")
        parts.append(b"$%d\r\n" % len(raw))
        parts.append(raw)
        parts.append(b"\r\n")
    return b"".join(parts)


def send_command(host, port, args, timeout=15):
    sock = socket.create_connection((host, port), timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(encode_command(args))
        return read_resp(sock)
    finally:
        sock.close()


def command_was_refused(reply):
    kind, value = reply
    if kind != "error":
        return False
    text = value.upper()
    return (
        text.startswith("NOAUTH")
        or text.startswith("NOPERM")
        or text.startswith("WRONGPASS")
        or text.startswith("DENIED")
    )


def published_endpoints(compose_file, project):
    listed = compose(compose_file, project, "ps", "-q", "redis", check=False)
    container_id = listed.stdout.strip().splitlines()
    if not container_id:
        return []
    inspected = docker("inspect", container_id[0], check=False)
    if inspected.returncode != 0:
        return []
    payload = json.loads(inspected.stdout)
    bindings = (payload[0].get("NetworkSettings") or {}).get("Ports") or {}
    published = bindings.get("6379/tcp") or []
    endpoints = []
    for binding in published:
        host = binding.get("HostIp") or "0.0.0.0"
        port = int(binding["HostPort"])
        if host in ("0.0.0.0", ""):
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        endpoints.append((host, port))
    return endpoints


def redis_is_running(compose_file, project):
    completed = compose(compose_file, project, "ps", "-q", "redis", check=False)
    return bool(completed.stdout.strip())


def probe_file_exists(compose_file, project):
    completed = compose(
        compose_file,
        project,
        "exec",
        "-T",
        "redis",
        "sh",
        "-c",
        "test -e %s" % PROBE_PATH,
        check=False,
    )
    return completed.returncode == 0


class PublishedRedisAuthTest(unittest.TestCase):
    def assert_unauthenticated_redis_is_closed(self, sample):
        compose_file = sample["compose_file"]
        project = "authprobe-%s" % sample["name"]
        self.assertTrue(
            (REPO_ROOT / compose_file).is_file(),
            "missing %s" % compose_file,
        )
        compose(compose_file, project, "down", "--remove-orphans", "-v", check=False)
        try:
            compose(
                compose_file,
                project,
                "up",
                "-d",
                "--quiet-pull",
                "redis",
                timeout=300,
            )
            endpoints = []
            for _ in range(40):
                if not redis_is_running(compose_file, project):
                    time.sleep(0.25)
                    continue
                endpoints = published_endpoints(compose_file, project)
                if endpoints:
                    break
                # The service is up and Compose reports no host port.
                # Give the port mapping a moment to appear, then treat
                # a still-empty result as "not published".
                time.sleep(0.25)
            else:
                if not redis_is_running(compose_file, project):
                    self.fail("redis service from %s did not stay running" % compose_file)

            if not endpoints:
                self.assertFalse(
                    probe_file_exists(compose_file, project),
                    "%s published no host port, but %s exists in the container"
                    % (compose_file, PROBE_PATH),
                )
                return

            replies = []
            accepted = []
            for endpoint in endpoints:
                for args in KEY_COMMANDS + (("RG.PYEXECUTE", PROBE_SCRIPT),):
                    try:
                        reply = send_command(endpoint[0], endpoint[1], args)
                    except (ConnectionRefusedError, TimeoutError, OSError, RespError) as exc:
                        replies.append((endpoint, args[0], ("connection", str(exc))))
                        continue
                    replies.append((endpoint, args[0], reply))
                    if not command_was_refused(reply):
                        accepted.append((endpoint, args[0], reply))
            file_created = probe_file_exists(compose_file, project)
            self.assertFalse(
                accepted or file_created,
                "%s let an unauthenticated client use Redis on the published "
                "port. accepted=%r probe_file_created=%s replies=%r"
                % (compose_file, accepted, file_created, replies),
            )
        finally:
            compose(compose_file, project, "down", "--remove-orphans", "-v", check=False)

    def test_nginx_nodejs_redis_published_port_requires_auth(self):
        self.assert_unauthenticated_redis_is_closed(SAMPLES[0])

    def test_flask_redis_published_port_requires_auth(self):
        self.assert_unauthenticated_redis_is_closed(SAMPLES[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
