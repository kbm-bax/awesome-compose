#!/usr/bin/env python3
"""Spec for the order API request-body limit.

The create, bulk-create, and update routes must refuse a body larger than
MAX_BODY_BYTES (64 KiB) with HTTP 413 before they read the rest of the body.
A body of exactly MAX_BODY_BYTES must still be accepted. The backend service
in compose.yml must also set a memory limit of at most MAX_CONTAINER_MEMORY_BYTES.

These tests fail while the handlers buffer the whole body and the compose file
sets no memory limit. They pass once both parts of that fix are in place.
POST /echo is not covered: it streams the request body back and does not
buffer it with the other three routes.

Run from wasmedge-mysql-nginx/backend, after the Wasm binary is built and
MariaDB is reachable at the fallback database URL in src/main.rs:

    cargo build --target wasm32-wasip1 --release
    python3 tests/request_body_limit.py
"""

import os
import signal
import socket
import subprocess
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILE = BACKEND_DIR.parent / "compose.yml"

MAX_BODY_BYTES = 64 * 1024
MAX_CONTAINER_MEMORY_BYTES = 512 * 1024 * 1024
DECLARED_OVERSIZE = 8 * 1024 * 1024
RESPONSE_TIMEOUT_SECONDS = 3

ROUTES = ("/create_order", "/create_orders", "/update_order")

ORDER_FIXED = (
    '{"order_id":1,"product_id":2,"quantity":1,"amount":1.0,'
    '"shipping":0.0,"tax":0.0,"shipping_address":"x","pad":"'
)
ORDER_END = '"}'


def find_wasm():
    candidates = [
        BACKEND_DIR / "target" / "wasm32-wasip1" / "release" / "order_demo_service.wasm",
        BACKEND_DIR / "target" / "wasm32-wasi" / "release" / "order_demo_service.wasm",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise unittest.SkipTest(
        "order_demo_service.wasm is missing; build the backend for wasm32-wasip1 first"
    )


def find_wasmedge():
    env = os.environ.get("WASMEDGE")
    if env and Path(env).is_file():
        return env
    for candidate in ("/opt/wasmedge/bin/wasmedge", "/usr/local/bin/wasmedge"):
        if Path(candidate).is_file():
            return candidate
    from shutil import which

    found = which("wasmedge")
    if found:
        return found
    raise unittest.SkipTest("wasmedge is not installed")


def order_body(total_len, as_array):
    """JSON order body of exactly total_len bytes. The extra field is ignored."""
    wrapper = 2 if as_array else 0
    pad_len = total_len - len(ORDER_FIXED) - len(ORDER_END) - wrapper
    if pad_len < 0:
        raise AssertionError("requested order body is shorter than the fixed JSON")
    body = ORDER_FIXED + ("p" * pad_len) + ORDER_END
    if as_array:
        body = "[" + body + "]"
    if len(body.encode()) != total_len:
        raise AssertionError("order body length math is wrong")
    return body.encode()


def http_exchange(host, port, request, timeout):
    """Send raw HTTP bytes and return the status code, or None on timeout."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        try:
            sock.sendall(request)
        except (BrokenPipeError, ConnectionResetError):
            return None
        sock.settimeout(timeout)
        data = b""
        try:
            while b"\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except socket.timeout:
            return None
        except ConnectionResetError:
            return None
        if not data:
            return None
        line = data.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        parts = line.split(" ")
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        return int(parts[1])
    finally:
        sock.close()


def post_headers(route, extra):
    return (
        f"POST {route} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        f"{extra}"
        "Connection: close\r\n"
        "\r\n"
    ).encode()


def memory_values(service_block):
    """Collect memory-limit quantities from one compose service block."""
    values = []
    lines = service_block.splitlines()
    for index, line in enumerate(lines):
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("mem_limit:"):
            values.append(stripped.split(":", 1)[1].strip())
        if stripped == "memory:" or stripped.startswith("memory:"):
            # Only the resources.limits.memory key, which is nested under limits.
            indent = len(line) - len(line.lstrip(" "))
            window = "\n".join(lines[max(0, index - 6) : index + 1])
            if "limits:" in window and "resources:" in window:
                if stripped == "memory:":
                    if index + 1 < len(lines):
                        values.append(lines[index + 1].strip())
                else:
                    values.append(stripped.split(":", 1)[1].strip())
                _ = indent
    return values


def parse_memory(text):
    token = text.strip().strip("\"'").replace(" ", "")
    if not token:
        return None
    suffix = token.lstrip("0123456789")
    number = token[: len(token) - len(suffix)] if suffix else token
    if not number.isdigit():
        return None
    amount = int(number)
    unit = suffix.lower()
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1000,
        "ki": 1024,
        "kib": 1024,
        "m": 1024 ** 2,
        "mb": 1000 ** 2,
        "mi": 1024 ** 2,
        "mib": 1024 ** 2,
        "g": 1024 ** 3,
        "gb": 1000 ** 3,
        "gi": 1024 ** 3,
        "gib": 1024 ** 3,
    }
    if unit not in multipliers:
        return None
    return amount * multipliers[unit]


def service_block(text, name):
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith(f"  {name}:"):
            start = index
            break
    if start is None:
        return ""
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("   ") and line.strip():
            break
        block.append(line)
    return "\n".join(block)


class OrderBodyLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wasm = find_wasm()
        cls.wasmedge = find_wasmedge()
        cls.server = None

    def setUp(self):
        self._start_server()
        status = self._request(b"GET /init HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        self.assertEqual(
            status,
            200,
            "GET /init did not succeed; the fallback database URL in src/main.rs is not reachable",
        )

    def tearDown(self):
        self._stop_server()

    def _start_server(self):
        self._stop_server()
        env = os.environ.copy()
        env.pop("DATABASE_URL", None)
        lib = str(Path(self.wasmedge).resolve().parents[1] / "lib")
        if Path(lib, "libwasmedge.so").is_file():
            env["LD_LIBRARY_PATH"] = lib + (
                ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""
            )
        self.server = subprocess.Popen(
            [self.wasmedge, "run", str(self.wasm)],
            cwd=str(BACKEND_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.time() + 10
        last_error = None
        while time.time() < deadline:
            if self.server.poll() is not None:
                err = self.server.stderr.read().decode("utf-8", "replace")
                self.fail(f"order API exited during startup: {err}")
            try:
                sock = socket.create_connection(("127.0.0.1", 8080), timeout=0.2)
                sock.close()
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        self._stop_server()
        self.fail(f"order API did not listen on port 8080 ({last_error})")

    def _stop_server(self):
        server = getattr(self, "server", None)
        if server is None or server.poll() is not None:
            self.server = None
            return
        try:
            os.killpg(server.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        server.wait(timeout=5)
        if server.stderr is not None:
            server.stderr.close()
        self.server = None

    def _restart_ready_server(self):
        self._start_server()
        status = self._request(b"GET /init HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        self.assertEqual(status, 200, "GET /init failed after restart")

    def _request(self, payload):
        return http_exchange("127.0.0.1", 8080, payload, RESPONSE_TIMEOUT_SECONDS)

    def _post(self, route, body, content_length=None):
        length = len(body) if content_length is None else content_length
        head = post_headers(route, f"Content-Length: {length}\r\n")
        return self._request(head + body)

    def test_body_at_limit_is_accepted(self):
        for route in ROUTES:
            with self.subTest(route=route):
                body = order_body(MAX_BODY_BYTES, as_array=(route == "/create_orders"))
                status = self._post(route, body)
                self.assertEqual(status, 200, route)

    def test_content_length_over_limit_is_rejected_before_the_rest_is_read(self):
        """Refuse once the buffered prefix exceeds the limit, without the remainder."""
        for route in ROUTES:
            with self.subTest(route=route):
                self._restart_ready_server()
                prefix = b"{" + (b"x" * MAX_BODY_BYTES)
                self.assertGreater(DECLARED_OVERSIZE, len(prefix))
                head = post_headers(route, f"Content-Length: {DECLARED_OVERSIZE}\r\n")
                status = self._request(head + prefix)
                self.assertEqual(status, 413, route)
                follow = self._request(
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                self.assertEqual(follow, 200, f"{route} stopped the server")

    def test_chunked_body_over_limit_is_rejected_before_the_terminator(self):
        for route in ROUTES:
            with self.subTest(route=route):
                self._restart_ready_server()
                chunk = b"{" + (b"y" * MAX_BODY_BYTES)
                framed = f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                head = post_headers(route, "Transfer-Encoding: chunked\r\n")
                status = self._request(head + framed)
                self.assertEqual(status, 413, route)

    def test_completed_oversize_body_returns_413_and_leaves_the_server_up(self):
        for route in ROUTES:
            with self.subTest(route=route):
                self._restart_ready_server()
                body = b"{" + (b"z" * MAX_BODY_BYTES)
                self.assertEqual(len(body), MAX_BODY_BYTES + 1)
                status = self._post(route, body)
                self.assertEqual(status, 413, route)
                follow = self._request(
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                self.assertEqual(follow, 200, f"{route} stopped the server")

    def test_compose_backend_memory_limit(self):
        text = COMPOSE_FILE.read_text()
        block = service_block(text, "backend")
        self.assertTrue(block, "compose.yml has no backend service")
        limits = [parse_memory(value) for value in memory_values(block)]
        limits = [value for value in limits if value]
        self.assertTrue(
            limits,
            "backend service in compose.yml does not set mem_limit or deploy.resources.limits.memory",
        )
        self.assertTrue(
            any(0 < value <= MAX_CONTAINER_MEMORY_BYTES for value in limits),
            "backend memory limit must be at most 512 MiB",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
