#!/usr/bin/env python3
"""Order write endpoints must reject bad JSON with HTTP 400 and keep serving.

POST /create_order, POST /create_orders, and POST /update_order currently
unwrap serde_json failures. On the wasm32-wasi / wasm32-wasip1 target that
aborts the process, so one invalid body takes the published API down.

These checks fail while that panic is present. They pass when each handler
returns HTTP 400 for a body that is not the expected order value, does not
insert or update a row, and the same process still serves reads and writes.

Run from anywhere:

    python3 wasmedge-mysql-nginx/backend/tests/invalid_order_json_returns_400.py

The script builds the release Wasm module and runs it under WasmEdge.
MySQL or MariaDB must accept the connection the service opens. When
DATABASE_URL is unset, that is the URL chosen by get_url() in
backend/src/main.rs. When DATABASE_URL is set, it is passed into the guest
and is never printed. WasmEdge must be on PATH or in WASMEDGE.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8080
BACKEND = Path(__file__).resolve().parents[1]
VALID_ORDER = {
    "order_id": 101,
    "product_id": 12,
    "quantity": 2,
    "amount": 56.0,
    "shipping": 15.0,
    "tax": 2.0,
    "shipping_address": "Mataderos",
}
VALID_ORDERS = [
    {
        "order_id": 102,
        "product_id": 15,
        "quantity": 3,
        "amount": 1.0,
        "shipping": 1.0,
        "tax": 1.0,
        "shipping_address": "Bobcat",
    }
]
VALID_UPDATE = {
    "order_id": 102,
    "product_id": 15,
    "quantity": 9,
    "amount": 1.0,
    "shipping": 1.0,
    "tax": 1.0,
    "shipping_address": "Updated",
}

# Bodies that are not the value the handler deserializes. Each one must be
# rejected before any database write.
REJECTED_BODIES = [
    b"",
    b"not-json",
    b"{}",
    b"[]",
    b"null",
    b'{"order_id":1}',
]


class CaseFailure(Exception):
    pass


def cargo_invocation() -> list[str]:
    rustup = shutil.which("rustup")
    if rustup:
        probe = subprocess.run(
            [rustup, "run", "stable", "rustc", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return [rustup, "run", "stable", "cargo"]
    return ["cargo"]


def rustc_invocation(cargo: list[str]) -> list[str]:
    if len(cargo) >= 4 and Path(cargo[0]).name == "rustup" and cargo[1] == "run":
        return [cargo[0], "run", cargo[2], "rustc"]
    return ["rustc"]


def target_loads(cargo: list[str], name: str) -> bool:
    probe = subprocess.run(
        rustc_invocation(cargo) + ["--print", "cfg", "--target", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return probe.returncode == 0


def wasm_target(cargo: list[str]) -> str:
    # The image builds wasm32-wasi. Newer toolchains renamed that target but
    # still abort on panic. Use the first name this toolchain can actually load.
    for name in ("wasm32-wasi", "wasm32-wasip1"):
        if target_loads(cargo, name):
            return name
    raise SystemExit("rustc cannot load wasm32-wasi or wasm32-wasip1")


def ensure_target(cargo: list[str], target: str) -> None:
    installed = subprocess.run(
        rustc_invocation(cargo) + ["--print", "target-libdir", "--target", target],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if installed.returncode == 0 and installed.stdout.strip():
        return
    rustup = shutil.which("rustup")
    if not rustup:
        raise SystemExit(f"target {target} is not installed")
    toolchain = (
        cargo[2]
        if len(cargo) >= 4 and Path(cargo[0]).name == "rustup" and cargo[1] == "run"
        else "stable"
    )
    subprocess.run([rustup, "target", "add", target, "--toolchain", toolchain], check=True)


def build_wasm(cargo: list[str], target: str) -> Path:
    # flate2 1.0.25+ refuses to compile with default features disabled, which
    # is how mysql_async_wasi depends on it. Pin a version that still builds.
    subprocess.run(
        cargo + ["update", "-p", "flate2", "--precise", "1.0.22"],
        cwd=BACKEND,
        check=True,
    )
    subprocess.run(
        cargo + ["build", "--target", target, "--release"],
        cwd=BACKEND,
        check=True,
    )
    wasm = BACKEND / "target" / target / "release" / "order_demo_service.wasm"
    if not wasm.is_file():
        raise SystemExit(f"missing wasm module at {wasm}")
    return wasm


def wasmedge_bin() -> str:
    override = os.environ.get("WASMEDGE")
    if override:
        return override
    found = shutil.which("wasmedge")
    if found:
        return found
    home = Path.home() / ".wasmedge" / "bin" / "wasmedge"
    if home.is_file():
        return str(home)
    raise SystemExit("wasmedge not found (set WASMEDGE or install it on PATH)")


def port_open() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=0.2):
            return True
    except OSError:
        return False


def http_exchange(method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        payload = resp.read()
        return resp.status, payload
    finally:
        conn.close()


class Server:
    def __init__(self, wasmedge: str, wasm: Path, log_path: Path):
        cmd = [wasmedge]
        database_url = os.environ.get("DATABASE_URL")
        if database_url:
            cmd.append(f"--env=DATABASE_URL={database_url}")
        cmd.append(str(wasm))
        self.log = log_path.open("w")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=self.log)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            if port_open():
                return
            time.sleep(0.1)
        self.close()
        raise CaseFailure(self.failure_text("server did not stay up on port 8080"))

    def alive(self) -> bool:
        return self.proc.poll() is None

    def failure_text(self, message: str) -> str:
        self.log.flush()
        text = self.log.name and Path(self.log.name).read_text(errors="replace")[-800:]
        code = self.proc.poll()
        return f"{message}; exit={code}; log_tail={text!r}"

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self.log.close()


def expect_status(status: int, body: bytes, expected: int, what: str) -> None:
    if status != expected:
        raise CaseFailure(f"{what}: expected HTTP {expected}, got {status}, body={body[:200]!r}")


def snapshot_orders() -> list:
    status, body = http_exchange("GET", "/orders")
    expect_status(status, body, 200, "GET /orders")
    return json.loads(body.decode())


def require_alive(server: Server, what: str) -> None:
    if not server.alive():
        raise CaseFailure(server.failure_text(f"{what}: process exited"))
    status, body = http_exchange("GET", "/")
    expect_status(status, body, 200, f"{what}: follow-up GET /")


def reject_all(server: Server, path: str, before: list) -> None:
    for raw in REJECTED_BODIES:
        try:
            status, body = http_exchange("POST", path, raw)
        except (OSError, http.client.HTTPException) as exc:
            deadline = time.time() + 2
            while server.alive() and time.time() < deadline:
                time.sleep(0.05)
            raise CaseFailure(
                server.failure_text(f"POST {path} body {raw!r} did not return a response ({exc})")
            ) from exc
        expect_status(status, body, 400, f"POST {path} body {raw!r}")
        require_alive(server, f"POST {path} body {raw!r}")
        after = snapshot_orders()
        if after != before:
            raise CaseFailure(
                f"POST {path} body {raw!r} changed orders from {before!r} to {after!r}"
            )


def exercise_create_order(server: Server) -> None:
    status, body = http_exchange(
        "POST", "/create_order", json.dumps(VALID_ORDER).encode()
    )
    expect_status(status, body, 200, "valid POST /create_order")
    orders = snapshot_orders()
    if not any(row.get("order_id") == VALID_ORDER["order_id"] for row in orders):
        raise CaseFailure(f"valid create did not persist an order: {orders!r}")
    reject_all(server, "/create_order", orders)


def exercise_create_orders(server: Server) -> None:
    status, body = http_exchange(
        "POST", "/create_orders", json.dumps(VALID_ORDERS).encode()
    )
    expect_status(status, body, 200, "valid POST /create_orders")
    orders = snapshot_orders()
    if not any(row.get("order_id") == VALID_ORDERS[0]["order_id"] for row in orders):
        raise CaseFailure(f"valid bulk create did not persist an order: {orders!r}")
    reject_all(server, "/create_orders", orders)


def exercise_update_order(server: Server) -> None:
    status, body = http_exchange(
        "POST", "/create_order", json.dumps(VALID_ORDERS[0]).encode()
    )
    expect_status(status, body, 200, "seed POST /create_order before update")
    status, body = http_exchange(
        "POST", "/update_order", json.dumps(VALID_UPDATE).encode()
    )
    expect_status(status, body, 200, "valid POST /update_order")
    orders = snapshot_orders()
    matched = [row for row in orders if row.get("order_id") == VALID_UPDATE["order_id"]]
    if not matched or matched[0].get("quantity") != VALID_UPDATE["quantity"]:
        raise CaseFailure(f"valid update did not change the order: {orders!r}")
    reject_all(server, "/update_order", orders)


def run_scenario(name: str, wasmedge: str, wasm: Path, exercise) -> str | None:
    print(f"== {name}")
    with tempfile.NamedTemporaryFile(prefix=f"order-{name}-", suffix=".log", delete=False) as handle:
        log_path = Path(handle.name)
    server = None
    try:
        if port_open():
            return f"{name}: port {PORT} is already in use"
        server = Server(wasmedge, wasm, log_path)
        status, body = http_exchange("GET", "/init")
        expect_status(status, body, 200, "GET /init")
        exercise(server)
        if not server.alive():
            raise CaseFailure(server.failure_text(f"{name}: process exited after the scenario"))
        print(f"PASS {name}")
        return None
    except CaseFailure as exc:
        print(f"FAIL {name}: {exc}")
        return str(exc)
    finally:
        if server is not None:
            server.close()
        else:
            log_path.unlink(missing_ok=True)
        # Let the listen socket leave TIME_WAIT before the next process binds.
        for _ in range(50):
            if not port_open():
                break
            time.sleep(0.1)


def main() -> int:
    cargo = cargo_invocation()
    target = wasm_target(cargo)
    ensure_target(cargo, target)
    print(f"building order_demo_service for {target}")
    wasm = build_wasm(cargo, target)
    wasmedge = wasmedge_bin()
    failures = []
    for name, exercise in (
        ("create_order", exercise_create_order),
        ("create_orders", exercise_create_orders),
        ("update_order", exercise_update_order),
    ):
        failed = run_scenario(name, wasmedge, wasm, exercise)
        if failed:
            failures.append(name)
    if failures:
        print("FAILED: " + ", ".join(failures))
        print(
            "Invalid order JSON still aborts the service or is not rejected "
            "with HTTP 400 before any write."
        )
        return 1
    print("PASS: invalid JSON on every order write returns 400 and the process stays up")
    return 0


if __name__ == "__main__":
    sys.exit(main())
