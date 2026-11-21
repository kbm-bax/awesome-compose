"""A network client must not become Grafana admin with a password committed in this sample.

The checks below fail while prometheus-grafana/compose.yaml publishes Grafana beyond
loopback and commits GF_SECURITY_ADMIN_USER / GF_SECURITY_ADMIN_PASSWORD as literals.
In that state a client that is not the operator can log in with those committed values
(form login and HTTP basic auth) and then write a dashboard or make Grafana request a
URL the client chooses.

They pass once the sample no longer gives a network client that path: the administrator
password is not a committed literal (an uncommitted ${NAME} reference or a Docker secret
is fine; a ${NAME:-default} default is still committed), or Grafana is published only on
a loopback address and a non-loopback client cannot reach it.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import subprocess
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILE = SAMPLE_DIR / "compose.yaml"
PROJECT = "pgadminexposure1408"
MARKER_PATH = "/ssrf-marker"
# ${NAME} only. A default (${NAME:-value} or ${NAME-value}) is still committed.
_EXTERNAL_ONLY = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")
_WITH_DEFAULT = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$")
_ASSIGNMENT = re.compile(
    r"""^\s*(?:-\s*)?['"]?(GF_SECURITY_ADMIN_(?:USER|PASSWORD))['"]?\s*[:=]\s*(.*?)\s*$"""
)
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_WILDCARD = {"", "0.0.0.0", "::"}


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def committed_literal(value: str) -> str | None:
    """Return the committed secret literal, or None when the value is not in the repo."""
    value = _strip_quotes(value)
    if value == "" or _EXTERNAL_ONLY.fullmatch(value):
        return None
    defaulted = _WITH_DEFAULT.fullmatch(value)
    if defaulted:
        default = defaulted.group(1)
        return default if default != "" else None
    return value


def external_only_variable(text: str, key: str) -> str | None:
    """Return NAME when key is exactly ${NAME}, with no committed default."""
    for line in text.splitlines():
        match = _ASSIGNMENT.match(line)
        if not match or match.group(1) != key:
            continue
        value = _strip_quotes(match.group(2))
        if _EXTERNAL_ONLY.fullmatch(value):
            return value[2:-1]
    return None


def committed_admin_credentials(text: str) -> dict[str, str] | None:
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = _ASSIGNMENT.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        literal = committed_literal(raw)
        if literal is not None:
            found[key] = literal
    user = found.get("GF_SECURITY_ADMIN_USER")
    password = found.get("GF_SECURITY_ADMIN_PASSWORD")
    if not user or not password:
        return None
    return {"user": user, "password": password}


def _run(
    cmd: list[str],
    timeout: int = 600,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=SAMPLE_DIR,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
        env=env,
    )


def _compose(
    args: list[str],
    timeout: int = 600,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT, *args],
        timeout=timeout,
        check=check,
        env=env,
    )


class _MarkerHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        hits: list[tuple[str, str]] = getattr(self.server, "hits", [])
        hits.append((self.client_address[0], self.path.split("?", 1)[0]))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        return


class _Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        auth: tuple[str, str] | None = None,
        timeout: int = 20,
    ) -> tuple[int, str, dict]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        if auth is not None:
            user, password = auth
            token = urllib.request.base64.b64encode(f"{user}:{password}".encode()).decode()
            # The header is built here so the password is not placed on a command line.
            request.add_header("Authorization", f"Basic {token}")
        try:
            with self.opener.open(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", "replace")
                return response.status, body, dict(response.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, body, dict(exc.headers)


def _redact(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, "<redacted>")
    return text


def _host_ipv4_addresses() -> list[str]:
    listed = _run(["ip", "-4", "-o", "addr", "show"], timeout=20)
    addresses: list[str] = []
    for line in listed.stdout.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        ip = parts[parts.index("inet") + 1].split("/", 1)[0]
        if ip.startswith("127."):
            continue
        addresses.append(ip)
    return addresses


def _binding_is_loopback_only(bindings: list[dict[str, str]]) -> bool:
    if not bindings:
        return False
    return all(item.get("HostIp") in _LOOPBACK for item in bindings)


def _wait_health(client: _Client, deadline: float) -> None:
    last = "no response"
    while time.time() < deadline:
        try:
            status, body, _headers = client.request("GET", "/api/health", timeout=5)
            if status == 200 and "ok" in body.lower():
                return
            last = f"status {status}"
        except Exception as exc:  # noqa: BLE001 - health probe, keep the last error
            last = str(exc)
        time.sleep(2)
    raise AssertionError(f"Grafana did not become ready: {last}")


def _section_values(text: str, section: str, keys: set[str]) -> dict[str, str]:
    """First assignment of each key inside one ini section."""
    current = ""
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != section or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in keys and key not in found:
            found[key] = value.strip()
    return found


def _container_env(container_id: str, key: str) -> str | None:
    proc = _run(["docker", "exec", container_id, "printenv", key], timeout=30, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.split("\n", 1)[0]


def _image_default_admin(container_id: str) -> dict[str, str] | None:
    proc = _run(
        ["docker", "exec", container_id, "cat", "/usr/share/grafana/conf/defaults.ini"],
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        return None
    values = _section_values(proc.stdout, "security", {"admin_user", "admin_password"})
    user = values.get("admin_user")
    password = values.get("admin_password")
    if not user or not password:
        return None
    return {"user": user, "password": password}


def _reachable_base(host_port: str, addresses: list[str]) -> str | None:
    for ip in addresses:
        base = f"http://{ip}:{host_port}"
        try:
            status, body, _headers = _Client(base).request("GET", "/api/health", timeout=5)
        except Exception:
            continue
        if status == 200 and "ok" in body.lower():
            return base
    return None


class GrafanaAdminExposureTest(unittest.TestCase):
    def test_external_reference_is_not_a_committed_literal(self) -> None:
        self.assertIsNone(committed_literal("${GRAFANA_ADMIN_PASSWORD}"))
        self.assertIsNone(committed_literal(""))

    def test_default_inside_interpolation_is_committed(self) -> None:
        self.assertEqual(committed_literal("${GRAFANA_ADMIN_PASSWORD:-placeholder}"), "placeholder")
        self.assertEqual(committed_literal("placeholder"), "placeholder")

    def test_network_client_cannot_use_committed_grafana_admin_password(self) -> None:
        compose_text = COMPOSE_FILE.read_text()
        creds = committed_admin_credentials(compose_text)
        # An uncommitted ${NAME} reference is the operator's secret. Supply one so an
        # unset variable cannot fall through to the image default during this run.
        run_env = os.environ.copy()
        password_var = external_only_variable(compose_text, "GF_SECURITY_ADMIN_PASSWORD")
        user_var = external_only_variable(compose_text, "GF_SECURITY_ADMIN_USER")
        if password_var:
            run_env[password_var] = "operator-supplied-placeholder"
        if user_var:
            run_env[user_var] = "operator-supplied-user"

        secrets_to_redact = [creds["password"]] if creds else []
        listener = ThreadingHTTPServer(("0.0.0.0", 0), _MarkerHandler)
        listener.hits = []  # type: ignore[attr-defined]
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            up = _compose(
                ["up", "-d", "--force-recreate", "--wait"],
                timeout=900,
                check=False,
                env=run_env,
            )
            if up.returncode != 0:
                rendered = up.stdout + "\n" + up.stderr
                for secret in secrets_to_redact:
                    rendered = _redact(rendered, secret)
                self.fail("docker compose up failed\n" + rendered)
            identity = _compose(["ps", "-q", "grafana"], env=run_env)
            container_id = identity.stdout.strip()
            self.assertTrue(container_id, "grafana service did not start")
            inspected = json.loads(_run(["docker", "inspect", container_id]).stdout)[0]
            bindings = inspected["NetworkSettings"]["Ports"].get("3000/tcp") or []
            self.assertTrue(bindings, "Grafana port 3000 is not published")

            if _binding_is_loopback_only(bindings):
                for ip in _host_ipv4_addresses():
                    with self.subTest(ip=ip):
                        with self.assertRaises(Exception):
                            _Client(f"http://{ip}:{bindings[0]['HostPort']}").request(
                                "GET", "/api/health", timeout=5
                            )
                self.assertIsNone(
                    creds,
                    "compose.yaml still commits GF_SECURITY_ADMIN_USER and GF_SECURITY_ADMIN_PASSWORD",
                )
                return

            host_port = next(
                item["HostPort"]
                for item in bindings
                if item.get("HostIp") in _WILDCARD or item.get("HostIp") not in _LOOPBACK
            )
            # docker-proxy resets connections until the process inside the container is listening.
            _wait_health(_Client(f"http://127.0.0.1:{host_port}"), time.time() + 180)
            base = None
            deadline = time.time() + 30
            while time.time() < deadline and base is None:
                base = _reachable_base(host_port, _host_ipv4_addresses())
                if base is None:
                    time.sleep(1)
            self.assertIsNotNone(
                base,
                f"Grafana is published as {bindings} but no non-loopback address accepted a connection",
            )
            assert base is not None
            _wait_health(_Client(base), time.time() + 180)

            attempts: list[dict[str, str]] = []
            if creds:
                attempts.append(creds)
            image_default = _image_default_admin(container_id)
            effective = _container_env(container_id, "GF_SECURITY_ADMIN_PASSWORD")
            if image_default and effective in (None, "", image_default["password"]):
                if not any(
                    item["user"] == image_default["user"] and item["password"] == image_default["password"]
                    for item in attempts
                ):
                    attempts.append(image_default)

            summary = "no attacker-known administrator password was accepted"
            attack_succeeded = False
            for attempt in attempts:
                secret = attempt["password"]
                secrets_to_redact.append(secret)
                client = _Client(base)
                form_status, form_body, _headers = client.request(
                    "POST",
                    "/login",
                    {"user": attempt["user"], "password": secret},
                )
                user_status, user_body, _headers = client.request("GET", "/api/user")
                form_admin = user_status == 200 and '"isGrafanaAdmin":true' in user_body.replace(" ", "")
                basic_client = _Client(base)
                basic_status, basic_body, _headers = basic_client.request(
                    "GET",
                    "/api/user",
                    auth=(attempt["user"], secret),
                )
                basic_admin = basic_status == 200 and '"isGrafanaAdmin":true' in basic_body.replace(" ", "")
                actor = client if form_admin else basic_client
                dash_status, dash_body, _headers = actor.request(
                    "POST",
                    "/api/dashboards/db",
                    {
                        "overwrite": True,
                        "dashboard": {
                            "uid": "netclientwrite",
                            "title": "network client write",
                            "schemaVersion": 39,
                            "version": 0,
                            "panels": [],
                        },
                    },
                )
                dashboard_written = dash_status == 200
                gateway = next(iter(inspected["NetworkSettings"]["Networks"].values()))["Gateway"]
                listen_port = listener.server_address[1]
                listener.hits.clear()
                ds_status, ds_body, _headers = actor.request(
                    "POST",
                    "/api/datasources",
                    {
                        "name": "attacker-chosen",
                        "type": "prometheus",
                        "access": "proxy",
                        "url": f"http://{gateway}:{listen_port}",
                        "uid": "attackerchosen",
                    },
                )
                proxy_status, proxy_body, _headers = actor.request(
                    "GET",
                    "/api/datasources/proxy/uid/attackerchosen" + MARKER_PATH
                )
                fetched = any(path == MARKER_PATH for _addr, path in listener.hits)
                attack_succeeded = form_admin or basic_admin or dashboard_written or fetched
                summary = (
                    "an attacker-known Grafana administrator password was accepted at "
                    f"{base} (bindings {bindings}). "
                    f"form_login={form_status} user_status={user_status} form_admin={form_admin} "
                    f"basic_status={basic_status} basic_admin={basic_admin} "
                    f"dashboard={dash_status} datasource={ds_status} proxy={proxy_status} "
                    f"server_fetched={fetched} "
                    f"dashboard_body={_redact(dash_body, secret)[:240]} "
                    f"datasource_body={_redact(ds_body, secret)[:240]} "
                    f"proxy_body={_redact(proxy_body, secret)[:240]} "
                    f"form_body={_redact(form_body, secret)[:120]}"
                )
                if attack_succeeded:
                    break

            self.assertFalse(attack_succeeded, summary)
            self.assertIsNone(
                creds,
                "compose.yaml still commits GF_SECURITY_ADMIN_USER and GF_SECURITY_ADMIN_PASSWORD",
            )
        finally:
            listener.shutdown()
            listener.server_close()
            _compose(["down", "-v", "--remove-orphans"], timeout=180, check=False)


if __name__ == "__main__":
    unittest.main()
