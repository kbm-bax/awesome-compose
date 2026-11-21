#!/usr/bin/env python3
"""Security spec for the React/Rust/Postgres sample.

These tests fail while the sample publishes the database and the application
pool connects without TLS. They pass once a network client cannot log in with
credentials committed in the compose file, and once `create_pool` reports TLS.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time
import unittest
from pathlib import Path

SAMPLE = Path(__file__).resolve().parents[1]
COMPOSE = SAMPLE / "compose.yaml"
MIGRATION = SAMPLE / "backend" / "migrations" / "0001_create-users_up.sql"
POOL_TLS = Path(__file__).resolve().parent / "pool_tls"
PROJECT = "rrpg-exposure"
PROBE_LOGIN = "exposure-probe-login"
PROGRAM_MARKER = "exposure-program-ok"


def docker_cmd():
    if shutil.which("docker") and subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0:
        return ["docker"]
    return ["sudo", "docker"]


def run(cmd, *, env=None, input_text=None, check=False, timeout=120):
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        env=env,
        check=check,
        timeout=timeout,
    )


def redact(text, secrets):
    redacted = text or ""
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def compose_literals(text):
    """Return committed user and password literals, never interpolated values."""
    users = []
    passwords = []
    pattern = re.compile(
        r"^\s*-\s*(PG_USER|POSTGRES_USER|PG_PASSWORD|POSTGRES_PASSWORD)=(.*)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip().strip("'\"")
        if not value or "$" in value:
            continue
        if key.endswith("USER"):
            users.append(value)
        else:
            passwords.append(value)
    return users, passwords


def published_tcp_ports(service):
    ports = []
    for entry in service.get("ports") or []:
        if entry.get("protocol", "tcp") != "tcp":
            continue
        published = entry.get("published")
        target = entry.get("target")
        if published is None or target is None:
            continue
        host_ip = entry.get("host_ip") or ""
        ports.append((str(host_ip), int(published), int(target)))
    return ports


def wait_for_internal_ready(docker, container, timeout_s=90):
    deadline = time.time() + timeout_s
    last = ""
    while time.time() < deadline:
        result = run(docker + ["exec", container, "pg_isready", "-U", "postgres", "-d", "postgres"])
        last = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("database container did not become ready: " + last[-500:])


def container_ipv4(docker, container):
    result = run(docker + ["inspect", container], check=True)
    info = json.loads(result.stdout)[0]
    addresses = []
    for network in info["NetworkSettings"]["Networks"].values():
        ip = network.get("IPAddress")
        if ip:
            addresses.append(ip)
    if not addresses:
        raise RuntimeError("database container has no IPv4 address")
    return addresses[0]


def psql(user, password, host, port, sql, secrets, database="postgres"):
    env = os.environ.copy()
    env["PGPASSWORD"] = password
    env["PGCONNECT_TIMEOUT"] = "5"
    result = run(
        [
            "psql",
            "-h",
            host,
            "-p",
            str(port),
            "-U",
            user,
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
            "-f",
            "-",
        ],
        env=env,
        input_text=sql,
        timeout=30,
    )
    stdout = redact(result.stdout, secrets)
    stderr = redact(result.stderr, secrets)
    return result.returncode, stdout, stderr


def listen_lines(port):
    result = run(["ss", "-ltn"], timeout=15)
    if result.returncode != 0:
        result = run(["sudo", "ss", "-ltn"], timeout=15)
    lines = []
    for line in (result.stdout or "").splitlines():
        if f":{port}" in line:
            lines.append(line.strip())
    return lines


class DatabaseExposureTests(unittest.TestCase):
    docker = None
    secrets = []
    users = []
    passwords = []
    container = ""
    container_ip = ""
    published = []

    @classmethod
    def setUpClass(cls):
        cls.docker = docker_cmd()
        info = run(cls.docker + ["info"])
        if info.returncode != 0:
            raise RuntimeError("docker is not available")
        raw = COMPOSE.read_text()
        cls.users, cls.passwords = compose_literals(raw)
        cls.secrets = list(cls.passwords)
        config = run(
            cls.docker
            + [
                "compose",
                "-f",
                str(COMPOSE),
                "--project-directory",
                str(SAMPLE),
                "config",
                "--format",
                "json",
            ],
            check=True,
        )
        spec = json.loads(config.stdout)
        cls.published = published_tcp_ports(spec["services"]["db"])
        up = run(
            cls.docker
            + [
                "compose",
                "-f",
                str(COMPOSE),
                "--project-directory",
                str(SAMPLE),
                "-p",
                PROJECT,
                "up",
                "-d",
                "db",
            ],
            timeout=180,
        )
        if up.returncode != 0:
            raise RuntimeError(redact(up.stderr or up.stdout, cls.secrets))
        cls.container = f"{PROJECT}-db-1"
        wait_for_internal_ready(cls.docker, cls.container)
        cls.container_ip = container_ipv4(cls.docker, cls.container)

    @classmethod
    def tearDownClass(cls):
        if not cls.docker:
            return
        run(
            cls.docker
            + [
                "compose",
                "-f",
                str(COMPOSE),
                "--project-directory",
                str(SAMPLE),
                "-p",
                PROJECT,
                "down",
                "-v",
                "--remove-orphans",
            ],
            timeout=180,
        )

    def test_published_port_rejects_repository_credentials(self):
        if not self.published or not self.users or not self.passwords:
            return
        published_port = self.published[0][1]
        host_targets = ["127.0.0.1"]
        for address in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = address[4][0]
            if not ip.startswith("127."):
                host_targets.append(ip)
        violations = []
        for host in host_targets:
            for user in self.users:
                for password in self.passwords:
                    code, stdout, stderr = psql(
                        user,
                        password,
                        host,
                        published_port,
                        "SELECT current_user;",
                        self.secrets,
                    )
                    if code != 0:
                        continue
                    violations.append(
                        f"{host}:{published_port} accepted a user named in the compose file"
                    )
                    impact_sql = "\n".join(
                        [
                            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user;",
                            "SHOW ssl;",
                            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();",
                            f"\\i {MIGRATION}",
                            "INSERT INTO users(login) VALUES ('" + PROBE_LOGIN + "') ON CONFLICT DO NOTHING;",
                            "SELECT login FROM users WHERE login = '" + PROBE_LOGIN + "';",
                            "CREATE TEMP TABLE program_out(line text);",
                            "COPY program_out FROM PROGRAM 'printf " + PROGRAM_MARKER + "';",
                            "SELECT line FROM program_out;",
                        ]
                    )
                    impact_code, impact_out, impact_err = psql(
                        user, password, host, published_port, impact_sql, self.secrets
                    )
                    combined = impact_out + "\n" + impact_err
                    lines = [line.strip() for line in impact_out.splitlines() if line.strip()]
                    if lines and lines[0] == "t":
                        violations.append("authenticated role is a superuser")
                    if PROBE_LOGIN in combined:
                        violations.append("users rows created by the sample migration are readable and writable")
                    if PROGRAM_MARKER in combined:
                        violations.append("server executed a program for the network session")
                    if "off" in lines or (len(lines) > 2 and lines[2] == "f"):
                        violations.append("network session was not using TLS")
                    if impact_code != 0:
                        violations.append("impact query failed: " + combined[-400:])
                    listeners = listen_lines(published_port)
                    wide = []
                    for line in listeners:
                        parts = line.split()
                        local = parts[3] if len(parts) >= 4 else ""
                        if local.startswith("0.0.0.0:") or local.startswith("[::]:") or local.startswith("*:"):
                            wide.append(line)
                    if wide:
                        violations.append("database port is published on all host interfaces: " + " | ".join(wide))
                    elif listeners:
                        violations.append("database port is listening: " + " | ".join(listeners))
                    visible = self._query_visible_on_wire(user, password, host, published_port)
                    if PROBE_LOGIN in visible or "SELECT login FROM users" in visible:
                        violations.append("query text was visible on the published port")
                    break
                if violations:
                    break
            if violations:
                break
        self.assertFalse(
            violations,
            "repository database credentials can use the published port:\n- " + "\n- ".join(violations),
        )

    def _query_visible_on_wire(self, user, password, host, port):
        if not shutil.which("tcpdump"):
            return ""
        pcap = Path("/tmp") / f"rrpg-exposure-{os.getpid()}.pcap"
        proc = subprocess.Popen(
            [
                "sudo",
                "tcpdump",
                "-ni",
                "any",
                "-s0",
                "-U",
                "-c",
                "80",
                "-w",
                str(pcap),
                "tcp",
                "port",
                str(port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)
        psql(
            user,
            password,
            host,
            port,
            "SELECT login FROM users WHERE login = '" + PROBE_LOGIN + "';",
            self.secrets,
        )
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.send_signal(2)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        visible = ""
        if pcap.exists():
            data = pcap.read_bytes()
            if PROBE_LOGIN.encode() in data or b"SELECT login FROM users" in data:
                visible = PROBE_LOGIN
            run(["sudo", "rm", "-f", str(pcap)])
        return visible

    def test_application_pool_uses_tls(self):
        binary = POOL_TLS / "target" / "debug" / "pool_tls_check"
        if not binary.exists():
            build = run(
                ["cargo", "build", "--manifest-path", str(POOL_TLS / "Cargo.toml")],
                timeout=600,
            )
            if build.returncode != 0:
                self.fail(redact((build.stderr or "")[-2000:], self.secrets))
        env = os.environ.copy()
        env["PG_HOST"] = self.container_ip
        env["PG_DBNAME"] = "postgres"
        env["PG_USER"] = self.users[0]
        env["PG_PASSWORD"] = self.passwords[0]
        result = run([str(binary)], env=env, timeout=30)
        output = redact((result.stdout or "") + (result.stderr or ""), self.secrets)
        self.assertEqual(
            result.returncode,
            0,
            "create_pool did not open a TLS session (exit "
            + str(result.returncode)
            + "): "
            + output[-1000:],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
