"""The cloudflared DoH sample must not be an open resolver on the host.

These tests fail while pihole-cloudflared-DoH/compose.yaml publishes port 5054
and sets ADDRESS to a wildcard. They pass once that host mapping is gone and
the proxy is bound to the compose-network address Pi-hole already uses.

Pi-hole's own published DNS port (53/tcp and 53/udp) is a different service
and is not covered here.

Run from the repository root:

    python3 -m unittest pihole-cloudflared-DoH.test_open_resolver
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).resolve().parent / "compose.yaml"
# visibilityspots/cloudflared:latest is the v2026.1.2 image. Its Dockerfile
# runs this command, with ADDRESS and PORT supplied by the compose service.
CLOUDFLARED_VERSION = "2026.1.2"
CLOUDFLARED_URL = (
    "https://github.com/cloudflare/cloudflared/releases/download/"
    f"{CLOUDFLARED_VERSION}/cloudflared-linux-amd64"
)
IMAGE_DEFAULTS = {
    "ADDRESS": "0.0.0.0",
    "PORT": "5054",
    "UPSTREAM1": "https://1.1.1.1/dns-query",
    "UPSTREAM2": "https://1.0.0.1/dns-query",
    "METRICS": "127.0.0.1:8080",
    "MAX_UPSTREAM_CONNS": "0",
}
PROXY_PORT = 5054
NETWORK_ADDRESS = "172.20.0.2"
QTYPE_A = 1
QTYPE_TXT = 16
WILDCARD_HOSTS = {"", "0.0.0.0", "::"}

_PROXY = None


def _split_proto_port(raw_port: str) -> tuple[str, str]:
    """docker/go-connections v0.4.0 nat.SplitProtoPort."""
    parts = raw_port.split("/")
    if len(raw_port) == 0 or len(parts) == 0 or len(parts[0]) == 0:
        return "", ""
    if len(parts) == 1:
        return "tcp", raw_port
    if len(parts[1]) == 0:
        return "tcp", parts[0]
    return parts[1], parts[0]


def _split_parts(raw_port: str) -> tuple[str, str, str]:
    """docker/go-connections v0.4.0 nat.splitParts."""
    parts = raw_port.split(":")
    container_port = parts[-1]
    count = len(parts)
    if count == 1:
        return "", "", container_port
    if count == 2:
        return "", parts[0], container_port
    if count == 3:
        return parts[0], parts[1], container_port
    return ":".join(parts[:-2]), parts[-2], container_port


def parse_port_spec(raw_port: str) -> dict[str, str]:
    """Parse one compose short port string the way nat.ParsePortSpec does.

    An empty host IP is left empty. Callers apply the engine default, which
    publishes that binding on every host interface.
    """
    host_ip, host_port, container_port = _split_parts(raw_port)
    protocol, container_port = _split_proto_port(container_port)
    if host_ip.startswith("[") and host_ip.endswith("]"):
        host_ip = host_ip[1:-1]
    return {
        "host_ip": host_ip,
        "host_port": host_port,
        "container_port": container_port,
        "protocol": protocol.lower(),
    }


def _env_map(service: dict) -> dict[str, str]:
    values = dict(IMAGE_DEFAULTS)
    for item in service.get("environment") or []:
        if isinstance(item, str) and "=" in item:
            key, value = item.split("=", 1)
            values[key] = value
    return values


def _service_ipv4(service: dict) -> str:
    networks = service.get("networks") or {}
    if isinstance(networks, dict):
        for config in networks.values():
            if isinstance(config, dict) and config.get("ipv4_address"):
                return str(config["ipv4_address"])
    return ""


def load_proxy_config() -> dict:
    document = yaml.safe_load(COMPOSE_PATH.read_text())
    service = document["services"]["cloudflared"]
    pihole = document["services"]["pihole"]
    environment = _env_map(service)
    publications = []
    for entry in service.get("ports") or []:
        if not isinstance(entry, str):
            raise AssertionError(f"unexpected port entry {entry!r}")
        parsed = parse_port_spec(entry)
        if parsed["container_port"] != str(PROXY_PORT):
            continue
        host_ip = parsed["host_ip"]
        if host_ip in WILDCARD_HOSTS:
            # moby v27.5.1 configurePortBindingIPv4 fills an empty host IP
            # from the daemon default, which is 0.0.0.0.
            host_ip = "0.0.0.0"
        publications.append({**parsed, "host_ip": host_ip})
    pihole_env = _env_map(pihole)
    return {
        "address": environment.get("ADDRESS", IMAGE_DEFAULTS["ADDRESS"]),
        "port": int(environment.get("PORT", str(PROXY_PORT))),
        "upstreams": [
            environment["UPSTREAM1"],
            environment["UPSTREAM2"],
        ],
        "max_upstream_conns": environment["MAX_UPSTREAM_CONNS"],
        "publications": publications,
        "ipv4_address": _service_ipv4(service),
        "pihole_dns": pihole_env.get("PIHOLE_DNS_", ""),
    }


def _local_host_addresses() -> list[str]:
    """IPv4 addresses this host owns, from the kernel local routing table."""
    addresses = []
    lines = Path("/proc/net/fib_trie").read_text().splitlines()
    pending = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|-- "):
            pending = stripped.split()[1]
            continue
        if pending and "/32 host LOCAL" in stripped:
            if pending not in addresses:
                addresses.append(pending)
            pending = None
        elif stripped.startswith("|-- ") or stripped.startswith("+-- "):
            pending = None
    if "127.0.0.1" not in addresses:
        addresses.insert(0, "127.0.0.1")
    return addresses


def _client_destinations(host_ip: str) -> list[str]:
    if host_ip == "0.0.0.0":
        destinations = [
            address
            for address in _local_host_addresses()
            if ":" not in address and not address.endswith(".255") and address != "0.0.0.0"
        ]
        if "::1" not in destinations:
            destinations.append("::1")
        # Prefer a non-loopback address so a hit is not only localhost.
        destinations.sort(key=lambda address: address.startswith("127.") or address == "::1")
        return destinations
    if host_ip == "::":
        return ["::1"]
    return [host_ip]


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(label)
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def build_query(name: str, qtype: int, query_id: int = 0x4D21) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def parse_response(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    query_id, flags, _qd, answers, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    return {
        "id": query_id,
        "qr": (flags >> 15) & 1,
        "rcode": flags & 0xF,
        "answers": answers,
        "size": len(payload),
    }


def exchange(host: str, port: int, protocol: str, query: bytes, timeout: float = 5) -> dict | None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    if protocol == "udp":
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(query, (host, port))
            payload, _source = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()
    elif protocol == "tcp":
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(struct.pack("!H", len(query)) + query)
            header = _read_exact(sock, 2)
            if header is None:
                return None
            length = struct.unpack("!H", header)[0]
            payload = _read_exact(sock, length)
            if payload is None:
                return None
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()
    else:
        raise AssertionError(protocol)
    parsed = parse_response(payload)
    if parsed is None or parsed["qr"] != 1 or parsed["id"] != struct.unpack("!H", query[:2])[0]:
        return None
    return parsed


def _read_exact(sock: socket.socket, size: int) -> bytes | None:
    chunks = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout:
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _cloudflared_binary() -> Path:
    override = os.environ.get("CLOUDFLARED_BIN")
    if override:
        return Path(override)
    cached = Path(tempfile.gettempdir()) / f"cloudflared-{CLOUDFLARED_VERSION}-linux-amd64"
    if cached.exists() and os.access(cached, os.X_OK):
        return cached
    staged = Path("/tmp/cloudflared-bin/cloudflared")
    if staged.exists() and os.access(staged, os.X_OK):
        return staged
    urllib.request.urlretrieve(CLOUDFLARED_URL, cached)
    cached.chmod(cached.stat().st_mode | stat.S_IXUSR)
    return cached


def _address_is_bindable_here(address: str) -> bool:
    if address in WILDCARD_HOSTS:
        return True
    try:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        probe = socket.socket(family, socket.SOCK_DGRAM)
        try:
            probe.bind((address, 0))
        finally:
            probe.close()
        return True
    except OSError:
        return False


def _start_proxy(config: dict) -> subprocess.Popen:
    binary = _cloudflared_binary()
    metrics_port = 18080
    command = [
        str(binary),
        "proxy-dns",
        "--address",
        config["address"],
        "--port",
        str(config["port"]),
        "--metrics",
        f"127.0.0.1:{metrics_port}",
        "--max-upstream-conns",
        str(config["max_upstream_conns"]),
    ]
    for upstream in config["upstreams"]:
        command.extend(["--upstream", upstream])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.time() + 20
    query = build_query("example.com", QTYPE_A)
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise AssertionError(f"cloudflared exited early:\n{output}")
        if exchange("127.0.0.1", config["port"], "udp", query, timeout=1):
            return process
        time.sleep(0.2)
    process.terminate()
    output = ""
    if process.stdout:
        try:
            output = process.stdout.read()
        except Exception:
            output = ""
    raise AssertionError(f"cloudflared did not answer on UDP within 20s:\n{output}")


def _stop_proxy(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stdout:
        process.stdout.close()


def setUpModule() -> None:
    global _PROXY
    config = load_proxy_config()
    exposed = bool(config["publications"]) and _address_is_bindable_here(config["address"])
    if exposed:
        _PROXY = _start_proxy(config)


def tearDownModule() -> None:
    global _PROXY
    _stop_proxy(_PROXY)
    _PROXY = None


class OpenResolverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_proxy_config()

    def _assert_no_answer(self, protocol: str, qtype: int, name: str) -> None:
        publications = [
            item for item in self.config["publications"] if item["protocol"] == protocol
        ]
        if not publications:
            return
        self.assertIsNotNone(
            _PROXY,
            f"{protocol} port {PROXY_PORT} is published, but the proxy was not started",
        )
        query = build_query(name, qtype)
        hits = []
        for publication in publications:
            port = int(publication["host_port"])
            for destination in _client_destinations(publication["host_ip"]):
                response = None
                for _attempt in range(3):
                    response = exchange(destination, port, protocol, query)
                    if response is not None:
                        break
                if response is not None:
                    hits.append(
                        f"{protocol} {destination}:{port} answered {name} "
                        f"type {qtype} with {response} (query {len(query)} bytes)"
                    )
        self.assertEqual(hits, [], "published proxy answered remote DNS clients:\n" + "\n".join(hits))

    def test_udp_client_receives_no_dns_answer(self) -> None:
        self._assert_no_answer("udp", QTYPE_A, "example.com")

    def test_tcp_client_receives_no_dns_answer(self) -> None:
        self._assert_no_answer("tcp", QTYPE_A, "example.com")

    def test_udp_client_receives_no_amplified_answer(self) -> None:
        """A TXT query whose answer is larger than the query is a reflector."""
        publications = [
            item for item in self.config["publications"] if item["protocol"] == "udp"
        ]
        if not publications:
            return
        self.assertIsNotNone(_PROXY, "UDP port 5054 is published, but the proxy was not started")
        query = build_query("google.com", QTYPE_TXT)
        reflections = []
        answered = False
        for publication in publications:
            port = int(publication["host_port"])
            for destination in _client_destinations(publication["host_ip"]):
                response = None
                for _attempt in range(3):
                    response = exchange(destination, port, "udp", query, timeout=8)
                    if response is not None:
                        break
                if response is None:
                    continue
                answered = True
                if response["size"] > len(query):
                    reflections.append(
                        f"udp {destination}:{port} reflected {len(query)} bytes "
                        f"as {response['size']} bytes (rcode {response['rcode']}, "
                        f"answers {response['answers']})"
                    )
        self.assertTrue(answered, "published UDP proxy did not answer a TXT query")
        self.assertEqual(
            reflections,
            [],
            "published proxy amplified a DNS query:\n" + "\n".join(reflections),
        )

    def test_proxy_is_not_published_on_the_host(self) -> None:
        self.assertEqual(
            self.config["publications"],
            [],
            "cloudflared container port 5054 is published on the host",
        )

    def test_proxy_address_is_the_compose_network_address(self) -> None:
        self.assertEqual(self.config["ipv4_address"], NETWORK_ADDRESS)
        self.assertEqual(
            self.config["address"],
            self.config["ipv4_address"],
            "cloudflared ADDRESS must be the compose-network address Pi-hole uses",
        )
        self.assertNotIn(self.config["address"], WILDCARD_HOSTS)

    def test_pihole_reaches_the_proxy_on_the_compose_network(self) -> None:
        self.assertIn(
            f"{NETWORK_ADDRESS}#{PROXY_PORT}",
            self.config["pihole_dns"],
        )


if __name__ == "__main__":
    unittest.main()
