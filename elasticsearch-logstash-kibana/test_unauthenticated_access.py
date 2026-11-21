#!/usr/bin/env python3
"""Security checks for the Elasticsearch, Logstash, and Kibana sample.

The sample must reject unauthenticated cluster operations. These checks fail
while Elasticsearch security is left at the basic-license default and the
compose file publishes the HTTP and transport ports.

Run from the repository root:

    python3 elasticsearch-logstash-kibana/test_unauthenticated_access.py

Requires Docker with the compose plugin. The first run pulls
elasticsearch:7.16.1, logstash:7.16.1, and kibana:7.16.1.
"""

import json
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = SAMPLE_DIR / "compose.yaml"
ES = "http://127.0.0.1:9200"
KIBANA = "http://127.0.0.1:5601"
# Obvious placeholder. The sample ships no password; this only proves a
# credential the caller invented is not accepted either.
PLACEHOLDER_USER = "elastic"
PLACEHOLDER_PASSWORD = "placeholder-not-a-real-secret"
JDK_ROOT = Path(os.environ.get("ELK_TEST_JDK_ROOT", "/tmp/elk-test-jdk"))
TEMURIN_URL = (
    "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
    "?project=jdk"
)

_override_file = None
_docker_prefix = None


def _docker_base():
    global _docker_prefix
    if _docker_prefix is not None:
        return list(_docker_prefix)
    for prefix in (["docker"], ["sudo", "docker"]):
        try:
            probe = subprocess.run(
                prefix + ["info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            continue
        if probe.returncode == 0:
            _docker_prefix = prefix
            return list(prefix)
    raise RuntimeError("docker is not available")


def _run(args, check=True, input_bytes=None):
    completed = subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            "command failed (%s): %s\n%s"
            % (
                completed.returncode,
                " ".join(args),
                (completed.stdout + completed.stderr).decode("utf-8", "replace")[-4000:],
            )
        )
    return completed


def compose(args, override=None, check=True):
    command = _docker_base() + ["compose", "-f", str(COMPOSE_FILE)]
    if override:
        command += ["-f", override]
    command += args
    return _run(command, check=check)


def _http(url, method="GET", body=None, headers=None, timeout=20):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(8192)
            return response.status, dict(response.headers), payload
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers or {}), error.read(8192)
    except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as error:
        return None, {}, str(error).encode("utf-8")


def _es(method, path, body=None, headers=None, content_type="application/json"):
    extra = {"Content-Type": content_type}
    if headers:
        extra.update(headers)
    status, response_headers, payload = _http(ES + path, method, body, extra)
    return status, response_headers, payload


def _placeholder_header():
    token = ("%s:%s" % (PLACEHOLDER_USER, PLACEHOLDER_PASSWORD)).encode("utf-8")
    import base64

    return {"Authorization": "Basic " + base64.b64encode(token).decode("ascii")}


def _assert_denied(status, payload, what):
    snippet = payload[:300] if isinstance(payload, bytes) else str(payload)[:300]
    if status not in (401, 403):
        raise AssertionError(
            "%s was not rejected (status %s): %s" % (what, status, snippet)
        )


def _host_ips():
    completed = _run(["hostname", "-I"], check=False)
    text = completed.stdout.decode("utf-8", "replace")
    addresses = []
    for item in text.split():
        if item.startswith("127.") or item == "::1":
            continue
        addresses.append(item)
    return addresses


def _tcp_open(host, port):
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _es_logs():
    completed = _run(_docker_base() + ["logs", "es"], check=False)
    return (completed.stdout + completed.stderr).decode("utf-8", "replace")


def _wait_for_es(deadline):
    while time.time() < deadline:
        status, _, _ = _es("GET", "/")
        if status in (200, 401, 403):
            return status
        time.sleep(2)
    return None


def _ensure_bridge_forwarding():
    """Container-to-container traffic is how Logstash and Kibana reach Elasticsearch.

    Some hosts keep a legacy iptables FORWARD policy of DROP while Docker
    programs nftables. Published host ports still answer, but the compose
    network does not. Relaxing that policy does not change the sample.
    """
    probe = _run(
        _docker_base()
        + ["exec", "log", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", "http://es:9200/"],
        check=False,
    )
    code = probe.stdout.decode("utf-8", "replace").strip()
    if code in ("200", "401", "403"):
        return
    if shutil.which("sudo"):
        _run(["sudo", "iptables-legacy", "-P", "FORWARD", "ACCEPT"], check=False)


def _download_temurin():
    if any(JDK_ROOT.glob("jdk-*/bin/java")):
        return next(JDK_ROOT.glob("jdk-*"))
    JDK_ROOT.mkdir(parents=True, exist_ok=True)
    archive = JDK_ROOT / "temurin17.tar.gz"
    request = urllib.request.Request(TEMURIN_URL)
    with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
    with tarfile.open(archive) as tar:
        tar.extractall(JDK_ROOT)
    archive.unlink()
    jdk = next(JDK_ROOT.glob("jdk-*"))
    # The Elasticsearch image drops to uid 1000 and must be able to execute this JDK.
    for path in jdk.rglob("*"):
        mode = path.stat().st_mode
        path.chmod(mode | 0o555 if path.is_dir() else mode | 0o444)
    return jdk


def _restart_with_bootable_jdk():
    global _override_file
    jdk = _download_temurin()
    handle = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    handle.write(
        "services:\n  elasticsearch:\n    volumes:\n      - %s:/usr/share/elasticsearch/jdk:ro\n" % jdk
    )
    handle.close()
    _override_file = handle.name
    compose(["up", "-d"], override=_override_file)


def start_stack():
    compose(["down", "-v", "--remove-orphans"], check=False)
    _run(["sudo", "sysctl", "-w", "vm.max_map_count=262144"], check=False)
    compose(["up", "-d"])
    status = _wait_for_es(time.time() + 45)
    if status is None and "CgroupV2Subsystem" in _es_logs():
        # Elasticsearch 7.16.1's bundled Temurin 17.0.1 throws while reading
        # cgroup metadata on kernels whose /proc/cgroups omits the memory
        # controller. A newer Java 17 build runs the same Elasticsearch
        # distribution and does not enable security.
        compose(["down", "-v", "--remove-orphans"], check=False)
        _restart_with_bootable_jdk()
        status = _wait_for_es(time.time() + 90)
    if status is None:
        raise RuntimeError("Elasticsearch did not accept HTTP connections:\n" + _es_logs()[-2000:])
    _ensure_bridge_forwarding()


def stop_stack():
    compose(["down", "-v", "--remove-orphans"], override=_override_file, check=False)
    if _override_file and os.path.exists(_override_file):
        os.unlink(_override_file)


class UnauthenticatedAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        start_stack()

    @classmethod
    def tearDownClass(cls):
        stop_stack()

    def test_cluster_reads_and_writes_require_authentication(self):
        index = "security-probe-index"
        denied = []

        def check(method, path, body=None, headers=None, content_type="application/json", label=None):
            status, _, payload = _es(method, path, body, headers, content_type)
            if status not in (401, 403):
                denied.append("%s %s -> %s %s" % (method, path, status, payload[:180]))

        check("GET", "/")
        check("GET", "/_cluster/health")
        check("GET", "/_cat/indices")
        check("GET", "/", headers=_placeholder_header(), label="placeholder credentials")
        check(
            "PUT",
            "/" + index,
            {"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
        )
        check(
            "POST",
            "/%s/_doc/1?refresh=true" % index,
            {"message": "unauthenticated write"},
        )
        check(
            "POST",
            "/%s/_update/1?refresh=true" % index,
            {"doc": {"message": "unauthenticated update"}},
        )
        check("GET", "/%s/_doc/1" % index)
        check("POST", "/%s/_search" % index, {"query": {"match_all": {}}})
        bulk = (
            '{ "index": { "_index": "%s", "_id": "2" } }\n{"message":"bulk"}\n' % index
        ).encode("utf-8")
        check("POST", "/_bulk", bulk, content_type="application/x-ndjson")
        check("DELETE", "/%s/_doc/1" % index)
        check("DELETE", "/" + index)
        check(
            "PUT",
            "/_cluster/settings",
            {"transient": {"cluster.routing.allocation.enable": "all"}},
        )
        if denied:
            self.fail("unauthenticated Elasticsearch calls were accepted:\n" + "\n".join(denied))

    def test_logstash_nginx_index_requires_authentication(self):
        deadline = time.time() + 180
        last = (None, b"")
        while time.time() < deadline:
            status, _, payload = _es("GET", "/nginx/_search?size=1")
            last = (status, payload)
            if status in (401, 403):
                break
            if status == 200 and b'"value"' in payload and b'"value":0' not in payload[:400]:
                self.fail(
                    "unauthenticated search read the nginx log index: %s" % payload[:400]
                )
            time.sleep(3)
        else:
            self.fail(
                "unauthenticated search of the nginx index was not rejected: %s %s"
                % (last[0], last[1][:300])
            )

        status, _, payload = _es("POST", "/nginx/_update_by_query", {"query": {"match_all": {}}})
        _assert_denied(status, payload, "update of nginx logs")
        status, _, payload = _es("DELETE", "/nginx")
        _assert_denied(status, payload, "delete of nginx index")

    def test_kibana_and_dev_tools_require_authentication(self):
        deadline = time.time() + 180
        status, headers, payload = None, {}, b""
        while time.time() < deadline:
            status, headers, payload = _http(KIBANA + "/app/home")
            if status == 503 and b"not ready" in payload.lower():
                time.sleep(3)
                continue
            if status is not None:
                break
            time.sleep(3)
        location = headers.get("Location") or headers.get("location") or ""
        if status == 200:
            self.fail("Kibana served /app/home without authentication: %s" % payload[:200])
        if status in (401, 403):
            pass
        elif status in (301, 302, 303, 307, 308) and "login" in location:
            pass
        else:
            self.fail("Kibana /app/home was not an authentication challenge: %s %s" % (status, location))

        proxy_status, _, proxy_body = _http(
            KIBANA + "/api/console/proxy?path=/_cat/indices&method=GET",
            method="POST",
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        )
        _assert_denied(proxy_status, proxy_body, "Kibana dev tools proxy")

    def test_transport_port_is_not_published(self):
        targets = [("127.0.0.1", 9300)]
        for address in _host_ips():
            targets.append((address, 9300))
        open_targets = [host for host, port in targets if _tcp_open(host, port)]
        if open_targets:
            self.fail("Elasticsearch transport port 9300 accepted TCP connections on %s" % open_targets)

    def test_non_loopback_http_requires_authentication(self):
        addresses = _host_ips()
        self.assertTrue(addresses, "this host has no non-loopback address to test published port 9200")
        denied = []
        for address in addresses:
            status, _, payload = _http("http://%s:9200/" % address)
            if status not in (401, 403):
                denied.append("%s -> %s %s" % (address, status, payload[:120]))
        if denied:
            self.fail("published Elasticsearch HTTP API answered without authentication: " + "; ".join(denied))


if __name__ == "__main__":
    unittest.main(verbosity=2)
