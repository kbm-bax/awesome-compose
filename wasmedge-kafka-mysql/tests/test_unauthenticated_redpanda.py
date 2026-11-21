#!/usr/bin/env python3
"""Security regressions for the wasmedge-kafka-mysql Redpanda sample.

The broker is started the way compose starts it: `rpk` plus the redpanda
service command, and the Redpanda v22.2.2 image defaults (admin on 9644,
pandaproxy, and schema registry enabled, SASL off). Telemetry is turned off
in this harness so the process does not phone home.

These tests encode the fixed behavior. They fail while an unauthenticated
client can use a port that compose publishes.
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yml"
MAIN_RS = ROOT / "etl" / "src" / "main.rs"
TRANSFORM_DIR = Path(__file__).resolve().parent / "order_transform"
RPK = os.environ.get("RPK", "/opt/redpanda/bin/rpk")

# Image defaults from redpandadata/redpanda:v22.2.2 /etc/redpanda/redpanda.yaml.
# enable_usage_stats and enable_metrics_reporter are forced off so this
# harness does not post telemetry. Listener and auth defaults match the image.
IMAGE_CONFIG = """
redpanda:
    data_directory: {data}
    node_id: 0
    seed_servers: []
    rpc_server:
        address: 0.0.0.0
        port: 33145
    kafka_api:
        - address: 0.0.0.0
          port: 9092
    admin:
        - address: 0.0.0.0
          port: 9644
    developer_mode: true
    enable_metrics_reporter: false
rpk:
    enable_usage_stats: false
    coredump_dir: {coredump}
    overprovisioned: true
pandaproxy: {{}}
schema_registry: {{}}
"""

FORGED_ORDER = (
    '{"order_id":424242,"product_id":7,"quantity":3,"amount":19.5,'
    '"shipping":2.0,"tax":1.25,"shipping_address":"forged-row"}'
)


def _run(args, timeout=20):
    proc = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout


def _published_container_ports(service):
    ports = set()
    for entry in service.get("ports") or []:
        text = str(entry)
        parts = text.split(":")
        ports.add(int(parts[-1]))
    return ports


def _flag_values(command, flag):
    values = []
    for i, item in enumerate(command):
        if item == flag and i + 1 < len(command):
            values.append(command[i + 1])
        elif item.startswith(flag + "="):
            values.append(item.split("=", 1)[1])
    return values


def _listen_ports(spec):
    """Ports from a redpanda addr list such as NAME://0.0.0.0:9092,other://host:29092."""
    ports = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        hostport = item.split("://", 1)[-1]
        ports.append(int(hostport.rsplit(":", 1)[-1]))
    return ports


def _wait_for_port(port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket()
        sock.settimeout(0.2)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.2)
        finally:
            sock.close()
    return False


def _http(method, url, body=None, headers=None, timeout=15):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


class UnauthenticatedRedpandaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(RPK).exists():
            raise unittest.SkipTest(f"rpk is not at {RPK}")
        with COMPOSE.open() as handle:
            doc = yaml.safe_load(handle)
        service = doc["services"]["redpanda"]
        # entrypoint.sh runs `exec /usr/bin/rpk $@` with $@ unquoted, so each
        # compose command item is split on whitespace before rpk sees it.
        command = []
        for item in service["command"]:
            command.extend(str(item).split())
        if command[:2] != ["redpanda", "start"]:
            raise AssertionError(f"unexpected redpanda command: {command}")
        cls.published = _published_container_ports(service)
        kafka_specs = _flag_values(command, "--kafka-addr")
        cls.kafka_ports = []
        for spec in kafka_specs:
            cls.kafka_ports.extend(_listen_ports(spec))
        proxy_specs = _flag_values(command, "--pandaproxy-addr")
        cls.proxy_ports = []
        for spec in proxy_specs:
            cls.proxy_ports.extend(_listen_ports(spec))
        # Image defaults used when the command does not override them.
        cls.admin_port = 9644
        cls.schema_port = 8081

        cls.tmp = tempfile.TemporaryDirectory(prefix="redpanda-sec-")
        data = Path(cls.tmp.name) / "data"
        coredump = Path(cls.tmp.name) / "coredump"
        data.mkdir()
        coredump.mkdir()
        cfg = Path(cls.tmp.name) / "redpanda.yaml"
        cfg.write_text(IMAGE_CONFIG.format(data=data, coredump=coredump))
        log_path = Path(cls.tmp.name) / "redpanda.log"
        cls.log = log_path.open("w")
        # --memory bounds the process for the harness. It is not an auth setting.
        argv = [RPK, *command, "--config", str(cfg), "--memory", "512M"]
        cls.proc = subprocess.Popen(
            argv,
            stdout=cls.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if not _wait_for_port(cls.kafka_ports[0] if cls.kafka_ports else 9092):
            cls.log.flush()
            raise RuntimeError(f"broker did not listen; log:\n{log_path.read_text()[-4000:]}")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if getattr(cls, "log", None):
            cls.log.close()
        if getattr(cls, "tmp", None):
            cls.tmp.cleanup()

    def _kafka_published(self):
        return [port for port in self.kafka_ports if port in self.published]

    def test_unauthenticated_topic_create_is_rejected(self):
        ports = self._kafka_published()
        if not ports:
            return
        for port in ports:
            with self.subTest(port=port):
                code, out = _run(
                    [RPK, "topic", "create", f"create-probe-{port}", "--brokers", f"127.0.0.1:{port}"]
                )
                self.assertNotEqual(
                    code,
                    0,
                    f"unauthenticated topic create was accepted on published port {port}:\n{out}",
                )

    def test_unauthenticated_produce_is_rejected(self):
        for port in self._kafka_published():
            with self.subTest(port=port):
                self._assert_produce_rejected(port)

    def _assert_produce_rejected(self, port):
        brokers = f"127.0.0.1:{port}"
        created, create_out = _run(
            [RPK, "topic", "create", f"produce-{port}", "--brokers", brokers]
        )
        proc = subprocess.run(
            [RPK, "topic", "produce", f"produce-{port}", "--brokers", brokers],
            input=FORGED_ORDER + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        accepted = proc.returncode == 0 or "Produced to partition" in proc.stdout
        self.assertFalse(
            accepted,
            "unauthenticated produce was accepted on published port "
            f"{port} after create exit {created}:\n{create_out}\n{proc.stdout}",
        )

    def test_unauthenticated_consume_is_rejected(self):
        for port in self._kafka_published():
            with self.subTest(port=port):
                self._assert_consume_rejected(port)

    def _assert_consume_rejected(self, port):
        brokers = f"127.0.0.1:{port}"
        _run([RPK, "topic", "create", f"order-{port}", "--brokers", brokers])
        subprocess.run(
            [RPK, "topic", "produce", f"order-{port}", "--brokers", brokers],
            input=FORGED_ORDER + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        try:
            _code, out = _run(
                [
                    RPK,
                    "topic",
                    "consume",
                    f"order-{port}",
                    "--brokers",
                    brokers,
                    "-o",
                    "start",
                    "-n",
                    "1",
                    "--pretty-print=false",
                ],
                timeout=8,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
        self.assertNotIn(
            "forged-row",
            out,
            f"unauthenticated consume returned a record on published port {port}:\n{out}",
        )
        self.assertNotIn('"order_id"', out)

    def test_unauthenticated_topic_delete_is_rejected(self):
        ports = self._kafka_published()
        if not ports:
            return
        brokers = f"127.0.0.1:{ports[0]}"
        _run([RPK, "topic", "create", "delete-probe", "--brokers", brokers])
        code, out = _run([RPK, "topic", "delete", "delete-probe", "--brokers", brokers])
        deleted = code == 0 and "OK" in out
        self.assertFalse(
            deleted,
            f"unauthenticated topic delete was accepted on published port {ports[0]}:\n{out}",
        )

    def test_unauthenticated_http_proxy_produce_is_rejected(self):
        ports = [port for port in self.proxy_ports if port in self.published]
        if not ports:
            return
        body = json.dumps(
            {
                "records": [
                    {
                        "value": json.loads(FORGED_ORDER),
                        "partition": 0,
                    }
                ]
            }
        )
        status, payload = _http(
            "POST",
            f"http://127.0.0.1:{ports[0]}/topics/order",
            body,
            {
                "Content-Type": "application/vnd.kafka.json.v2+json",
                "Accept": "application/vnd.kafka.v2+json",
            },
        )
        stored = status == 200 and '"offset":-' not in payload and "error_code" not in payload and '"offset":' in payload
        self.assertFalse(
            stored,
            f"unauthenticated HTTP proxy produce stored a record on published port {ports[0]}: {status} {payload}",
        )

    def test_unauthenticated_admin_reconfigure_is_rejected(self):
        if self.admin_port not in self.published:
            return
        status, payload = _http(
            "PUT",
            f"http://127.0.0.1:{self.admin_port}/v1/cluster_config",
            json.dumps(
                {
                    "upsert": {"log_message_timestamp_type": "LogAppendTime"},
                    "remove": [],
                }
            ),
            {"Content-Type": "application/json"},
        )
        self.assertNotIn(
            "config_version",
            payload,
            f"unauthenticated admin config change was accepted on published port {self.admin_port}: {status} {payload}",
        )
        self.assertNotEqual(status, 200)

    def test_unauthenticated_schema_registry_write_is_rejected(self):
        if self.schema_port not in self.published:
            return
        status, payload = _http(
            "POST",
            f"http://127.0.0.1:{self.schema_port}/subjects/order-value/versions",
            json.dumps({"schema": '{"type":"string"}'}),
            {"Content-Type": "application/vnd.schemaregistry.v1+json"},
        )
        self.assertNotEqual(
            status,
            200,
            f"unauthenticated schema registry write was accepted on published port {self.schema_port}: {payload}",
        )
        self.assertNotIn('"id"', payload)

    def test_pipeline_does_not_store_forged_order(self):
        ports = self._kafka_published()
        if not ports:
            return
        source = MAIN_RS.read_text()
        helper = (TRANSFORM_DIR / "src" / "main.rs").read_text()
        marker = 'r"INSERT INTO orders VALUES ({:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, CURRENT_TIMESTAMP);"'
        self.assertIn(marker, source)
        self.assertIn(marker, helper)
        # KAFKA_URL in compose.yml reads topic "order" on port 9092.
        port = 9092 if 9092 in ports else ports[0]
        brokers = f"127.0.0.1:{port}"
        _run([RPK, "topic", "create", "order", "--brokers", brokers])
        proc = subprocess.run(
            [RPK, "topic", "produce", "order", "--brokers", brokers],
            input=FORGED_ORDER + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0 and "Produced to partition" not in proc.stdout:
            return
        sql = _order_insert_sql(FORGED_ORDER)
        stored = _store_order(sql, 424242)
        self.fail(
            "unauthenticated produce was accepted and the order pipeline stored it: "
            f"broker={proc.stdout.strip()} sql={sql} stored={stored}"
        )


def _order_insert_sql(payload):
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = "/tmp/order-transform-target"
    proc = subprocess.run(
        ["cargo", "run", "--quiet", "--manifest-path", str(TRANSFORM_DIR / "Cargo.toml"), "--", payload],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout)
    return proc.stdout.strip()


def _store_order(sql, order_id):
    init = (
        "CREATE TABLE IF NOT EXISTS orders ("
        "order_id INT, product_id INT, quantity INT, amount FLOAT, "
        "shipping FLOAT, tax FLOAT, shipping_address VARCHAR(50), "
        "date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
    )
    socket_path = os.environ.get("MYSQL_SOCKET", "/run/mysqld/mysqld.sock")
    mysql = shutil.which("mysql") or "mysql"
    script = f"USE mysql;\n{init}\n{sql}\nSELECT order_id, shipping_address FROM orders WHERE order_id = {int(order_id)};\n"
    code, out = _run(["sudo", mysql, f"--socket={socket_path}", "-u", "root", "-N", "-e", script], timeout=20)
    if code != 0:
        raise RuntimeError(out)
    return out.strip()


if __name__ == "__main__":
    unittest.main(verbosity=2)
