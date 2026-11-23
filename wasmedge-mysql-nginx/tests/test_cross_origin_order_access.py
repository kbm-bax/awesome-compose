#!/usr/bin/env python3
"""Security tests for the Wasm order API.

These assertions describe the fixed behavior. They fail while every
response_build route sends Access-Control-Allow-Origin: * and while
GET /init and GET /delete_order change stored orders.

Run against a server already listening on ORDER_API_URL (default
http://127.0.0.1:8080), with the orders table in the MariaDB database
named by ORDER_DB (default mysql) reachable through the local socket:

    sudo mysql --socket=/run/mysqld/mysqld.sock < /dev/null
    python3 wasmedge-mysql-nginx/tests/test_cross_origin_order_access.py

The database password is not stored in this file. Schema setup uses the
local MariaDB socket.

Not covered: POST /echo, GET /, and unmatched paths do not call
response_build. A simple text/plain POST that happens to be valid JSON
is a separate unauthenticated write and is not asserted here.
"""

import json
import os
import subprocess
import unittest
import urllib.error
import urllib.request

API = os.environ.get("ORDER_API_URL", "http://127.0.0.1:8080").rstrip("/")
DB = os.environ.get("ORDER_DB", "mysql")
SOCKET = os.environ.get("ORDER_DB_SOCKET", "/run/mysqld/mysqld.sock")
EVIL = "https://evil.example"
ADDRESS = "9 Elm Lane"
ORDER_ID = 42

ROUTES_WITH_WILDCARD = (
    ("OPTIONS", "/init", None),
    ("OPTIONS", "/create_order", None),
    ("OPTIONS", "/create_orders", None),
    ("OPTIONS", "/update_order", None),
    ("OPTIONS", "/delete_order", None),
    ("OPTIONS", "/orders", None),
    ("GET", "/init", None),
    ("GET", "/orders", None),
    ("GET", "/delete_order?id=%d" % ORDER_ID, None),
    ("POST", "/create_order", "order"),
    ("POST", "/create_orders", "orders"),
    ("POST", "/update_order", "order"),
)


def mysql(sql):
    subprocess.run(
        ["sudo", "mysql", "--socket=" + SOCKET, DB, "-e", sql],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def order_count():
    out = subprocess.run(
        [
            "sudo",
            "mysql",
            "--socket=" + SOCKET,
            "--batch",
            "--skip-column-names",
            DB,
            "-e",
            "SELECT COUNT(*) FROM orders WHERE order_id=%d AND shipping_address='%s'"
            % (ORDER_ID, ADDRESS),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return int(out.stdout.strip())


def seed():
    mysql(
        "DROP TABLE IF EXISTS orders; "
        "CREATE TABLE orders (order_id INT, product_id INT, quantity INT, "
        "amount FLOAT, shipping FLOAT, tax FLOAT, shipping_address VARCHAR(20)); "
        "INSERT INTO orders VALUES (%d, 3, 1, 12.5, 2, 1, '%s');"
        % (ORDER_ID, ADDRESS)
    )


def order_body(many=False):
    row = {
        "order_id": ORDER_ID,
        "product_id": 3,
        "quantity": 1,
        "amount": 12.5,
        "shipping": 2.0,
        "tax": 1.0,
        "shipping_address": ADDRESS,
    }
    return json.dumps([row] if many else row).encode()


def request(method, path, body=None, origin=EVIL):
    data = None
    headers = {"Origin": origin}
    if body == "order":
        data = order_body(False)
        headers["Content-Type"] = "application/json"
    elif body == "orders":
        data = order_body(True)
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


def acao_values(headers):
    values = []
    for key, value in headers.items():
        if key.lower() == "access-control-allow-origin":
            values.extend(part.strip() for part in value.split(","))
    return values


def exposed_to(headers, origin):
    values = acao_values(headers)
    return "*" in values or origin in values


class CrossOriginOrderAccessTest(unittest.TestCase):
    def test_untrusted_origin_cannot_read_any_response_build_route(self):
        seed()
        leaked = []
        for method, path, body in ROUTES_WITH_WILDCARD:
            status, headers, payload = request(method, path, body)
            if exposed_to(headers, EVIL):
                leaked.append(
                    "%s %s -> %s ACAO=%s body=%s"
                    % (method, path, status, acao_values(headers), payload[:80])
                )
        self.assertEqual(
            leaked,
            [],
            "untrusted origin can read responses: %s" % leaked,
        )

    def test_get_orders_body_is_not_granted_to_evil_origin(self):
        seed()
        status, headers, payload = request("GET", "/orders")
        self.assertEqual(status, 200)
        self.assertIn(ADDRESS.encode(), payload)
        self.assertFalse(
            exposed_to(headers, EVIL),
            "GET /orders exposed shipping address to %s via %s"
            % (EVIL, acao_values(headers)),
        )

    def test_get_init_does_not_drop_stored_orders(self):
        seed()
        request("GET", "/init")
        self.assertEqual(
            order_count(),
            1,
            "GET /init removed the stored order",
        )

    def test_get_delete_order_does_not_delete(self):
        seed()
        request("GET", "/delete_order?id=%d" % ORDER_ID)
        self.assertEqual(
            order_count(),
            1,
            "GET /delete_order removed the stored order",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
