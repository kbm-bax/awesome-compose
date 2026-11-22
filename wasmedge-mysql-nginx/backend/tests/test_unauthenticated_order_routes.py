#!/usr/bin/env python3
"""Security spec for the Wasm order service.

An unauthenticated caller who can reach the published order API must not read
shipping addresses and must not insert, update, delete, or reinitialize orders.
These tests fail while that access is open. They pass once every order route
refuses the caller before it touches stored rows.

The database password is the obvious placeholder "placeholder" unless
ORDER_TEST_DB_PASSWORD is set. It is not a credential from the sample compose
file.

Routes that do not read or write orders are not covered: GET /, POST /echo,
and the OPTIONS preflights.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

SERVICE = os.environ.get("ORDER_SERVICE_URL", "http://127.0.0.1:8080")
DB_HOST = os.environ.get("ORDER_TEST_DB_HOST", "127.0.0.1")
DB_PORT = os.environ.get("ORDER_TEST_DB_PORT", "3306")
DB_USER = os.environ.get("ORDER_TEST_DB_USER", "orderapp")
DB_NAME = os.environ.get("ORDER_TEST_DB_NAME", "orders_test")
DB_PASSWORD = os.environ.get("ORDER_TEST_DB_PASSWORD", "placeholder")

SEED_ADDRESS_1 = "seed-addr-1"
SEED_ADDRESS_2 = "seed-addr-2"
ATTACK_ADDRESS = "attacker-addr"

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "compose.yml"


def mysql(sql):
    env = os.environ.copy()
    env["MYSQL_PWD"] = DB_PASSWORD
    result = subprocess.run(
        [
            "mysql",
            "--protocol=tcp",
            "-h",
            DB_HOST,
            "-P",
            DB_PORT,
            "-u",
            DB_USER,
            "--batch",
            "--raw",
            "--skip-column-names",
            DB_NAME,
            "-e",
            sql,
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "mysql failed")
    return result.stdout


def reset_orders():
    mysql(
        """
        DROP TABLE IF EXISTS orders;
        CREATE TABLE orders (
            order_id INT,
            product_id INT,
            quantity INT,
            amount FLOAT,
            shipping FLOAT,
            tax FLOAT,
            shipping_address VARCHAR(20)
        );
        INSERT INTO orders VALUES
            (1, 11, 2, 10, 2, 1, '%s'),
            (2, 12, 4, 20, 3, 2, '%s');
        """
        % (SEED_ADDRESS_1, SEED_ADDRESS_2)
    )


def snapshot():
    return mysql(
        "SELECT order_id, product_id, quantity, amount, shipping, tax, "
        "shipping_address FROM orders ORDER BY order_id;"
    )


def request(method, path, body=None, headers=None):
    data = None if body is None else body.encode()
    req = urllib.request.Request(SERVICE + path, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")


def assert_closed(method, path, body=None, headers=None):
    """The call must not succeed and must not change stored orders."""
    before = snapshot()
    status, payload = request(method, path, body=body, headers=headers)
    after = snapshot()
    problems = []
    if 200 <= status < 300:
        problems.append("status %s" % status)
    for secret in (SEED_ADDRESS_1, SEED_ADDRESS_2):
        if secret in payload:
            problems.append("response contains stored shipping address")
            break
    if after != before:
        problems.append("stored orders changed\n before:\n%s after:\n%s" % (before, after))
    if problems:
        return "%s %s leaked or mutated (%s); body=%r" % (
            method,
            path,
            "; ".join(problems),
            payload,
        )
    return None


ORDER = {
    "order_id": 2,
    "product_id": 12,
    "quantity": 9,
    "amount": 20,
    "shipping": 3,
    "tax": 2,
    "shipping_address": ATTACK_ADDRESS,
}
NEW_ORDER = {
    "order_id": 8,
    "product_id": 1,
    "quantity": 1,
    "amount": 5,
    "shipping": 1,
    "tax": 1,
    "shipping_address": ATTACK_ADDRESS,
}

NO_CREDENTIAL = {}
EMPTY_AUTHORIZATION = {"Authorization": ""}
WRONG_BEARER = {"Authorization": "Bearer placeholder-wrong"}
WRONG_API_HEADER = {"api": "placeholder-wrong"}
BROWSER = {
    "Origin": "https://evil.example",
    "Accept": "text/html,application/xhtml+xml",
    "User-Agent": "Mozilla/5.0",
}


def credential_variants(extra=None):
    base = [NO_CREDENTIAL, EMPTY_AUTHORIZATION, WRONG_BEARER, WRONG_API_HEADER]
    if extra:
        merged = []
        for headers in base:
            copy = dict(BROWSER)
            copy.update(headers)
            copy.update(extra)
            merged.append(copy)
        return base + merged
    return base


def backend_publishes_container_port(text, container_port):
    """True when the backend service maps container_port onto a host port."""
    in_services = False
    in_backend = False
    in_ports = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped == "services:":
            in_services = True
            continue
        if not in_services:
            continue
        if indent == 2 and stripped.endswith(":"):
            in_backend = stripped == "backend:"
            in_ports = False
            continue
        if not in_backend:
            continue
        if indent <= 2:
            in_backend = False
            in_ports = False
            continue
        if indent == 4 and stripped == "ports:":
            in_ports = True
            continue
        if in_ports and indent <= 4 and not stripped.startswith("-"):
            in_ports = False
        if not in_ports or not stripped.startswith("-"):
            continue
        mapping = stripped.lstrip("-").strip().strip("'\"")
        parts = mapping.split(":")
        if len(parts) < 2:
            continue
        published = parts[-1].split("/")[0]
        if published == container_port:
            return True
    return False


def main():
    failures = []
    reset_orders()

    list_cases = []
    for headers in credential_variants():
        list_cases.append(("GET", "/orders", None, headers))
        list_cases.append(("GET", "/orders?id=1", None, headers))

    mutation_cases = []
    bodies = {
        "/create_order": json.dumps(NEW_ORDER),
        "/update_order": json.dumps(ORDER),
        "/create_orders": json.dumps([NEW_ORDER]),
    }
    for headers in credential_variants():
        mutation_cases.append(
            ("POST", "/create_order", bodies["/create_order"], dict(headers, **{"Content-Type": "application/json"}))
        )
        mutation_cases.append(
            ("POST", "/create_orders", bodies["/create_orders"], dict(headers, **{"Content-Type": "application/json"}))
        )
        mutation_cases.append(
            (
                "POST",
                "/update_order?id=1",
                bodies["/update_order"],
                dict(headers, **{"Content-Type": "application/json"}),
            )
        )
        mutation_cases.append(("GET", "/delete_order?id=1", None, headers))
        mutation_cases.append(("GET", "/delete_order?id=1&id=2", None, headers))
        mutation_cases.append(("GET", "/init", None, headers))
        mutation_cases.append(("POST", "/init", "", headers))
        mutation_cases.append(("POST", "/delete_order?id=1", "", headers))
        mutation_cases.append(("DELETE", "/delete_order?id=2", None, headers))

    browser_cases = [
        ("GET", "/orders", None, BROWSER),
        ("GET", "/delete_order?id=2", None, BROWSER),
        ("GET", "/init", None, BROWSER),
    ]

    cases = list_cases + mutation_cases + browser_cases
    for method, path, body, headers in cases:
        reset_orders()
        failure = assert_closed(method, path, body=body, headers=headers)
        label = "%s %s headers=%s" % (method, path, sorted(headers))
        if failure:
            failures.append(label + " :: " + failure)
            print("FAIL", failure)
        else:
            print("PASS", label)

    if not COMPOSE_FILE.is_file():
        failures.append("missing %s" % COMPOSE_FILE)
        print("FAIL compose file missing")
    elif backend_publishes_container_port(COMPOSE_FILE.read_text(), "8080"):
        failures.append(
            "backend service publishes container port 8080 on the host (%s)"
            % COMPOSE_FILE
        )
        print("FAIL compose publishes backend port 8080")
    else:
        print("PASS compose does not publish backend port 8080")

    print("%s failed, %s passed" % (len(failures), len(cases) + 1 - len(failures)))
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
