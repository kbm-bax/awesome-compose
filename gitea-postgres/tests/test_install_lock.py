#!/usr/bin/env python3
"""Security tests for the Gitea sample.

These tests start the sample as compose.yaml defines it and then act as a
network client of the published web port. They are expected to fail while the
installation wizard is unlocked or public registration is left on. A fix that
locks installation and disables public registration before the service accepts
requests makes them pass.

Run from the repository root:

    python3 gitea-postgres/tests/test_install_lock.py
"""

import http.cookiejar
import shutil
import subprocess
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILE = SAMPLE_DIR / "compose.yaml"
HOST = "127.0.0.1"
START_TIMEOUT_SECONDS = 120
REQUEST_TIMEOUT_SECONDS = 120
RESTART_TIMEOUT_SECONDS = 90

# Chosen by the test client. These are not credentials from the sample.
ATTACKER_ADMIN = "netclient"
ATTACKER_ADMIN_EMAIL = "netclient@example.invalid"
ATTACKER_ADMIN_PASSWORD = "placeholder-attacker-password"
OPERATOR_ADMIN = "operator"
OPERATOR_ADMIN_EMAIL = "operator@example.invalid"
OPERATOR_ADMIN_PASSWORD = "placeholder-operator-password"
REGISTERED_USER = "otherclient"
REGISTERED_EMAIL = "otherclient@example.invalid"
REGISTERED_PASSWORD = "placeholder-password"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _InstallFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_form = False
        self.fields = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form" and attributes.get("method", "").lower() == "post":
            self._in_form = True
            return
        if not self._in_form or tag != "input":
            return
        name = attributes.get("name")
        if not name:
            return
        field_type = attributes.get("type", "text").lower()
        if field_type in ("checkbox", "radio"):
            if "checked" in attributes:
                self.fields.append((name, attributes.get("value") or "on"))
            return
        if field_type in ("submit", "button", "image"):
            return
        self.fields.append((name, attributes.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def _docker_command():
    if shutil.which("docker"):
        probe = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode == 0:
            return ["docker"]
    if shutil.which("sudo"):
        probe = subprocess.run(
            ["sudo", "docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode == 0:
            return ["sudo", "docker"]
    raise unittest.SkipTest("docker is not available")


def _published_host_port(compose_text):
    in_gitea = False
    in_ports = False
    for raw_line in compose_text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 2 and stripped.endswith(":"):
            in_gitea = stripped[:-1] == "gitea"
            in_ports = False
            continue
        if not in_gitea:
            continue
        if indent == 4 and stripped == "ports:":
            in_ports = True
            continue
        if in_ports and indent == 4 and stripped.endswith(":"):
            in_ports = False
            continue
        if in_ports and stripped.startswith("-"):
            mapping = stripped[1:].strip().strip("'\"")
            mapping = mapping.split("/", 1)[0]
            host_port = mapping.split(":")[-2] if mapping.count(":") >= 2 else mapping.split(":")[0]
            return int(host_port)
    raise AssertionError("gitea service does not publish a host port in compose.yaml")


def _opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect())


def _request(opener, url, data=None, timeout=REQUEST_TIMEOUT_SECONDS):
    request = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, response.headers.get("Location"), body
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        return error.code, error.headers.get("Location"), body


def _install_form(html):
    parser = _InstallFormParser()
    parser.feed(html)
    return dict(parser.fields)


def _is_install_wizard(html):
    return 'class="page-content install"' in html and 'name="admin_name"' in html and "post-install" not in html


def _post_install(base, fields, timeout=REQUEST_TIMEOUT_SECONDS):
    opener = _opener()
    _request(opener, base + "/", timeout=timeout)
    body = urllib.parse.urlencode(fields).encode()
    status, _location, html = _request(opener, base + "/", data=body, timeout=timeout)
    return status, html


def _can_sign_in(base, username, password):
    opener = _opener()
    _request(opener, base + "/user/login")
    body = urllib.parse.urlencode({"user_name": username, "password": password}).encode()
    status, location, _html = _request(opener, base + "/user/login", data=body)
    if status != 303:
        return False
    return location is not None


def _is_administrator(base, username, password):
    opener = _opener()
    _request(opener, base + "/user/login")
    body = urllib.parse.urlencode({"user_name": username, "password": password}).encode()
    status, _location, _html = _request(opener, base + "/user/login", data=body)
    if status != 303:
        return False
    admin_status, _location, _html = _request(opener, base + "/-/admin")
    return admin_status == 200


def _wait_until(predicate, timeout, description):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as error:  # noqa: BLE001 - the server restarts during install
            last_error = error
        time.sleep(1)
    raise AssertionError(f"timed out waiting until {description}: {last_error}")


class GiteaInstallLockTest(unittest.TestCase):
    def setUp(self):
        self.docker = _docker_command()
        self.port = _published_host_port(COMPOSE_FILE.read_text())
        self.base = f"http://{HOST}:{self.port}"
        self.project = "gitea-install-lock-" + self._testMethodName.replace("_", "-")[-40:]
        self.addCleanup(self._compose_down)
        self._compose("up", "-d")
        _wait_until(self._http_is_up, START_TIMEOUT_SECONDS, "the published web port answers")

    def _compose(self, *args):
        command = self.docker + [
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            self.project,
            *args,
        ]
        completed = subprocess.run(
            command,
            cwd=SAMPLE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(f"docker compose {args[0]} exited {completed.returncode}")

    def _compose_down(self):
        command = self.docker + [
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            self.project,
            "down",
            "-v",
            "--remove-orphans",
        ]
        subprocess.run(
            command,
            cwd=SAMPLE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    def _http_is_up(self):
        status, _location, _body = _request(_opener(), self.base + "/", timeout=5)
        return status == 200

    def _page(self):
        status, _location, html = _request(_opener(), self.base + "/")
        self.assertEqual(status, 200, "the published web port did not return the installation or home page")
        return html

    def _wait_for_restart(self):
        # SubmitInstall shuts the install listener down and the image starts the
        # normal server. Connection errors in between are part of that restart.
        time.sleep(3)
        _wait_until(self._http_is_up, RESTART_TIMEOUT_SECONDS, "Gitea answers again after installation")

    def _rendered_install_fields(self):
        html = self._page()
        self.assertTrue(
            _is_install_wizard(html),
            "the installation wizard was not served to an unauthenticated client",
        )
        fields = _install_form(html)
        self.assertIn("db_type", fields)
        self.assertIn("db_host", fields)
        return fields

    def test_network_client_cannot_submit_installer(self):
        """A client of the published port must not be able to create the administrator.

        The installer form lets the client choose the database type. The image
        registers SQLite, so this submission does not depend on the bundled
        database service staying up.
        """
        fields = self._rendered_install_fields()
        fields["db_type"] = "sqlite3"
        fields["admin_name"] = ATTACKER_ADMIN
        fields["admin_email"] = ATTACKER_ADMIN_EMAIL
        fields["admin_passwd"] = ATTACKER_ADMIN_PASSWORD
        fields["admin_confirm_passwd"] = ATTACKER_ADMIN_PASSWORD
        _status, html = _post_install(self.base, fields)
        if "post-install" in html or "goto-after-install" in html:
            self._wait_for_restart()
        self.assertFalse(
            _is_administrator(self.base, ATTACKER_ADMIN, ATTACKER_ADMIN_PASSWORD),
            "submitting the installation form created an administrator",
        )

    def test_network_client_cannot_register(self):
        """Public registration must stay closed, including after the wizard's own defaults.

        When the wizard is still being served, it is submitted with the
        checkboxes the page rendered and an operator account, so registration
        is whatever the sample put on that form. A second client must then be
        unable to create an account. When the wizard is not served, the same
        client must be unable to create an account on the running service.
        """
        html = self._page()
        if _is_install_wizard(html):
            fields = _install_form(html)
            fields["db_type"] = "sqlite3"
            fields["admin_name"] = OPERATOR_ADMIN
            fields["admin_email"] = OPERATOR_ADMIN_EMAIL
            fields["admin_passwd"] = OPERATOR_ADMIN_PASSWORD
            fields["admin_confirm_passwd"] = OPERATOR_ADMIN_PASSWORD
            _status, submitted = _post_install(self.base, fields)
            self.assertIn(
                "post-install",
                submitted,
                "the rendered installation form did not finish, so registration was left on an open wizard",
            )
            self._wait_for_restart()

        opener = _opener()
        _request(opener, self.base + "/user/sign_up")
        body = urllib.parse.urlencode(
            {
                "user_name": REGISTERED_USER,
                "email": REGISTERED_EMAIL,
                "password": REGISTERED_PASSWORD,
                "retype": REGISTERED_PASSWORD,
            }
        ).encode()
        _request(opener, self.base + "/user/sign_up", data=body)
        self.assertFalse(
            _can_sign_in(self.base, REGISTERED_USER, REGISTERED_PASSWORD),
            "a network client created an account through public registration",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
