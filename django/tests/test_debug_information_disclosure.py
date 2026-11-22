"""Security regressions for the Django sample's default debug configuration.

The sample starts ``manage.py runserver`` with no ``DEBUG`` or ``ALLOWED_HOSTS``
set. These tests issue the HTTP requests an unauthenticated client can send to
that server and require the responses to omit Django's technical debug pages.

They fail while debug mode stays on by default. They pass once that default is
off. Assertion messages name the marker that was disclosed and do not include
the response body.

RequestDataTooBig and TooManyFieldsSent are not requested here. Both are
SuspiciousOperation subclasses and, while debug mode is on, use the same
technical 400 response as a disallowed Host header.
"""

import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1] / "app"

# Markers that the technical 500 / technical 400 page copies out of this
# sample's configuration or out of the interpreter. The plain 400 and 404
# handlers do not emit them.
SETTINGS_DISCLOSURE_MARKERS = (
    "db.sqlite3",
    "example.settings",
    "BASE_DIR",
    "Python Path",
    "django.contrib.admin",
)


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DebugInformationDisclosureTests(unittest.TestCase):
    """The development server must not return Django's debug pages."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.port = _free_port()
        env = os.environ.copy()
        # Operator overrides would hide the sample's own defaults.
        env.pop("DEBUG", None)
        env.pop("ALLOWED_HOSTS", None)
        env.pop("SECRET_KEY", None)
        cls._log = tempfile.TemporaryFile()
        # Same command as django/app/Dockerfile, with --noreload so this
        # process is the one that serves requests, and with an ephemeral port.
        cls._server = subprocess.Popen(
            [
                sys.executable,
                "manage.py",
                "runserver",
                "0.0.0.0:%s" % cls.port,
                "--noreload",
            ],
            cwd=APP_DIR,
            env=env,
            stdout=cls._log,
            stderr=subprocess.STDOUT,
        )
        cls._wait_until_serving()

    @classmethod
    def tearDownClass(cls):
        cls._server.terminate()
        try:
            cls._server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls._server.kill()
            cls._server.wait(timeout=10)
        cls._log.close()
        super().tearDownClass()

    @classmethod
    def _wait_until_serving(cls):
        deadline = time.time() + 30
        while time.time() < deadline:
            if cls._server.poll() is not None:
                raise RuntimeError("development server exited during startup")
            try:
                status, _body = cls._exchange(
                    "GET", "/ready", "localhost"
                )
            except (ConnectionRefusedError, TimeoutError, OSError):
                time.sleep(0.2)
                continue
            if status:
                return
        raise RuntimeError("development server did not accept a connection")

    @classmethod
    def _exchange(cls, method, path, host, body=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", cls.port, timeout=5
        )
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={"Host": host},
            )
            response = connection.getresponse()
            payload = response.read()
            return response.status, payload.decode("utf-8", errors="replace")
        finally:
            connection.close()

    def _response(self, method, path, host, body=None):
        try:
            return self._exchange(method, path, host, body)
        except OSError as exc:
            self.fail("request %s %s failed: %s" % (method, path, exc.__class__.__name__))

    def _assert_absent(self, payload, marker):
        if marker in payload:
            self.fail("response disclosed %r" % marker)

    def test_allowed_host_unknown_path_does_not_return_debug_404(self):
        status, payload = self._response(
            "GET", "/this-page-is-not-real", "localhost"
        )
        self.assertEqual(status, 404)
        self._assert_absent(payload, "DEBUG = True")
        self._assert_absent(payload, "example.urls")

    def test_allowed_host_root_does_not_return_debug_install_page(self):
        _status, payload = self._response("GET", "/", "localhost")
        self._assert_absent(payload, "DEBUG=True")
        self._assert_absent(payload, "The install worked successfully")

    def test_disallowed_host_does_not_return_settings_traceback(self):
        status, payload = self._response(
            "GET", "/this-page-is-not-real", "attacker.example"
        )
        self.assertEqual(status, 400)
        for marker in SETTINGS_DISCLOSURE_MARKERS:
            self._assert_absent(payload, marker)

    def test_post_without_trailing_slash_does_not_return_settings_traceback(self):
        _status, payload = self._response(
            "POST", "/admin", "localhost", body=b""
        )
        for marker in SETTINGS_DISCLOSURE_MARKERS:
            self._assert_absent(payload, marker)


if __name__ == "__main__":
    unittest.main()
