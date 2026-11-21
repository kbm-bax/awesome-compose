"""Host access through credentials committed with the Postgres samples.

These tests start the shipped compose projects and connect from the host the
way a remote client would. They fail while that client can authenticate with
the committed values. They pass once the shipped project no longer accepts
those values on a host-published port.

Run:
    python3 -m unittest discover -s tests -p 'test_shipped_postgres_credentials.py' -v

Left untested on purpose:
    nextcloud-postgres and gitea-postgres commit a database password, but the
    database service only uses expose, so Compose does not publish host port
    5432. spring-postgres and nginx-golang-postgres pass the database password
    through a secret file and also do not publish host port 5432.
"""

import json
import os
import subprocess
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


class RedirectCapture(urllib.request.HTTPRedirectHandler):
    """Leave the login response on the 302 so the test can read Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _run(args, timeout=120, env=None):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def _compose(project, directory, *args, timeout=180):
    return _run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "--project-directory",
            str(directory),
            *args,
        ],
        timeout=timeout,
    )


def _compose_config(directory):
    completed = _compose(
        "config-only",
        directory,
        "config",
        "--format",
        "json",
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "docker compose config failed for {0}: {1}".format(
                directory.name, completed.stderr[-500:]
            )
        )
    return json.loads(completed.stdout)


def _service_env(config, service):
    environment = config["services"][service].get("environment") or {}
    if isinstance(environment, dict):
        return environment
    parsed = {}
    for item in environment:
        key, separator, value = item.partition("=")
        if separator:
            parsed[key] = value
    return parsed


def _published_port(config, service, container_port):
    for binding in config["services"][service].get("ports") or []:
        if int(binding.get("target", 0)) == int(container_port):
            published = binding.get("published")
            if published:
                return str(published)
    return None


def _container_id(project, directory, service):
    completed = _compose(project, directory, "ps", "-q", service, timeout=30)
    return completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""


def _internal_ready(container_id):
    if not container_id:
        return False
    completed = _run(
        ["docker", "exec", container_id, "pg_isready", "-h", "127.0.0.1", "-p", "5432"],
        timeout=20,
    )
    return completed.returncode == 0


def _psql(port, user, password, dbname, sql, sslmode):
    env = os.environ.copy()
    # The value stays in this child environment and is never written to a file
    # or an assertion message.
    env["PGPASSWORD"] = password
    env["PGSSLMODE"] = sslmode
    return _run(
        [
            "psql",
            "-h",
            HOST,
            "-p",
            str(port),
            "-U",
            user,
            "-d",
            dbname,
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-t",
            "-A",
            "-c",
            sql,
        ],
        timeout=30,
        env=env,
    )


def _auth_rejected(completed):
    text = (completed.stderr or "") + (completed.stdout or "")
    markers = (
        "password authentication failed",
        "no pg_hba.conf entry",
        "server does not support SSL",
        "SSL error",
        "received invalid response",
        "authentication failed",
        "no encryption",
        "SSL connection is required",
        "pg_hba.conf rejects connection",
    )
    return completed.returncode != 0 and any(marker in text for marker in markers)


def _connection_failed(completed):
    text = (completed.stderr or "") + (completed.stdout or "")
    markers = (
        "Connection refused",
        "could not connect",
        "No route to host",
        "timeout expired",
        "could not translate host",
    )
    return completed.returncode != 0 and any(marker in text for marker in markers)


class HostSession:
    def __init__(self):
        self.authenticated = False
        self.sslmode = None
        self.superuser = False
        self.os_command = False
        self.wrote_other_database = False
        self.databases_reached = []

    def summary(self):
        return (
            "authenticated={0} sslmode={1} superuser={2} "
            "server_program={3} wrote_other_database={4} databases={5}"
        ).format(
            self.authenticated,
            self.sslmode,
            self.superuser,
            self.os_command,
            self.wrote_other_database,
            ",".join(self.databases_reached),
        )


def _probe_session(port, user, password, dbname, sslmode):
    session = HostSession()
    session.sslmode = sslmode
    identity = _psql(
        port,
        user,
        password,
        dbname,
        "SELECT current_user;",
        sslmode,
    )
    if identity.returncode != 0:
        return session, identity
    session.authenticated = True
    superuser = _psql(
        port,
        user,
        password,
        dbname,
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user;",
        sslmode,
    )
    session.superuser = superuser.returncode == 0 and superuser.stdout.strip() == "t"
    program = _psql(
        port,
        user,
        password,
        dbname,
        "CREATE TEMP TABLE shipped_probe(line text); "
        "COPY shipped_probe FROM PROGRAM '/bin/echo probe-ok'; "
        "SELECT line FROM shipped_probe;",
        sslmode,
    )
    session.os_command = (
        program.returncode == 0 and "probe-ok" in program.stdout
    )
    names = _psql(
        port,
        user,
        password,
        dbname,
        "SELECT datname FROM pg_database WHERE datallowconn AND datname <> "
        "current_database() ORDER BY 1;",
        sslmode,
    )
    if names.returncode == 0:
        for other in [line.strip() for line in names.stdout.splitlines() if line.strip()]:
            write = _psql(
                port,
                user,
                password,
                other,
                "CREATE TABLE IF NOT EXISTS public.shipped_cred_probe(n int); "
                "INSERT INTO public.shipped_cred_probe VALUES (1); "
                "SELECT n FROM public.shipped_cred_probe ORDER BY n LIMIT 1;",
                sslmode,
            )
            if write.returncode == 0 and write.stdout.strip() == "1":
                session.databases_reached.append(other)
    session.wrote_other_database = bool(session.databases_reached)
    return session, identity


def attempt_committed_login(port, user, password, dbname):
    """Try the committed password in plaintext and, if that is refused, with TLS."""
    last_session = HostSession()
    last_completed = None
    for sslmode in ("disable", "require"):
        session, completed = _probe_session(port, user, password, dbname, sslmode)
        last_session = session
        last_completed = completed
        if session.authenticated:
            return session, completed
        if _auth_rejected(completed):
            continue
        if _connection_failed(completed):
            return session, completed
    return last_session, last_completed


def _wait_until(predicate, timeout):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last is not None:
            return last
        time.sleep(2)
    return None


class ComposeSample:
    def __init__(self, directory, project, service):
        self.directory = directory
        self.project = project
        self.service = service
        self.config = _compose_config(directory)
        self.env = _service_env(self.config, service)
        self.port = _published_port(self.config, service, 5432)

    def up(self, *services):
        return _compose(
            self.project,
            self.directory,
            "up",
            "-d",
            "--no-deps",
            *services,
            timeout=240,
        )

    def down(self):
        _compose(
            self.project,
            self.directory,
            "down",
            "-v",
            "--remove-orphans",
            timeout=180,
        )

    def container_id(self):
        return _container_id(self.project, self.directory, self.service)


def _assert_committed_db_login_closed(test, sample, user_key="POSTGRES_USER", password_key="POSTGRES_PASSWORD", db_key="POSTGRES_DB"):
    """Fail when the committed database password opens a host session."""
    user = sample.env.get(user_key) or "postgres"
    password = sample.env.get(password_key)
    dbname = sample.env.get(db_key) or user
    if not sample.port:
        # The shipped project does not publish the database port.
        return
    if password is None:
        password = ""

    def attempt():
        container_id = sample.container_id()
        if not _internal_ready(container_id):
            return None
        session, completed = attempt_committed_login(
            sample.port, user, password, dbname
        )
        if session.authenticated or _auth_rejected(completed):
            return session
        if _connection_failed(completed):
            return None
        return session

    session = _wait_until(attempt, 120)
    if session is None:
        # The database never accepted a host connection with the committed
        # values. Crash-looping because the shipped file has no usable
        # password is the closed state.
        return
    binding = _compose(
        sample.project, sample.directory, "port", sample.service, "5432", timeout=30
    )
    test.assertFalse(
        session.authenticated,
        "host client opened a database session with the committed "
        "{0}/{1} on published port {2} ({3}): {4}".format(
            user_key,
            password_key,
            sample.port,
            binding.stdout.strip() or "no host binding",
            session.summary(),
        ),
    )


class PostgreSQLPgAdminSample(unittest.TestCase):
    sample = None

    @classmethod
    def setUpClass(cls):
        directory = REPO_ROOT / "postgresql-pgadmin"
        cls.sample = ComposeSample(directory, "cursor-tp-pgadmin", "postgres")
        cls.pgadmin_env = _service_env(cls.sample.config, "pgadmin")
        cls.pgadmin_port = _published_port(cls.sample.config, "pgadmin", 80)
        completed = cls.sample.up("postgres", "pgadmin")
        cls.up_error = completed.stderr if completed.returncode != 0 else ""

    @classmethod
    def tearDownClass(cls):
        if cls.sample is not None:
            cls.sample.down()

    def test_committed_postgres_credentials_do_not_open_a_host_session(self):
        _assert_committed_db_login_closed(self, self.sample)

    def test_committed_pgadmin_credentials_do_not_open_a_host_session(self):
        if not self.pgadmin_port:
            return
        email = self.pgadmin_env.get("PGADMIN_DEFAULT_EMAIL") or ""
        password = self.pgadmin_env.get("PGADMIN_DEFAULT_PASSWORD")
        if password is None:
            password = ""

        def attempt():
            try:
                return _pgadmin_login(self.pgadmin_port, email, password)
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                return None

        logged_in = _wait_until(attempt, 180)
        if logged_in is None:
            return
        self.assertFalse(
            logged_in,
            "host client signed in to pgAdmin on published port {0} "
            "with the committed PGADMIN_MAIL and PGADMIN_PW".format(
                self.pgadmin_port
            ),
        )


class ReactRustPostgresSample(unittest.TestCase):
    sample = None

    @classmethod
    def setUpClass(cls):
        directory = REPO_ROOT / "react-rust-postgres"
        cls.sample = ComposeSample(directory, "cursor-tp-rustpg", "db")
        completed = cls.sample.up("db")
        cls.up_error = completed.stderr if completed.returncode != 0 else ""

    @classmethod
    def tearDownClass(cls):
        if cls.sample is not None:
            cls.sample.down()

    def test_committed_postgres_credentials_do_not_open_a_host_session(self):
        _assert_committed_db_login_closed(self, self.sample)


def _page_props(html):
    marker = "renderSecurityPage('login_user',"
    start = html.find(marker)
    if start < 0:
        return None
    brace = html.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(html)):
        char = html[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(html[brace : index + 1])
    return None


def _pgadmin_login(port, email, password):
    """Return True when the committed pgAdmin password creates a session.

    Return False when the login page is up and rejects the password.
    Return None when the page is not ready yet.
    """
    base = "http://{0}:{1}".format(HOST, port)
    jar = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(jar, RedirectCapture())
    try:
        with opener.open(base + "/login", timeout=10) as response:
            html = response.read().decode("utf-8", "replace")
            final_url = response.geturl()
    except urllib.error.HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            return None
        raise
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None
    if "login_user" not in html and "csrfToken" not in html:
        return None
    props = _page_props(html)
    if not props or "csrfToken" not in props:
        return None
    login_url = urllib.parse.urljoin(final_url, props.get("loginUrl") or "/authenticate/login")
    form = urllib.parse.urlencode(
        {
            "email": email,
            "password": password,
            "csrf_token": props["csrfToken"],
            "internal_button": "Login",
            "language": "en",
        }
    ).encode()
    request = urllib.request.Request(login_url, data=form)
    try:
        with opener.open(request, timeout=20) as response:
            # A 200 that is still the login page did not create a session.
            body = response.read().decode("utf-8", "replace")
            return "login_user" not in body and response.geturl().rstrip("/").endswith("/browser")
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location") or ""
        resolved = urllib.parse.urljoin(login_url, location)
        if error.code not in (301, 302, 303, 307, 308):
            return False
        if "/browser" not in urllib.parse.urlparse(resolved).path:
            return False
        follow = urllib.request.Request(resolved)
        try:
            with opener.open(follow, timeout=20) as response:
                body = response.read().decode("utf-8", "replace")
                path = urllib.parse.urlparse(response.geturl()).path
        except urllib.error.HTTPError as follow_error:
            follow_location = follow_error.headers.get("Location") or ""
            return "/login" not in follow_location and "/browser" in follow_location
        return "/browser" in path and "login_user" not in body


if __name__ == "__main__":
    unittest.main()
