#!/usr/bin/env python3
"""Spec for the Plex sample's unclaimed first start.

These tests fail while the sample is exploitable. They pass once a neighbor
on the operator's LAN can no longer claim the server or attach the mounted
media path.

Run from the repository root:

    python3 -m unittest plex.tests.test_unclaimed_subnet_claim

The process needs sudo (network namespaces) and network access to download
Plex Media Server the first time. The claim token sent by the tests is the
placeholder PLACEHOLDER_CLAIM_TOKEN.
"""

from __future__ import annotations

import os
import subprocess
import time
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
SAMPLE = REPO / "plex"
CLAIM_SCRIPT = Path(__file__).resolve().parent / "fixtures" / "init-plex-claim"

# linuxserver/docker-plex 4cfd2594caa353a5282bf00b7b7bdc38da25fefc
# package_versions.txt pins the server this image starts.
PMS_VERSION = "1.43.5.11079-b3b13e506"
PMS_DEB_URL = (
    "https://downloads.plex.tv/plex-media-server-new/"
    f"{PMS_VERSION}/debian/plexmediaserver_{PMS_VERSION}_amd64.deb"
)
PMS_CACHE = Path("/tmp/plex-claim-test/pms")
NETNS = "pclaimns"
SERVER_IP = "10.51.0.2"
SAME_SUBNET_IP = "10.51.0.1"
OTHER_SUBNET_IP = "10.61.0.1"
OTHER_SERVER_IP = "10.61.0.2"
CLAIM_TOKEN = "PLACEHOLDER_CLAIM_TOKEN"

_STATE: dict = {}


def _run(cmd, check=True, **kwargs):
    return subprocess.run(cmd, check=check, text=True, **kwargs)


def _sudo(cmd, check=True, **kwargs):
    return _run(["sudo", *cmd], check=check, **kwargs)


def load_service() -> dict:
    data = yaml.safe_load((SAMPLE / "compose.yaml").read_text())
    services = data.get("services") or {}
    if "plex" not in services:
        raise AssertionError("plex service is missing from plex/compose.yaml")
    return services["plex"]


def container_environment(service: dict) -> dict[str, str]:
    """Environment the service block actually sets in the container."""
    env = service.get("environment") or []
    values: dict[str, str] = {}
    if isinstance(env, dict):
        for key, value in env.items():
            values[str(key)] = "" if value is None else str(value)
        return values
    for item in env:
        text = str(item)
        if "=" in text:
            key, value = text.split("=", 1)
            values[key] = value
        else:
            values[text] = ""
    return values


def lan_neighbor_is_on_server_subnet(service: dict) -> bool:
    """Host networking puts the server on the host's subnets.

    Compose spec `network_mode: host` gives the container the host network
    interface. Any other mode attaches the service to its own network, and a
    published-port connection keeps the neighbor's source address (Docker
    29.1.3 DNAT). That address is not on the container subnet, which is the
    case Plex classifies as WAN.
    """
    return str(service.get("network_mode") or "").strip() == "host"


def run_claim_init(env: dict[str, str], support_dir: Path) -> str:
    """Run the image's claim script the way the container runs it."""
    script_env = os.environ.copy()
    script_env.update(env)
    script_env["PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR"] = str(support_dir)
    # The sample does not set a claim token. Keep an empty value absent so
    # the script's `-z` check sees the same environment the container would.
    if not script_env.get("PLEX_CLAIM"):
        script_env.pop("PLEX_CLAIM", None)
    completed = subprocess.run(
        ["bash", str(CLAIM_SCRIPT)],
        cwd=support_dir,
        env=script_env,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout + completed.stderr


def _ensure_pms() -> Path:
    binary = PMS_CACHE / "usr/lib/plexmediaserver/Plex Media Server"
    if binary.exists():
        return binary
    PMS_CACHE.mkdir(parents=True, exist_ok=True)
    deb = PMS_CACHE / "plex.deb"
    if not deb.exists() or deb.stat().st_size < 1000:
        _run(["curl", "-fsSL", "-o", str(deb), PMS_DEB_URL])
    _run(["dpkg-deb", "-x", str(deb), str(PMS_CACHE)])
    if not binary.exists():
        raise RuntimeError(f"Plex Media Server binary missing after extract: {binary}")
    return binary


def _setup_netns() -> None:
    subprocess.run(
        ["sudo", "ip", "netns", "del", NETNS],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for name in ("pclaim-same", "pclaim-other"):
        subprocess.run(
            ["sudo", "ip", "link", "del", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    _sudo(["ip", "netns", "add", NETNS])
    _sudo(["ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up"])
    _sudo(["ip", "link", "add", "pclaim-same", "type", "veth", "peer", "name", "pclaim-same-ns"])
    _sudo(["ip", "link", "set", "pclaim-same-ns", "netns", NETNS])
    _sudo(["ip", "addr", "add", f"{SAME_SUBNET_IP}/24", "dev", "pclaim-same"])
    _sudo(["ip", "link", "set", "pclaim-same", "up"])
    _sudo(["ip", "netns", "exec", NETNS, "ip", "addr", "add", f"{SERVER_IP}/24", "dev", "pclaim-same-ns"])
    _sudo(["ip", "netns", "exec", NETNS, "ip", "link", "set", "pclaim-same-ns", "up"])
    _sudo(["ip", "link", "add", "pclaim-other", "type", "veth", "peer", "name", "pclaim-other-ns"])
    _sudo(["ip", "link", "set", "pclaim-other-ns", "netns", NETNS])
    _sudo(["ip", "addr", "add", f"{OTHER_SUBNET_IP}/24", "dev", "pclaim-other"])
    _sudo(["ip", "link", "set", "pclaim-other", "up"])
    _sudo(["ip", "netns", "exec", NETNS, "ip", "addr", "add", f"{OTHER_SERVER_IP}/24", "dev", "pclaim-other-ns"])
    _sudo(["ip", "netns", "exec", NETNS, "ip", "link", "set", "pclaim-other-ns", "up"])


def _start_pms(binary: Path, support: Path, media: Path) -> subprocess.Popen:
    helper = Path("/tmp/plex-claim-test/start-pms.sh")
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text(
        "\n".join(
            [
                "#!/bin/bash",
                "set -euo pipefail",
                f'export PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR="{support}"',
                f'export PLEX_MEDIA_SERVER_HOME="{binary.parent}"',
                "export PLEX_MEDIA_SERVER_MAX_PLUGIN_PROCS=6",
                "export PLEX_MEDIA_SERVER_INFO_VENDOR=Docker",
                'export PLEX_MEDIA_SERVER_INFO_DEVICE="Docker Container (LinuxServer.io)"',
                'export PLEX_MEDIA_SERVER_INFO_MODEL="$(uname -m)"',
                'export PLEX_MEDIA_SERVER_INFO_PLATFORM_VERSION="$(uname -r)"',
                "export TMPDIR=/tmp/plex-claim-test/tmp",
                'mkdir -p "$TMPDIR" "$PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR"',
                'cd "$PLEX_MEDIA_SERVER_HOME"',
                'exec ./Plex\\ Media\\ Server',
                "",
            ]
        )
    )
    helper.chmod(0o755)
    log = open("/tmp/plex-claim-test/pms.log", "w")
    proc = subprocess.Popen(
        ["sudo", "ip", "netns", "exec", NETNS, str(helper)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    _STATE["log"] = log
    deadline = time.time() + 90
    last = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("Plex Media Server exited during startup")
        try:
            status, body = http("GET", "/identity", SAME_SUBNET_IP, timeout=3)
        except Exception as exc:  # noqa: BLE001 - startup probe
            last = str(exc)
            time.sleep(1)
            continue
        if status == 200 and 'claimed="0"' in body and "startState" not in body:
            return proc
        last = f"status={status}"
        time.sleep(1)
    raise RuntimeError(f"Plex did not become ready: {last}")


def http(method: str, path: str, source_ip: str, timeout: float = 20) -> tuple[int, str]:
    cmd = [
        "curl",
        "-sS",
        "-g",
        "--interface",
        source_ip,
        "--max-time",
        str(timeout),
        "-o",
        "/tmp/plex-claim-test/body",
        "-w",
        "%{http_code}",
        "-X",
        method,
        f"http://{SERVER_IP}:32400{path}",
    ]
    completed = subprocess.run(cmd, text=True, capture_output=True, check=False)
    body = ""
    body_path = Path("/tmp/plex-claim-test/body")
    if body_path.exists():
        body = body_path.read_text(errors="replace")
    if completed.returncode != 0 and not completed.stdout.strip().isdigit():
        raise RuntimeError(completed.stderr.strip() or f"curl exit {completed.returncode}")
    code = int(completed.stdout.strip() or "0")
    return code, body


def _log_text() -> str:
    log = Path("/tmp/plex-support-claim/Plex Media Server/Logs/Plex Media Server.log")
    # support dir is stored in state; fall back to the known test path
    support = _STATE.get("support")
    if support:
        log = Path(support) / "Plex Media Server" / "Logs" / "Plex Media Server.log"
    if not log.exists():
        return ""
    try:
        return log.read_text(errors="replace")
    except PermissionError:
        return subprocess.check_output(["sudo", "cat", str(log)], text=True, errors="replace")


def setUpModule() -> None:
    service = load_service()
    env = container_environment(service)
    support = Path("/tmp/plex-claim-test/support")
    media = Path("/tmp/plex-claim-test/media")
    # The server runs as root inside the namespace and owns its data directory.
    subprocess.run(["sudo", "rm", "-rf", str(support), str(media)], check=True)
    support.mkdir(parents=True)
    media.mkdir(parents=True)
    (media / "library-file.txt").write_text("sample-media-marker\n")
    app_support = support / "config"
    app_support.mkdir(parents=True)
    if env.get("PLEX_CLAIM"):
        # A non-empty value still has to be exchanged with the claim service
        # before the server is claimed. Do not perform that exchange here.
        init_out = ""
    else:
        init_out = run_claim_init(env, app_support)
    binary = _ensure_pms()
    _setup_netns()
    # Fresh support dir: the claim script exits before creating preferences
    # when no token is set, then the service starts the server.
    pms_support = support / "Library" / "Application Support"
    proc = _start_pms(binary, pms_support, media)
    attacker = SAME_SUBNET_IP if lan_neighbor_is_on_server_subnet(service) else OTHER_SUBNET_IP
    _STATE.update(
        service=service,
        env=env,
        init_out=init_out,
        media=media,
        support=pms_support,
        proc=proc,
        attacker=attacker,
    )


def tearDownModule() -> None:
    proc = _STATE.get("proc")
    if proc and proc.poll() is None:
        subprocess.run(["sudo", "kill", str(proc.pid)], check=False)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "kill", "-9", str(proc.pid)], check=False)
    log = _STATE.get("log")
    if log:
        log.close()
    subprocess.run(
        ["sudo", "ip", "netns", "del", NETNS],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for name in ("pclaim-same", "pclaim-other"):
        subprocess.run(
            ["sudo", "ip", "link", "del", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


class UnclaimedSubnetClaimTest(unittest.TestCase):
    def test_sample_starts_unclaimed_without_a_claim_token(self) -> None:
        env = _STATE["env"]
        if not env.get("PLEX_CLAIM"):
            self.assertIn("no claim token has been set", _STATE["init_out"])
        code, body = http("GET", "/identity", _STATE["attacker"])
        self.assertEqual(code, 200, body[:200])
        self.assertIn('claimed="0"', body)

    def test_lan_neighbor_cannot_use_the_unclaimed_server(self) -> None:
        code, _body = http("GET", "/", _STATE["attacker"])
        self.assertEqual(
            code,
            401,
            "a LAN neighbor received the unauthenticated server root from an unclaimed Plex",
        )

    def test_lan_neighbor_cannot_submit_a_claim(self) -> None:
        before = len(_log_text())
        code, _body = http(
            "POST",
            f"/myplex/claim?token={CLAIM_TOKEN}",
            _STATE["attacker"],
            timeout=25,
        )
        added = _log_text()[before:]
        self.assertEqual(
            code,
            401,
            "the claim endpoint accepted a LAN neighbor on an unclaimed server",
        )
        self.assertNotIn(
            "api/claim/exchange",
            added,
            "the server started a claim exchange for a LAN neighbor",
        )

    def test_lan_neighbor_cannot_attach_the_mounted_media(self) -> None:
        media = _STATE["media"]
        query = (
            "name=Mounted&type=13&agent=com.plexapp.agents.none"
            "&scanner=Plex%20Photo%20Scanner&language=xn"
            f"&location={media}"
        )
        code, body = http("POST", f"/library/sections?{query}", _STATE["attacker"])
        self.assertEqual(
            code,
            401,
            "a LAN neighbor attached a library on the mounted media path "
            f"(status {code})",
        )
        self.assertNotIn(str(media), body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
