"""GCP Cloud Shell backend.

Mirrors the AWS backend in common.py, but the transport is plain SSH instead of
SSM. The Cloud Shell API hands out an ``sshHost``/``sshPort``/``sshUsername``
triple for the caller's single environment; we register an ephemeral public key,
open one SSH connection, and drive it exactly like the SSM shell.

Two differences from AWS are structural, not incidental:

* There is no region choice. Every Google account gets one Cloud Shell
  environment in a region Google picks, so the region picker does not apply.
* SSH allows TCP forwarding (``AllowTcpForwarding yes``), which makes the UDP
  hole punch optional: ``-L`` can carry OpenVPN over the SSH connection itself.
  ``PermitTunnel`` is off, so ``ssh -w`` (layer-3 tun over SSH) is not an option.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .common import DATA_DIR, SHELL_STARTUP_DELAY_S, Shell, VpnError

log = logging.getLogger(__name__)

API_ROOT = "https://cloudshell.googleapis.com/v1"
ENV_NAME = "users/me/environments/default"
ENV_URL = f"{API_ROOT}/{ENV_NAME}"

# Cloud Shell rejects ed25519 keys (the API answers 500 INTERNAL). RSA is what
# gcloud itself registers, and it is what the service accepts.
KEY_TYPE = "rsa"
KEY_BITS = 2048
KEY_PATH = DATA_DIR / "gcp_cloudshell_key"

START_TIMEOUT_S = 300
SSH_KEEPALIVE_INTERVAL_S = 60


class GcpError(VpnError):
    pass


# --------------------------------------------------------------- credentials


def access_token() -> str:
    """Fetch an OAuth token from the gcloud CLI.

    Shelling out to gcloud keeps google-auth out of requirements.txt, and it
    means the tool inherits whatever login the user already has — including the
    proxy and custom-CA settings gcloud was configured with.
    """
    if not shutil.which("gcloud"):
        raise GcpError(
            "gcloud CLI not found.\n"
            "  Install it: https://cloud.google.com/sdk/docs/install\n"
            "  Then authenticate: gcloud auth login"
        )
    proc = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True, timeout=60,
    )
    token = proc.stdout.strip()
    if proc.returncode != 0 or not token:
        raise GcpError(
            f"Could not get a GCP access token.\n"
            f"  Authenticate with: gcloud auth login\n"
            f"  gcloud said: {proc.stderr.strip() or 'no output'}"
        )
    return token


def _api(path: str, body: dict | None = None, timeout: int = 60) -> dict:
    """Call the Cloud Shell API. POST when a body is given, GET otherwise."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        path,
        data=data,
        method="POST" if data is not None else "GET",
        headers={
            "Authorization": f"Bearer {access_token()}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail)["error"]["message"]
        except Exception:
            pass
        if e.code == 403:
            raise GcpError(
                f"Cloud Shell API denied the request: {detail}\n"
                f"  Enable the API: gcloud services enable cloudshell.googleapis.com\n"
                f"  Cloud Shell must also be enabled for your account."
            )
        raise GcpError(f"Cloud Shell API error ({e.code}): {detail}")
    except urllib.error.URLError as e:
        raise GcpError(
            f"Cannot reach the Cloud Shell API: {e.reason}\n"
            f"  Behind a proxy? Set HTTPS_PROXY, and point gcloud at your\n"
            f"  corporate CA with: gcloud config set core/custom_ca_certs_file <ca.pem>"
        )


def validate_credentials() -> None:
    """Fail early, with an actionable message, if GCP access is not usable."""
    env = _api(ENV_URL)
    if "sshUsername" not in env:
        raise GcpError(f"Unexpected Cloud Shell API response: {env}")


# --------------------------------------------------------------- environment


class Environment:
    """Connection details for the caller's Cloud Shell environment."""

    def __init__(self, payload: dict) -> None:
        self.state: str = payload.get("state", "UNKNOWN")
        self.ssh_host: str = payload.get("sshHost", "")
        self.ssh_port: int = int(payload.get("sshPort", 0) or 0)
        self.ssh_username: str = payload.get("sshUsername", "")
        self.web_host: str = payload.get("webHost", "")

    @property
    def ready(self) -> bool:
        return self.state == "RUNNING" and bool(self.ssh_host and self.ssh_port)

    def __str__(self) -> str:
        return f"{self.ssh_username}@{self.ssh_host}:{self.ssh_port} ({self.state})"


def get_environment() -> Environment:
    return Environment(_api(ENV_URL))


def start_environment(public_key: str, timeout: int = START_TIMEOUT_S) -> Environment:
    """Bring the environment to RUNNING and make sure our key is registered.

    ``:start`` both boots a suspended environment and installs the key, so a
    single call covers the cold path. A already-running environment still needs
    the key, hence the explicit add.
    """
    env = get_environment()
    if not env.ready:
        log.info(f"Starting Cloud Shell environment (state: {env.state})...")
        _api(f"{ENV_URL}:start", {"publicKeys": [public_key]})
        deadline = time.time() + timeout
        while not env.ready:
            if time.time() > deadline:
                raise GcpError(f"Environment stuck in state {env.state}")
            time.sleep(3)
            env = get_environment()
            log.info(f"State: {env.state}...")
    add_public_key(public_key)
    log.info(f"Cloud Shell ready: {env}")
    return env


def add_public_key(public_key: str) -> None:
    try:
        _api(f"{ENV_URL}:addPublicKey", {"key": public_key})
    except GcpError as e:
        raise GcpError(
            f"Could not register the SSH key with Cloud Shell: {e}\n"
            f"  Cloud Shell caps the number of stored keys. Prune them at\n"
            f"  https://shell.cloud.google.com (Settings > Manage public keys)."
        )


def remove_public_key(public_key: str) -> None:
    """Best-effort key removal — never let cleanup failure mask a real error."""
    try:
        _api(f"{ENV_URL}:removePublicKey", {"key": public_key})
    except Exception as e:
        log.warning(f"Could not remove the ephemeral SSH key: {e}")


# ------------------------------------------------------------------ ssh key


def ensure_keypair() -> tuple[Path, str]:
    """Generate a fresh keypair for this run. Returns (private path, public key).

    Regenerated every run: the key lives as long as the session, and a stale key
    left in the account is exactly what we clean up on exit.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)  # mkdir ignores mode when the dir exists
    for path in (KEY_PATH, KEY_PATH.with_suffix(".pub")):
        path.unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", KEY_TYPE, "-b", str(KEY_BITS), "-N", "",
         "-f", str(KEY_PATH), "-C", "cloudshell-vpn"],
        check=True, capture_output=True, timeout=120,
    )
    os.chmod(KEY_PATH, 0o600)
    # The API matches keys verbatim, so strip the comment: what we send on add
    # has to be byte-identical to what we send on remove.
    pub = KEY_PATH.with_suffix(".pub").read_text().split()
    return KEY_PATH, f"{pub[0]} {pub[1]}"


# -------------------------------------------------------------------- shell


class GcpShell(Shell):
    """An SSH session to Cloud Shell, driven like the SSM shell.

    Reuses Shell's drain/send/run/wait_for verbatim — they only ever touch
    ``self._proc`` — and replaces the AWS-specific setup and teardown.
    """

    def __init__(
        self,
        env: Environment,
        key_path: Path,
        forward_port: int | None = None,
        proxy_command: str | None = None,
    ) -> None:
        cmd = [
            "ssh", "-tt",
            "-i", str(key_path),
            "-p", str(env.ssh_port),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=30",
            # Cloud Shell reclaims idle sessions; keep the channel warm.
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=6",
        ]
        if proxy_command:
            cmd += ["-o", f"ProxyCommand={proxy_command}"]
        if forward_port:
            # Carries OpenVPN/TCP when the UDP hole punch is unavailable.
            cmd += ["-L", f"{forward_port}:127.0.0.1:{forward_port}"]
        cmd.append(f"{env.ssh_username}@{env.ssh_host}")

        log.debug(f"SSH: {' '.join(cmd)}")
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        fd = self._proc.stdout.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        time.sleep(SHELL_STARTUP_DELAY_S)

        if self._proc.poll() is not None:
            raise GcpError(
                f"SSH to Cloud Shell exited immediately (code {self._proc.returncode}).\n"
                f"  Port {env.ssh_port} to {env.ssh_host} may be blocked by your network.\n"
                f"  Behind a corporate firewall, use --transport ssh with\n"
                f"  --ssh-proxy-command to tunnel through your proxy."
            )
        self.drain()

    def cleanup(self) -> None:
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()


def start_heartbeat(shell: Shell) -> None:
    """Keep the Cloud Shell session from being reclaimed as idle.

    There is no heartbeat API as on AWS. In punch mode the tunnel traffic
    bypasses SSH entirely, so the session would otherwise look idle: send a
    newline down the channel instead. The agent does not read stdin, so this is
    inert on the remote side.
    """
    def loop():
        while True:
            time.sleep(SSH_KEEPALIVE_INTERVAL_S)
            try:
                shell.send("")
            except Exception as e:
                log.debug(f"Keepalive failed: {e}")
                return
    threading.Thread(target=loop, daemon=True, name="gcp-keepalive").start()
