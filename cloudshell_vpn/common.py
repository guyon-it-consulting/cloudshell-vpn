"""Shared utilities for CloudShell VPN."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import socket
import struct
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import boto3
import botocore.session

log = logging.getLogger(__name__)

AGENT_UDP_PORT = 4433
OVPN_PORT = 1194  # OpenVPN listen port on CloudShell side
OVPN_SUBNET = "10.98.0"
OVPN_SERVER_IP = f"{OVPN_SUBNET}.1"
OVPN_CLIENT_IP = f"{OVPN_SUBNET}.2"

DATA_DIR = Path.home() / ".cloudshell-vpn"

STUN_SERVER = ("stun.l.google.com", 19302)
STUN_TIMEOUT_S = 5
HEARTBEAT_INTERVAL_S = 300
SHELL_STARTUP_DELAY_S = 3
AWS_PROFILE = os.environ.get("AWS_PROFILE")

_ANSI_RE = re.compile(r"\x1b[^a-zA-Z]*[a-zA-Z]|\x0f|\r")
_PKG_DIR = Path(__file__).resolve().parent
_MODEL_DIR_DEV = _PKG_DIR.parent / "my-additional-models"
_MODEL_DIR_INSTALLED = _PKG_DIR / "my-additional-models"
_MODEL_DIR = str(_MODEL_DIR_DEV if _MODEL_DIR_DEV.is_dir() else _MODEL_DIR_INSTALLED)


class VpnError(Exception):
    pass


class StunError(VpnError):
    pass


class AgentError(VpnError):
    pass


class ShellError(VpnError):
    pass


def generate_openvpn_pki() -> dict[str, str]:
    """Generate ephemeral PKI for OpenVPN (CA + server + client certs).
    
    Returns a dict with keys:
        ca_cert, ca_key, server_cert, server_key, client_cert, client_key, ta_key
    All values are PEM-encoded strings.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import os
    
    def gen_key() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    def key_to_pem(key: rsa.RSAPrivateKey) -> str:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()
    
    def cert_to_pem(cert: x509.Certificate) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode()
    
    now = datetime.datetime.now(datetime.timezone.utc)
    validity = datetime.timedelta(days=1)  # Ephemeral, 1 day is plenty
    
    # CA
    ca_key = gen_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CloudShell-VPN-CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    
    # Server cert
    server_key = gen_key()
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CloudShell-VPN-Server")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            key_cert_sign=False, crl_sign=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    
    # Client cert
    client_key = gen_key()
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CloudShell-VPN-Client")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False,
            key_cert_sign=False, crl_sign=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    
    # TLS-Auth key (random 256 bytes, hex encoded like OpenVPN expects)
    ta_key_bytes = os.urandom(256)
    ta_key_hex = "\n".join(
        ta_key_bytes[i:i+16].hex() for i in range(0, 256, 16)
    )
    ta_key = f"""-----BEGIN OpenVPN Static key V1-----
{ta_key_hex}
-----END OpenVPN Static key V1-----"""
    
    return {
        "ca_cert": cert_to_pem(ca_cert),
        "ca_key": key_to_pem(ca_key),
        "server_cert": cert_to_pem(server_cert),
        "server_key": key_to_pem(server_key),
        "client_cert": cert_to_pem(client_cert),
        "client_key": key_to_pem(client_key),
        "ta_key": ta_key,
    }


def validate_credentials() -> None:
    """Validate AWS credentials early. Raises VpnError with actionable message."""
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        ProfileNotFound,
        TokenRetrievalError,
    )

    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
        sts = session.client("sts")
        sts.get_caller_identity()
    except ProfileNotFound:
        profile = AWS_PROFILE or "default"
        raise VpnError(
            f"AWS profile '{profile}' not found.\n"
            f"  Available profiles: check ~/.aws/credentials and ~/.aws/config\n"
            f"  Use --profile <name> or set AWS_PROFILE env var."
        )
    except NoCredentialsError:
        raise VpnError(
            "No AWS credentials found.\n"
            "  Configure credentials with: aws configure\n"
            "  Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars.\n"
            "  Or specify a profile with --profile <name>."
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("ExpiredToken", "ExpiredTokenException"):
            raise VpnError(
                "AWS credentials have expired.\n"
                "  Refresh your session: aws sso login --profile <name>\n"
                "  Or regenerate temporary credentials."
            )
        elif code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
            raise VpnError(
                "AWS credentials are invalid.\n"
                "  Check your access key and secret in ~/.aws/credentials\n"
                "  Or refresh with: aws configure"
            )
        elif code == "AccessDenied":
            raise VpnError(
                "AWS credentials lack permission to call sts:GetCallerIdentity.\n"
                "  Verify the IAM user/role has basic STS access."
            )
        else:
            raise VpnError(f"AWS credential check failed: {e}")
    except TokenRetrievalError as e:
        raise VpnError(
            f"Failed to retrieve AWS SSO/session token.\n"
            f"  Try: aws sso login --profile {AWS_PROFILE or 'default'}\n"
            f"  Error: {e}"
        )
    except Exception as e:
        raise VpnError(f"AWS credential check failed: {e}")


def create_cs_client(region: str) -> Any:
    """Create a boto3 CloudShell client with custom service model."""
    bc = botocore.session.get_session()
    bc.get_component("data_loader").search_paths.insert(0, _MODEL_DIR)
    session = boto3.Session(botocore_session=bc, profile_name=AWS_PROFILE)
    return session.client("cloudshell", region_name=region)


def create_ec2_client(region: str) -> Any:
    """Create a boto3 EC2 client for region listing."""
    return boto3.Session(profile_name=AWS_PROFILE).client("ec2", region_name=region)


def get_or_create_env(client: Any, environment_id: str | None = None) -> str:
    """Get an existing CloudShell environment or create a new one."""
    if environment_id:
        return environment_id
    envs = client.describe_environments()["Environments"]
    if envs:
        return envs[0]["EnvironmentId"]
    return client.create_environment()["EnvironmentId"]


def wait_for_running(client: Any, env_id: str, timeout: int = 300) -> None:
    """Poll environment status until RUNNING."""
    status = client.get_environment_status(EnvironmentId=env_id)["Status"]
    if status == "SUSPENDED":
        log.info("Starting environment...")
        client.start_environment(EnvironmentId=env_id)
    deadline = time.time() + timeout
    while status != "RUNNING":
        if time.time() > deadline:
            raise TimeoutError(f"Environment stuck in {status}")
        log.info(f"Status: {status}...")
        time.sleep(3)
        status = client.get_environment_status(EnvironmentId=env_id)["Status"]
    log.info("Environment RUNNING")


def stun_discover(sock: socket.socket) -> tuple[str, int]:
    """Discover public IP:port via STUN Binding Request."""
    txn = os.urandom(12)
    sock.settimeout(STUN_TIMEOUT_S)
    try:
        sock.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn, STUN_SERVER)
        data = sock.recv(1024)
    except (OSError, socket.timeout) as exc:
        raise StunError(f"STUN failed: {exc}") from exc
    i = 20
    while i < len(data):
        atype, alen = struct.unpack("!HH", data[i : i + 4])
        if atype == 0x0020:
            port = struct.unpack("!H", data[i + 6 : i + 8])[0] ^ 0x2112
            raw_ip = struct.unpack("!I", data[i + 8 : i + 12])[0] ^ 0x2112A442
            ip = f"{(raw_ip >> 24) & 0xFF}.{(raw_ip >> 16) & 0xFF}.{(raw_ip >> 8) & 0xFF}.{raw_ip & 0xFF}"
            return ip, port
        i += 4 + alen
    raise StunError("No XOR-MAPPED-ADDRESS in STUN response")


class Shell:
    """SSM session-manager-plugin wrapper for CloudShell."""

    def __init__(self, cs_client: Any, env_id: str, region: str) -> None:
        sess = cs_client.create_session(
            EnvironmentId=env_id, SessionType="TMUX",
            TabId=str(uuid.uuid4()), QCliDisabled=True,
        )
        self._sid = sess["SessionId"]
        self._env_id = env_id
        self._cs = cs_client
        payload = json.dumps({k: sess[k] for k in ("SessionId", "TokenValue", "StreamUrl")})
        self._proc = subprocess.Popen(
            ["session-manager-plugin", payload, region, "StartSession"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        fd = self._proc.stdout.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        time.sleep(SHELL_STARTUP_DELAY_S)
        self.drain()

    def drain(self) -> None:
        while True:
            try:
                if not os.read(self._proc.stdout.fileno(), 65536):
                    break
            except BlockingIOError:
                break

    def send(self, cmd: str) -> None:
        self._proc.stdin.write(f"{cmd}\r\n".encode())
        self._proc.stdin.flush()

    def run(self, cmd: str, timeout: float = 10) -> str:
        self.drain()
        self.send(cmd)
        time.sleep(min(timeout, 2))
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = os.read(self._proc.stdout.fileno(), 65536)
                if chunk:
                    buf += chunk
            except BlockingIOError:
                pass
            time.sleep(0.1)
        return _ANSI_RE.sub("", buf.decode(errors="replace"))

    def wait_for(self, marker: str, timeout: float = 60) -> tuple[bool, str]:
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = os.read(self._proc.stdout.fileno(), 65536)
                if chunk:
                    buf += chunk
                    text = buf.decode(errors="replace")
                    if marker in text:
                        return True, _ANSI_RE.sub("", text)
            except BlockingIOError:
                pass
            time.sleep(0.1)
        return False, _ANSI_RE.sub("", buf.decode(errors="replace"))

    def cleanup(self) -> None:
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        try:
            self._cs.delete_session(EnvironmentId=self._env_id, SessionId=self._sid)
        except Exception:
            pass
