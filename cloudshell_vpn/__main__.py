"""CLI entry point for CloudShell VPN (OpenVPN).

Usage:
    python -m cloudshell_vpn                  # Interactive region picker + TUI
    python -m cloudshell_vpn --region eu-west-1
"""

from __future__ import annotations

import base64
import gzip
import io
import logging
import os
import re
import shlex
import shutil
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# Cloudflare: shorter retention than Google's resolvers, and no ad profile.
# Override with --dns.
DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def list_regions() -> list[str]:
    """List AWS regions where CloudShell is available and enabled for the account."""
    from .common import create_ec2_client
    
    # CloudShell supported regions (from AWS docs)
    # https://docs.aws.amazon.com/general/latest/gr/cloudshell.html
    CLOUDSHELL_REGIONS = {
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "af-south-1",
        "ap-east-1", "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2",
        "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7",
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ca-central-1", "ca-west-1",
        "eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3",
        "eu-south-1", "eu-south-2", "eu-north-1",
        "il-central-1",
        "me-south-1", "me-central-1",
        "sa-east-1",
    }
    
    # Get regions enabled for this account
    ec2 = create_ec2_client("us-east-1")
    resp = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    account_regions = {r["RegionName"] for r in resp["Regions"]}
    
    # Return intersection: CloudShell supported AND enabled for account
    return sorted(CLOUDSHELL_REGIONS & account_regions)


def pick_region() -> str:
    from .tui import select_region
    
    print("\nFetching enabled regions...", flush=True)
    regions = list_regions()
    
    selected = select_region(regions)
    if selected is None:
        print("Cancelled.")
        sys.exit(0)
    return selected


def upload_agent(shell) -> None:
    """Upload the OpenVPN agent script to CloudShell (gzip + base64)."""
    agent_path = Path(__file__).resolve().parent / "agent_openvpn.py"
    raw = agent_path.read_bytes()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as gz:
        gz.write(raw)
    b64 = base64.b64encode(buf.getvalue()).decode()
    log.info(f"Uploading OpenVPN agent ({len(raw)}B -> {len(b64)}B compressed)...")
    shell.run(f"echo '{b64}' | base64 -d | gunzip > /tmp/vpn_agent_openvpn.py", timeout=5)


OVPN_CONNECT_BIN = Path(
    "/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect"
)
OVPN_PROFILE_NAME = "cloudshell-vpn"


def _reveal(conf_path: Path) -> None:
    """Hand the profile to the desktop, if there is one. 'open' is macOS-only."""
    if sys.platform != "darwin":
        return
    import subprocess

    subprocess.Popen(["open", str(conf_path)])


def _check_openvpn_connect() -> None:
    """Warn early on macOS if the client we auto-import into is missing."""
    if sys.platform == "darwin" and not OVPN_CONNECT_BIN.parent.parent.parent.exists():
        print("WARNING: OpenVPN Connect not found at /Applications/OpenVPN Connect/")
        print("Install from: https://openvpn.net/client/")
        print("The VPN config will be saved to ~/.cloudshell-vpn/cloudshell-vpn.ovpn "
              "for manual import.\n")


def import_into_openvpn_connect(conf_path: Path, log_msg=log.info) -> None:
    """Import the profile and relaunch OpenVPN Connect so it auto-connects.

    macOS only — elsewhere the user imports the profile into their own client.
    """
    import subprocess

    if not OVPN_CONNECT_BIN.exists():
        # log_msg, not log: the TUI disables logging, and this is the one
        # message the user must see to finish connecting by hand.
        log_msg(
            "OpenVPN Connect not found! Install it from https://openvpn.net/client/ "
            f"or import this profile into your own client: {conf_path}"
        )
        _reveal(conf_path)
        return

    subprocess.run(
        [str(OVPN_CONNECT_BIN), f"--remove-profile={OVPN_PROFILE_NAME}"],
        capture_output=True, timeout=10,
    )
    result = subprocess.run(
        [str(OVPN_CONNECT_BIN), f"--import-profile={conf_path}", f"--name={OVPN_PROFILE_NAME}"],
        capture_output=True, text=True, timeout=10,
    )
    if "success" not in result.stdout.lower():
        log_msg(f"Auto-import failed, opening the config file instead: {result.stdout}")
        _reveal(conf_path)
        return

    log_msg(f"Profile '{OVPN_PROFILE_NAME}' imported into OpenVPN Connect")
    # Quit and relaunch to trigger auto-connect (connect-on-launch setting)
    subprocess.run([str(OVPN_CONNECT_BIN), "--quit"], capture_output=True, timeout=3)
    time.sleep(0.5)
    # Launch minimized (no UI window) — connect-on-launch will auto-connect
    subprocess.Popen(
        [str(OVPN_CONNECT_BIN), "--minimize"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def teardown_openvpn_connect() -> None:
    """Disconnect and drop the profile. Best effort — runs in a finally block."""
    if not OVPN_CONNECT_BIN.exists():
        return
    import subprocess

    subprocess.run([str(OVPN_CONNECT_BIN), "--quit"], capture_output=True, timeout=3)
    subprocess.run(
        [str(OVPN_CONNECT_BIN), f"--remove-profile={OVPN_PROFILE_NAME}"],
        capture_output=True, timeout=3,
    )


def generate_ovpn_conf(
    pki: dict[str, str],
    local_port: int,
    exclude_ips: list[str],
    dns_servers: list[str] | None = None,
    proto: str = "udp",
) -> str:
    """Generate OpenVPN .ovpn config with inline certs and net_gateway routes.

    The key feature: routes for exclude_ips use 'net_gateway' which tells
    OpenVPN to route them via the original gateway BEFORE the VPN was connected.
    This is managed entirely by OpenVPN Connect — no external sudo required!
    """
    from .common import OVPN_PORT

    if proto not in ("udp", "tcp"):
        raise ValueError(f"invalid proto: {proto!r}")
    # 'tcp' in a client profile means tcp-client; spell it out so the server's
    # tcp-server has an unambiguous counterpart.
    client_proto = "tcp-client" if proto == "tcp" else "udp"

    # Build route exclusions using net_gateway
    route_lines = []
    for ip in exclude_ips:
        route_lines.append(f"route {ip} 255.255.255.255 net_gateway")
    routes = "\n".join(route_lines)

    dns_lines = "\n".join(
        f"dhcp-option DNS {ip}" for ip in (dns_servers or DEFAULT_DNS)
    )

    return f"""# CloudShell VPN - OpenVPN Config
# Auto-imported into OpenVPN Connect

client
dev tun
proto {client_proto}
remote 127.0.0.1 {local_port}
nobind

# Note: resolv-retry / persist-key / persist-tun / mute / keepalive / ping* are
# deliberately absent. OpenVPN Connect reports them as "unsupported options" —
# it manages timers and interface persistence internally, and the server pushes
# the keepalive timers anyway.

# Crypto
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
remote-cert-tls server

# Route ALL traffic through VPN (full tunnel)
redirect-gateway def1

# Block IPv6 to prevent leaks (VPN only supports IPv4)
# This tells OpenVPN Connect to reject all IPv6 traffic while connected
block-ipv6

# CRITICAL: These routes bypass the VPN for relay/AWS traffic.
# net_gateway = the gateway that existed BEFORE VPN connected.
# OpenVPN handles this automatically — no sudo required!
{routes}

# DNS
{dns_lines}

# Performance
sndbuf 524288
rcvbuf 524288

# Keepalive and dead-tunnel detection come from the server: its
# 'keepalive 10 30' expands to push "ping 10" + push "ping-restart 30".
# Setting them locally makes OpenVPN Connect flag them as unsupported.

# Verbosity ('mute' omitted — unsupported by OpenVPN Connect)
verb 3

# Inline certificates and keys (ephemeral, valid 1 day)
<ca>
{pki["ca_cert"]}</ca>

<cert>
{pki["client_cert"]}</cert>

<key>
{pki["client_key"]}</key>

<tls-auth>
{pki["ta_key"]}
</tls-auth>
key-direction 1
"""


def run_openvpn_with_callbacks(
    region: str,
    log_callback,
    status_callback,
    stop_event,
    dns_servers: list[str] | None = None,
) -> None:
    """Run OpenVPN with TUI callbacks for status updates."""
    from .common import (
        AGENT_UDP_PORT,
        MAX_UDP_PAYLOAD,
        OVPN_PORT,
        AgentError,
        Shell,
        create_cs_client,
        generate_openvpn_pki,
        get_or_create_env,
        stun_discover,
        validate_public_ipv4,
        validate_port,
        wait_for_running,
    )
    from .tunnel_openvpn import hole_punch, start_heartbeat

    def log_msg(msg: str):
        log_callback(msg)

    if not shutil.which("session-manager-plugin"):
        log_msg("[red]ERROR: session-manager-plugin not found[/]")
        return

    log_msg("Generating OpenVPN PKI (ephemeral)...")
    pki = generate_openvpn_pki()

    log_msg(f"Region: {region}")
    cs = create_cs_client(region)
    env_id = get_or_create_env(cs)

    log_msg("Waiting for CloudShell environment...")
    wait_for_running(cs, env_id)

    shell = Shell(cs, env_id, region)
    udp = None
    ovpn_sock = None
    try:
        log_msg("Uploading OpenVPN agent to CloudShell...")
        upload_agent(shell)

        # STUN discovery
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("", 0))

        log_msg("STUN: discovering laptop endpoint...")
        local_ip, local_port = stun_discover(udp)
        log_msg(f"Laptop public: {local_ip}:{local_port}")

        # NAT keepalive
        stop_keepalive = threading.Event()
        def nat_keepalive():
            while not stop_keepalive.is_set():
                try:
                    txn = os.urandom(12)
                    udp.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn, ("stun.l.google.com", 19302))
                except OSError:
                    pass
                stop_keepalive.wait(2)
        threading.Thread(target=nat_keepalive, daemon=True).start()

        shell.run("pkill -f vpn_agent_openvpn.py 2>/dev/null; sudo pkill openvpn 2>/dev/null", timeout=5)
        time.sleep(2)
        shell.drain()

        ca_b64 = base64.b64encode(pki["ca_cert"].encode()).decode()
        server_cert_b64 = base64.b64encode(pki["server_cert"].encode()).decode()
        server_key_b64 = base64.b64encode(pki["server_key"].encode()).decode()
        ta_key_b64 = base64.b64encode(pki["ta_key"].encode()).decode()

        log_msg("Starting OpenVPN agent...")
        # local_ip/local_port are STUN-derived and already validated, but this
        # command runs under sudo — quote every interpolated value regardless.
        shell.send(
            f"export TA_KEY_B64={shlex.quote(ta_key_b64)} && "
            f"export VPN_DNS={shlex.quote(','.join(dns_servers or DEFAULT_DNS))} && "
            f"sudo -E python3 /tmp/vpn_agent_openvpn.py {AGENT_UDP_PORT} "
            f"{shlex.quote(f'{local_ip}:{local_port}')} "
            f"{shlex.quote(ca_b64)} {shlex.quote(server_cert_b64)} "
            f"{shlex.quote(server_key_b64)} 2>&1"
        )

        log_msg("Waiting for agent (timeout: 120s)...")
        found, output = shell.wait_for("AGENT_READY:", timeout=120)
        if not found:
            if "SETUP_ERROR" in output:
                raise AgentError("OpenVPN setup failed in CloudShell")
            raise AgentError("Agent failed to start (timeout after 120s)")

        match = re.search(r"AGENT_READY:(\S+)", output)
        if not match:
            raise AgentError("Cannot parse agent endpoint")

        agent_ip, agent_port_str = match.group(1).rsplit(":", 1)
        # This value reaches the .ovpn file as a 'route' directive, read by a
        # privileged binary — validate before trusting the agent's stdout.
        agent_ip = validate_public_ipv4(agent_ip, "Agent")
        agent_port = validate_port(int(agent_port_str), "Agent")
        remote_addr = (agent_ip, agent_port)
        log_msg(f"Agent public: {agent_ip}:{agent_port}")

        stop_keepalive.set()
        time.sleep(0.5)

        udp.setblocking(False)
        while True:
            try:
                udp.recvfrom(1024)
            except (BlockingIOError, OSError):
                break

        log_msg("Hole punching (timeout: 8s)...")
        actual_addr, punch_received = hole_punch(udp, remote_addr)
        if not punch_received:
            log_msg("[yellow]Warning: NAT punch may have failed[/]")
        udp.connect(actual_addr)
        log_msg(f"Connected to {actual_addr}")

        exclude_ips = [agent_ip]
        start_heartbeat(cs, env_id)

        conf = generate_ovpn_conf(pki, OVPN_PORT, exclude_ips, dns_servers)
        from .common import DATA_DIR
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)  # mkdir ignores mode when the dir exists
        conf_path = DATA_DIR / "cloudshell-vpn.ovpn"
        conf_path.write_text(conf)
        os.chmod(conf_path, 0o600)  # contains the client private key

        # Bind the relay BEFORE launching the client. OpenVPN Connect starts
        # sending to 127.0.0.1:1194 immediately; if nothing is listening yet it
        # gets ICMP port-unreachable and gives up before we ever bind.
        ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ovpn_sock.bind(("127.0.0.1", OVPN_PORT))

        # Auto-import into OpenVPN Connect
        import_into_openvpn_connect(conf_path, log_msg)

        # Signal connected
        status_callback(connected=True, bytes_in=0, bytes_out=0, latency_ms=0)
        log_msg("[green]VPN Connected![/]")

        # UDP relay loop with stats - use select() for efficiency
        # (ovpn_sock was bound above, before the client was launched)
        import select

        bytes_in = 0
        bytes_out = 0
        ovpn_client = None
        relay_started = time.time()
        last_stats = time.time()
        last_remote_data = time.time()
        last_ping = time.time()
        ping_sent_time = None
        latency_ms = 0
        DISCONNECT_TIMEOUT = 120
        CLIENT_CONNECT_TIMEOUT = 60  # OpenVPN Connect never reached the relay
        PING_INTERVAL = 10  # Ping every 10 seconds

        while not stop_event.is_set():
            readable, _, _ = select.select([udp, ovpn_sock], [], [], 0.1)
            
            for sock in readable:
                if sock is ovpn_sock:
                    data, addr = ovpn_sock.recvfrom(65535)
                    if data:
                        ovpn_client = addr
                        udp.send(data)
                        bytes_out += len(data)
                elif sock is udp:
                    data = udp.recv(65535)
                    if data:
                        # Check if it's a ping response
                        if data.startswith(b"PONG:") and ping_sent_time:
                            latency_ms = int((time.time() - ping_sent_time) * 1000)
                            ping_sent_time = None
                        elif ovpn_client:
                            ovpn_sock.sendto(data, ovpn_client)
                            bytes_in += len(data)
                        last_remote_data = time.time()

            now = time.time()
            
            # Send ping every PING_INTERVAL seconds
            if now - last_ping >= PING_INTERVAL:
                try:
                    ping_sent_time = time.time()
                    udp.send(b"PING:" + str(ping_sent_time).encode())
                except Exception:
                    pass
                last_ping = now
            
            # Update stats every 5 seconds
            if now - last_stats >= 5:
                status_callback(connected=True, bytes_in=bytes_in, bytes_out=bytes_out, latency_ms=latency_ms)
                last_stats = now
            
            # Dead-tunnel detection. Waiting for OpenVPN Connect to reach the
            # local relay is a different failure from losing the agent — the
            # old single condition never fired in the first case.
            if ovpn_client is None:
                if (now - relay_started) > CLIENT_CONNECT_TIMEOUT:
                    log_msg("[yellow]OpenVPN Connect never reached the relay, retrying...[/]")
                    raise ConnectionError(
                        f"OpenVPN Connect never connected to the local relay "
                        f"(waited {CLIENT_CONNECT_TIMEOUT}s on 127.0.0.1:{OVPN_PORT})"
                    )
            elif (now - last_remote_data) > DISCONNECT_TIMEOUT:
                log_msg("[yellow]Connection appears dead, reconnecting...[/]")
                raise ConnectionError("No data from CloudShell for 2 minutes")

    except ConnectionError:
        # Let the TUI retry loop handle it — the bare 'except Exception' below
        # used to swallow this, making the retry mechanism unreachable.
        raise
    except Exception as e:
        log_msg(f"[red]Error: {e}[/]")
    finally:
        # Cleanup sockets (may be None if we failed before creating them)
        for sock in (udp, ovpn_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        # Close the CloudShell session properly — killing the local plugin
        # alone leaves an orphan session burning the 200h/region quota.
        try:
            shell.cleanup()
        except Exception:
            pass

        # Cleanup OpenVPN Connect
        try:
            teardown_openvpn_connect()
        except Exception:
            pass

        log_msg("Disconnected.")


def run_openvpn(
    region: str,
    dns_servers: list[str] | None = None,
    extra_excludes: list[str] | None = None,
) -> None:
    """Run VPN using OpenVPN.

    Route exclusions are handled in the .ovpn config via
    'route <ip> ... net_gateway', so no sudo for route management is needed.
    OpenVPN Connect handles everything.
    """
    from .common import (
        AGENT_UDP_PORT,
        OVPN_PORT,
        AgentError,
        Shell,
        create_cs_client,
        generate_openvpn_pki,
        get_or_create_env,
        stun_discover,
        validate_public_ipv4,
        validate_port,
        wait_for_running,
    )
    from .tunnel_openvpn import hole_punch, udp_relay, start_heartbeat

    if not shutil.which("session-manager-plugin"):
        print("ERROR: session-manager-plugin not found. Install from:")
        print("  https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html")
        sys.exit(1)

    # Generate ephemeral PKI (CA + server + client certs)
    log.info("Generating OpenVPN PKI (ephemeral)...")
    pki = generate_openvpn_pki()

    log.info(f"Region: {region}")
    cs = create_cs_client(region)
    env_id = get_or_create_env(cs)
    wait_for_running(cs, env_id)

    shell = Shell(cs, env_id, region)
    udp = None
    ovpn_sock = None
    try:
        log.info("Uploading OpenVPN agent to CloudShell...")
        upload_agent(shell)

        # STUN discovery (laptop side)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("", 0))

        log.info("STUN: discovering laptop endpoint...")
        local_ip, local_port = stun_discover(udp)
        log.info(f"Laptop public: {local_ip}:{local_port}")

        # NAT keepalive while agent starts
        stop_keepalive = threading.Event()

        def nat_keepalive():
            while not stop_keepalive.is_set():
                try:
                    txn = os.urandom(12)
                    udp.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn, ("stun.l.google.com", 19302))
                except OSError:
                    pass
                stop_keepalive.wait(2)

        threading.Thread(target=nat_keepalive, daemon=True).start()

        # Clean up any previous sessions
        shell.run("pkill -f vpn_agent_openvpn.py 2>/dev/null; sudo pkill openvpn 2>/dev/null", timeout=5)
        time.sleep(2)
        shell.drain()

        # Encode PKI for shell-safe transport (base64)
        ca_b64 = base64.b64encode(pki["ca_cert"].encode()).decode()
        server_cert_b64 = base64.b64encode(pki["server_cert"].encode()).decode()
        server_key_b64 = base64.b64encode(pki["server_key"].encode()).decode()
        ta_key_b64 = base64.b64encode(pki["ta_key"].encode()).decode()

        log.info("Starting OpenVPN agent...")
        # TA key is too long for args, pass via environment variable.
        # local_ip/local_port are STUN-derived and already validated, but this
        # command runs under sudo — quote every interpolated value regardless.
        shell.send(
            f"export TA_KEY_B64={shlex.quote(ta_key_b64)} && "
            f"export VPN_DNS={shlex.quote(','.join(dns_servers or DEFAULT_DNS))} && "
            f"sudo -E python3 /tmp/vpn_agent_openvpn.py {AGENT_UDP_PORT} "
            f"{shlex.quote(f'{local_ip}:{local_port}')} "
            f"{shlex.quote(ca_b64)} {shlex.quote(server_cert_b64)} "
            f"{shlex.quote(server_key_b64)} 2>&1"
        )

        found, output = shell.wait_for("AGENT_READY:", timeout=120)
        if not found:
            log.error(f"Agent output:\n{output}")
            if "SETUP_ERROR" in output:
                raise AgentError(f"OpenVPN setup failed in CloudShell:\n{output}")
            raise AgentError(f"Agent failed:\n{output}")
        log.info(f"Agent setup output:\n{output}")

        match = re.search(r"AGENT_READY:(\S+)", output)
        if not match:
            raise AgentError(f"Cannot parse agent endpoint:\n{output}")

        agent_ip, agent_port_str = match.group(1).rsplit(":", 1)
        # This value reaches the .ovpn file as a 'route' directive, read by a
        # privileged binary — validate before trusting the agent's stdout.
        agent_ip = validate_public_ipv4(agent_ip, "Agent")
        agent_port = validate_port(int(agent_port_str), "Agent")
        remote_addr = (agent_ip, agent_port)
        log.info(f"Agent public: {agent_ip}:{agent_port}")

        # Stop keepalive, start punching
        stop_keepalive.set()
        time.sleep(0.5)

        # Drain STUN responses
        udp.setblocking(False)
        while True:
            try:
                udp.recvfrom(1024)
            except (BlockingIOError, OSError):
                break

        # hole_punch returns (addr, punch_received) — unpack both
        actual_addr, punch_received = hole_punch(udp, remote_addr)
        if not punch_received:
            log.warning("NAT punch may have failed — continuing anyway")

        # Connect the socket (for send/recv API)
        udp.connect(actual_addr)
        log.info(f"Socket connected to {actual_addr} (local: {udp.getsockname()})")

        # Only the agent IP needs to bypass the VPN (for the UDP relay to work)
        exclude_ips = [agent_ip]
        for ip in extra_excludes or []:
            if ip not in exclude_ips:
                exclude_ips.append(ip)
        log.info(f"IPs to exclude from VPN: {exclude_ips}")

        # Start heartbeat BEFORE writing config
        start_heartbeat(cs, env_id)

        # Write OpenVPN config file
        conf = generate_ovpn_conf(pki, OVPN_PORT, exclude_ips, dns_servers)
        from .common import DATA_DIR
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)  # mkdir ignores mode when the dir exists
        conf_path = DATA_DIR / "cloudshell-vpn.ovpn"
        conf_path.write_text(conf)
        os.chmod(conf_path, 0o600)  # contains the client private key
        log.info(f"OpenVPN config written to: {conf_path}")

        # Bind the relay BEFORE launching the client. OpenVPN Connect starts
        # sending to 127.0.0.1:1194 immediately; if nothing is listening yet it
        # gets ICMP port-unreachable and gives up before we ever bind.
        ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ovpn_sock.bind(("127.0.0.1", OVPN_PORT))

        # Try to auto-import into OpenVPN Connect (if installed)
        import_into_openvpn_connect(conf_path)
        log.info(
            f"\n{'=' * 55}\n"
            f"  VPN connecting...\n"
            f"  Press Ctrl+C to disconnect and exit\n"
            f"{'=' * 55}\n"
        )

        # Run UDP relay (blocks) — socket is already connected
        udp_relay(udp, ovpn_sock)

    except KeyboardInterrupt:
        log.info("\nShutting down...")
    except ConnectionError as e:
        # No retry loop in --no-tui mode; exit with a clear reason instead of
        # spinning on a tunnel that no longer carries traffic.
        log.error(f"Connection lost: {e}")
        log.error("Re-run the command to reconnect.")
    finally:
        # Free port 1194 so an immediate re-run can bind it again
        for sock in (udp, ovpn_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        # Close the CloudShell session properly — killing the local plugin
        # alone leaves an orphan session burning the 200h/region quota.
        try:
            shell.cleanup()
        except Exception:
            pass

        # Disconnect and cleanup OpenVPN Connect
        teardown_openvpn_connect()

        log.info("Done.")


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m cloudshell_vpn",
        description="Free VPN via AWS CloudShell or GCP Cloud Shell (OpenVPN)",
    )
    p.add_argument(
        "--provider", choices=("aws", "gcp"), default="aws",
        help="Cloud backend (default: aws)",
    )
    p.add_argument("--region", "-r", help="AWS region (interactive picker if omitted; AWS only)")
    p.add_argument("--profile", "-p", help="AWS profile name (uses default credential chain if omitted)")
    p.add_argument(
        "--transport", choices=("punch", "ssh"), default="punch",
        help="GCP only: 'punch' relays OpenVPN/UDP through a NAT hole (faster); "
             "'ssh' carries OpenVPN/TCP over an SSH forward (works behind "
             "symmetric NAT and corporate proxies)",
    )
    p.add_argument(
        "--ssh-proxy-command",
        help="GCP only: ssh(1) ProxyCommand, e.g. "
             "'nc -X connect -x proxy.corp:3128 %%h %%p'",
    )
    p.add_argument(
        "--exclude-ip", action="append", metavar="IP",
        help="Extra IPv4 address to route outside the tunnel (repeatable). "
             "Needed for a proxy or relay the tunnel itself depends on.",
    )
    p.add_argument(
        "--no-tui", action="store_true",
        help="Disable TUI, use simple log output",
    )
    p.add_argument(
        "--dns",
        help=f"Comma-separated DNS servers pushed to the client "
             f"(default: {','.join(DEFAULT_DNS)})",
    )
    args = p.parse_args()

    # Validate DNS before any AWS call — these end up in the .ovpn file,
    # which is read by a privileged binary.
    dns_servers = None
    if args.dns:
        import ipaddress
        dns_servers = []
        for entry in args.dns.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                dns_servers.append(str(ipaddress.IPv4Address(entry)))
            except ValueError:
                print(f"ERROR: invalid DNS address: {entry!r}", file=sys.stderr)
                sys.exit(1)
        if not dns_servers:
            print("ERROR: --dns was empty", file=sys.stderr)
            sys.exit(1)

    # These become 'route <ip> ... net_gateway' lines in the .ovpn, which a
    # privileged binary reads — validate before anything else touches them.
    extra_excludes = []
    if args.exclude_ip:
        import ipaddress
    for entry in args.exclude_ip or []:
        try:
            extra_excludes.append(str(ipaddress.IPv4Address(entry.strip())))
        except ValueError:
            print(f"ERROR: invalid --exclude-ip address: {entry!r}", file=sys.stderr)
            sys.exit(1)

    if args.provider == "gcp":
        _check_openvpn_connect()
        from .gcp import GcpError, validate_credentials as validate_gcp
        from .gcp_run import run_gcp

        try:
            validate_gcp()
        except GcpError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        if args.region:
            log.warning("--region is ignored on GCP: Google assigns the Cloud Shell region.")
        run_gcp(
            transport=args.transport,
            dns_servers=dns_servers,
            extra_excludes=extra_excludes,
            ssh_proxy_command=args.ssh_proxy_command,
        )
        return

    # Override AWS profile if specified
    if args.profile:
        from . import common
        common.AWS_PROFILE = args.profile

    # Check prerequisites before doing anything
    if not shutil.which("session-manager-plugin"):
        print("ERROR: session-manager-plugin not found.")
        print("Install from: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html")
        sys.exit(1)

    # Validate AWS credentials early
    from .common import validate_credentials, VpnError
    try:
        validate_credentials()
    except VpnError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    
    _check_openvpn_connect()

    if args.region or args.no_tui:
        # Direct region or no-tui flag - use classic mode
        region = args.region or pick_region()
        log.info(f"Selected region: {region}")
        run_openvpn(region, dns_servers, extra_excludes)
    else:
        # Full TUI mode - disable standard logging
        logging.disable(logging.CRITICAL)
        from .tui import run_vpn_tui
        
        print("\nFetching enabled regions...", flush=True)
        regions = list_regions()
        
        def vpn_runner(region, log_callback, status_callback, stop_event):
            run_openvpn_with_callbacks(
                region, log_callback, status_callback, stop_event, dns_servers
            )
        
        run_vpn_tui(regions, vpn_runner)


if __name__ == "__main__":
    main()
