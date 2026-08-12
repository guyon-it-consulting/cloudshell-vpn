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


def generate_ovpn_conf(
    pki: dict[str, str],
    local_port: int,
    exclude_ips: list[str],
) -> str:
    """Generate OpenVPN .ovpn config with inline certs and net_gateway routes.

    The key feature: routes for exclude_ips use 'net_gateway' which tells
    OpenVPN to route them via the original gateway BEFORE the VPN was connected.
    This is managed entirely by OpenVPN Connect — no external sudo required!
    """
    from .common import OVPN_PORT

    # Build route exclusions using net_gateway
    route_lines = []
    for ip in exclude_ips:
        route_lines.append(f"route {ip} 255.255.255.255 net_gateway")
    routes = "\n".join(route_lines)

    return f"""# CloudShell VPN - OpenVPN Config
# Auto-imported into OpenVPN Connect

client
dev tun
proto udp
remote 127.0.0.1 {local_port}
resolv-retry infinite
nobind
persist-key
persist-tun

# Crypto
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
remote-cert-tls server

# Route ALL traffic through VPN (full tunnel)
redirect-gateway def1

# CRITICAL: These routes bypass the VPN for relay/AWS traffic.
# net_gateway = the gateway that existed BEFORE VPN connected.
# OpenVPN handles this automatically — no sudo required!
{routes}

# DNS
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

# Performance
sndbuf 524288
rcvbuf 524288

# Keepalive
keepalive 10 60

# Verbosity
verb 3
mute 10

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
) -> None:
    """Run OpenVPN with TUI callbacks for status updates."""
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

        conf = generate_ovpn_conf(pki, OVPN_PORT, exclude_ips)
        from .common import DATA_DIR
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        conf_path = DATA_DIR / "cloudshell-vpn.ovpn"
        conf_path.write_text(conf)

        # Bind the relay BEFORE launching the client. OpenVPN Connect starts
        # sending to 127.0.0.1:1194 immediately; if nothing is listening yet it
        # gets ICMP port-unreachable and gives up before we ever bind.
        ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ovpn_sock.bind(("127.0.0.1", OVPN_PORT))

        # Auto-import into OpenVPN Connect
        ovpn_connect_bin = Path("/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect")
        if ovpn_connect_bin.exists():
            import subprocess
            subprocess.run([str(ovpn_connect_bin), "--remove-profile=cloudshell-vpn"], capture_output=True, timeout=10)
            result = subprocess.run(
                [str(ovpn_connect_bin), f"--import-profile={conf_path}", "--name=cloudshell-vpn"],
                capture_output=True, text=True, timeout=10,
            )
            if "success" in result.stdout.lower():
                log_msg("Profile imported into OpenVPN Connect")
                subprocess.run([str(ovpn_connect_bin), "--quit"], capture_output=True, timeout=3)
                time.sleep(0.5)
                subprocess.Popen([str(ovpn_connect_bin), "--minimize"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                log_msg(f"[yellow]Auto-import failed, opening config file...[/]")
                subprocess.Popen(["open", str(conf_path)])
        else:
            log_msg("[yellow]OpenVPN Connect not found, opening config file...[/]")
            import subprocess
            subprocess.Popen(["open", str(conf_path)])

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
        # Cleanup sockets
        try:
            udp.close()
        except Exception:
            pass
        try:
            ovpn_sock.close()
        except Exception:
            pass
        
        # Kill CloudShell session
        try:
            shell._proc.kill()
        except Exception:
            pass
        
        # Cleanup OpenVPN Connect
        ovpn_connect_bin = Path("/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect")
        if ovpn_connect_bin.exists():
            import subprocess
            try:
                subprocess.run([str(ovpn_connect_bin), "--quit"], capture_output=True, timeout=3)
                subprocess.run([str(ovpn_connect_bin), "--remove-profile=cloudshell-vpn"], capture_output=True, timeout=3)
            except Exception:
                pass
        
        log_msg("Disconnected.")


def run_openvpn(region: str) -> None:
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
        log.info(f"IPs to exclude from VPN: {exclude_ips}")

        # Start heartbeat BEFORE writing config
        start_heartbeat(cs, env_id)

        # Write OpenVPN config file
        conf = generate_ovpn_conf(pki, OVPN_PORT, exclude_ips)
        from .common import DATA_DIR
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        conf_path = DATA_DIR / "cloudshell-vpn.ovpn"
        conf_path.write_text(conf)
        log.info(f"OpenVPN config written to: {conf_path}")

        # Bind the relay BEFORE launching the client. OpenVPN Connect starts
        # sending to 127.0.0.1:1194 immediately; if nothing is listening yet it
        # gets ICMP port-unreachable and gives up before we ever bind.
        ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ovpn_sock.bind(("127.0.0.1", OVPN_PORT))

        # Try to auto-import into OpenVPN Connect (if installed)
        ovpn_connect_bin = Path("/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect")
        if ovpn_connect_bin.exists():
            import subprocess
            # Remove old profile silently
            subprocess.run(
                [str(ovpn_connect_bin), "--remove-profile=cloudshell-vpn"],
                capture_output=True, timeout=10,
            )
            # Import new profile silently
            result = subprocess.run(
                [str(ovpn_connect_bin), f"--import-profile={conf_path}", "--name=cloudshell-vpn"],
                capture_output=True, text=True, timeout=10,
            )
            if "success" in result.stdout.lower():
                log.info("Profile 'cloudshell-vpn' imported into OpenVPN Connect")
                # Quit and relaunch to trigger auto-connect (connect-on-launch setting)
                subprocess.run([str(ovpn_connect_bin), "--quit"], capture_output=True, timeout=3)
                time.sleep(0.5)
                # Launch minimized (no UI window) - connect-on-launch will auto-connect
                subprocess.Popen(
                    [str(ovpn_connect_bin), "--minimize"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                log.info(
                    f"\n{'=' * 55}\n"
                    f"  VPN connecting...\n"
                    f"  Press Ctrl+C to disconnect and exit\n"
                    f"{'=' * 55}\n"
                )
            else:
                log.warning(f"Auto-import failed: {result.stdout}")
                subprocess.Popen(["open", str(conf_path)])
        else:
            # OpenVPN Connect not found
            log.error(
                "OpenVPN Connect not found!\n"
                "Install it from: https://openvpn.net/client/\n"
                f"Or manually import: {conf_path}"
            )
            # Try to open the file anyway (might work with another app)
            import subprocess
            subprocess.Popen(["open", str(conf_path)])

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
        # Kill the session-manager-plugin process
        try:
            shell._proc.kill()
        except Exception:
            pass
        
        # Disconnect and cleanup OpenVPN Connect
        ovpn_connect_bin = Path("/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect")
        if ovpn_connect_bin.exists():
            import subprocess
            # Quit the app (disconnects VPN)
            subprocess.run(
                [str(ovpn_connect_bin), "--quit"],
                capture_output=True, timeout=3,
            )
            # Remove the profile
            subprocess.run(
                [str(ovpn_connect_bin), "--remove-profile=cloudshell-vpn"],
                capture_output=True, timeout=3,
            )
        
        log.info("Done.")


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m cloudshell_vpn",
        description="Free VPN via AWS CloudShell + NAT hole punching (OpenVPN)",
    )
    p.add_argument("--region", "-r", help="AWS region (interactive picker if omitted)")
    p.add_argument("--profile", "-p", help="AWS profile name (uses default credential chain if omitted)")
    p.add_argument(
        "--no-tui", action="store_true",
        help="Disable TUI, use simple log output",
    )
    args = p.parse_args()

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
    
    # Check OpenVPN Connect on macOS
    ovpn_app = Path("/Applications/OpenVPN Connect/OpenVPN Connect.app")
    if sys.platform == "darwin" and not ovpn_app.exists():
        print("WARNING: OpenVPN Connect not found at /Applications/OpenVPN Connect/")
        print("Install from: https://openvpn.net/client/")
        print("The VPN config will be saved to ~/.cloudshell-vpn/cloudshell-vpn.ovpn for manual import.\n")

    if args.region or args.no_tui:
        # Direct region or no-tui flag - use classic mode
        region = args.region or pick_region()
        log.info(f"Selected region: {region}")
        run_openvpn(region)
    else:
        # Full TUI mode - disable standard logging
        logging.disable(logging.CRITICAL)
        from .tui import run_vpn_tui
        
        print("\nFetching enabled regions...", flush=True)
        regions = list_regions()
        
        def vpn_runner(region, log_callback, status_callback, stop_event):
            run_openvpn_with_callbacks(region, log_callback, status_callback, stop_event)
        
        run_vpn_tui(regions, vpn_runner)


if __name__ == "__main__":
    main()
