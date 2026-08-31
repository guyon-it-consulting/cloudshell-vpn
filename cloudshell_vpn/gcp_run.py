"""Orchestration for the GCP Cloud Shell backend.

The AWS path in __main__.py has exactly one transport: punch a UDP hole and
relay OpenVPN through it. GCP Cloud Shell hands out a real SSH endpoint, which
buys a second option:

* ``punch`` — same as AWS. Best throughput, needs outbound UDP and a NAT that
  keeps its mappings endpoint-independent. Cloud Shell's own NAT does (it even
  preserves ports), so this comes down to the client side.
* ``ssh`` — OpenVPN over TCP through an ``ssh -L`` forward. No UDP, no STUN, no
  hole punch, so it survives symmetric NAT and corporate proxies. Slower:
  TCP inside TCP.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shlex
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)


def run_gcp(
    transport: str = "punch",
    dns_servers: list[str] | None = None,
    extra_excludes: list[str] | None = None,
    ssh_proxy_command: str | None = None,
) -> None:
    """Bring up the VPN over GCP Cloud Shell and block until interrupted."""
    from . import gcp
    from .common import (
        AGENT_UDP_PORT,
        DATA_DIR,
        OVPN_PORT,
        AgentError,
        generate_openvpn_pki,
        stun_discover,
        validate_public_ipv4,
        validate_port,
    )
    from .__main__ import (
        DEFAULT_DNS,
        generate_ovpn_conf,
        import_into_openvpn_connect,
        teardown_openvpn_connect,
        upload_agent,
    )
    from .tunnel_openvpn import hole_punch, udp_relay

    dns_servers = dns_servers or DEFAULT_DNS

    log.info("Generating OpenVPN PKI (ephemeral)...")
    pki = generate_openvpn_pki()

    log.info("Registering an ephemeral SSH key with Cloud Shell...")
    key_path, public_key = gcp.ensure_keypair()
    env = gcp.start_environment(public_key)

    # The SSH endpoint must never be routed into the tunnel it carries.
    ssh_host = validate_public_ipv4(env.ssh_host, "Cloud Shell")

    shell = None
    udp = None
    ovpn_sock = None
    # Declared outside the try so the finally block can always stop it.
    stop_keepalive = threading.Event()
    try:
        # Inside the try: if SSH cannot be established — the common outcome on a
        # network that blocks port 6000 — the finally block still has to retract
        # the key we just registered.
        shell = gcp.GcpShell(
            env,
            key_path,
            forward_port=OVPN_PORT if transport == "ssh" else None,
            proxy_command=ssh_proxy_command,
        )

        log.info("Uploading OpenVPN agent to Cloud Shell...")
        upload_agent(shell)

        shell.run("pkill -f vpn_agent_openvpn.py 2>/dev/null; sudo pkill openvpn 2>/dev/null", timeout=5)
        time.sleep(2)
        shell.drain()

        ca_b64 = base64.b64encode(pki["ca_cert"].encode()).decode()
        server_cert_b64 = base64.b64encode(pki["server_cert"].encode()).decode()
        server_key_b64 = base64.b64encode(pki["server_key"].encode()).decode()
        ta_key_b64 = base64.b64encode(pki["ta_key"].encode()).decode()

        exclude_ips = [ssh_host]

        if transport == "punch":
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind(("", 0))

            log.info("STUN: discovering laptop endpoint...")
            local_ip, local_port = stun_discover(udp)
            log.info(f"Laptop public: {local_ip}:{local_port}")

            # Hold the NAT mapping open while the agent installs OpenVPN.
            def nat_keepalive():
                while not stop_keepalive.is_set():
                    try:
                        udp.sendto(
                            struct.pack("!HHI", 0x0001, 0, 0x2112A442) + os.urandom(12),
                            ("stun.l.google.com", 19302),
                        )
                    except OSError:
                        pass
                    stop_keepalive.wait(2)

            threading.Thread(target=nat_keepalive, daemon=True).start()
            laptop_arg = f"{local_ip}:{local_port}"
        else:
            laptop_arg = "-"

        log.info(f"Starting OpenVPN agent (transport: {transport})...")
        # Everything interpolated here runs under sudo — quote it all, even the
        # values already validated laptop-side.
        shell.send(
            f"export TA_KEY_B64={shlex.quote(ta_key_b64)} && "
            f"export VPN_DNS={shlex.quote(','.join(dns_servers))} && "
            f"export VPN_TRANSPORT={shlex.quote(transport)} && "
            f"sudo -E python3 /tmp/vpn_agent_openvpn.py {AGENT_UDP_PORT} "
            f"{shlex.quote(laptop_arg)} "
            f"{shlex.quote(ca_b64)} {shlex.quote(server_cert_b64)} "
            f"{shlex.quote(server_key_b64)} 2>&1"
        )

        found, output = shell.wait_for("AGENT_READY:", timeout=180)
        if not found:
            log.error(f"Agent output:\n{output}")
            if "SETUP_ERROR" in output:
                raise AgentError(f"OpenVPN setup failed in Cloud Shell:\n{output}")
            raise AgentError(f"Agent failed:\n{output}")
        log.info(f"Agent setup output:\n{output}")

        if transport == "punch":
            match = re.search(r"AGENT_READY:(\d[\d.]*):(\d+)", output)
            if not match:
                raise AgentError(f"Cannot parse agent endpoint:\n{output}")
            # Reaches the .ovpn as a 'route' directive, read by a privileged
            # binary — validate before trusting the agent's stdout.
            agent_ip = validate_public_ipv4(match.group(1), "Agent")
            agent_port = validate_port(int(match.group(2)), "Agent")
            log.info(f"Agent public: {agent_ip}:{agent_port}")

            stop_keepalive.set()
            time.sleep(0.5)

            # Drop the STUN replies still queued on the socket.
            udp.setblocking(False)
            while True:
                try:
                    udp.recvfrom(1024)
                except (BlockingIOError, OSError):
                    break

            actual_addr, punch_received = hole_punch(udp, (agent_ip, agent_port))
            if not punch_received:
                log.warning("NAT punch may have failed — continuing anyway")
            udp.connect(actual_addr)
            log.info(f"Socket connected to {actual_addr} (local: {udp.getsockname()})")

            if agent_ip not in exclude_ips:
                exclude_ips.append(agent_ip)

        for ip in extra_excludes or []:
            if ip not in exclude_ips:
                exclude_ips.append(ip)
        log.info(f"IPs to exclude from VPN: {exclude_ips}")

        gcp.start_heartbeat(shell)

        conf = generate_ovpn_conf(
            pki, OVPN_PORT, exclude_ips, dns_servers,
            proto="tcp" if transport == "ssh" else "udp",
        )
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)  # mkdir ignores mode when the dir exists
        conf_path = DATA_DIR / "cloudshell-vpn.ovpn"
        conf_path.write_text(conf)
        os.chmod(conf_path, 0o600)  # contains the client private key
        log.info(f"OpenVPN config written to: {conf_path}")

        if transport == "punch":
            # Bind before launching the client: OpenVPN Connect starts sending
            # to 127.0.0.1:1194 immediately and gives up on ICMP
            # port-unreachable if nothing is listening yet.
            ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ovpn_sock.bind(("127.0.0.1", OVPN_PORT))
        # In ssh mode the listener is the SSH forward, already up since connect.

        import_into_openvpn_connect(conf_path)
        log.info(
            f"\n{'=' * 55}\n"
            f"  VPN connecting via GCP Cloud Shell ({transport})\n"
            f"  Exit IP: {ssh_host} — region is assigned by Google\n"
            f"  Press Ctrl+C to disconnect and exit\n"
            f"{'=' * 55}\n"
        )

        if transport == "punch":
            udp_relay(udp, ovpn_sock)
        else:
            _wait_on_shell(shell)

    except KeyboardInterrupt:
        log.info("\nShutting down...")
    except ConnectionError as e:
        log.error(f"Connection lost: {e}")
        log.error("Re-run the command to reconnect.")
    finally:
        stop_keepalive.set()
        # Free port 1194 so an immediate re-run can bind it again
        for sock in (udp, ovpn_sock):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        if shell is not None:
            try:
                shell.cleanup()
            except Exception:
                pass
        # Leaving the key behind would grant shell access to anyone holding it.
        gcp.remove_public_key(public_key)
        teardown_openvpn_connect()
        log.info("Done.")


def _wait_on_shell(shell) -> None:
    """Block until the SSH session dies or the user interrupts.

    In ssh transport there is no relay loop to run: the SSH forward carries the
    traffic. What we must still notice is the tunnel's carrier going away.
    """
    while True:
        if shell._proc.poll() is not None:
            raise ConnectionError(
                f"SSH session to Cloud Shell ended (code {shell._proc.returncode}) "
                f"— the tunnel it carried is gone"
            )
        shell.drain()
        time.sleep(5)
