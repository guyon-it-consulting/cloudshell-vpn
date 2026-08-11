"""Laptop-side UDP relay for OpenVPN traffic.

Binds 127.0.0.1:1194 and relays OpenVPN packets through the
NAT-punched UDP hole to the CloudShell agent.

The external socket must be connect()-ed to the agent's address.
OpenVPN client handles routing via net_gateway in the .ovpn config,
so no external route management is needed.
"""

from __future__ import annotations

import logging
import select
import socket
import threading
import time

from .common import HEARTBEAT_INTERVAL_S, OVPN_PORT

log = logging.getLogger(__name__)

_PUNCH_INTERVAL_S = 0.05
LOCAL_OVPN_PORT = OVPN_PORT


def start_heartbeat(cs_client, env_id: str) -> None:
    """Keep CloudShell alive with periodic heartbeats."""
    def loop():
        while True:
            try:
                cs_client.send_heart_beat(EnvironmentId=env_id)
                log.debug("Heartbeat sent")
            except Exception as e:
                log.warning(f"Heartbeat failed: {e}")
            time.sleep(HEARTBEAT_INTERVAL_S)
    threading.Thread(target=loop, daemon=True, name="heartbeat").start()


def udp_relay(ext_sock: socket.socket) -> None:
    """Relay OpenVPN UDP between local client and remote agent.

    ext_sock must already be connect()-ed to the agent's address.
    Uses send()/recv() — no address needed since socket is connected.
    """
    ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ovpn_sock.bind(("127.0.0.1", LOCAL_OVPN_PORT))
    ovpn_sock.setblocking(False)
    ext_sock.setblocking(False)

    log.info(f"Listening on 127.0.0.1:{LOCAL_OVPN_PORT} (OpenVPN UDP)")
    log.info(f"Remote endpoint: {ext_sock.getpeername()}")

    client_addr: tuple[str, int] | None = None
    last_send = time.time() - 10  # Force immediate keepalive
    last_stats_log = time.time()
    ovpn_packets = 0
    remote_packets = 0

    while True:
        readable, _, _ = select.select([ext_sock, ovpn_sock], [], [], 5.0)

        # Log stats every 60 seconds
        if time.time() - last_stats_log > 60:
            if ovpn_packets > 0 or remote_packets > 0:
                log.info(f"Traffic: {ovpn_packets} packets sent, {remote_packets} received")
            last_stats_log = time.time()

        for sock in readable:
            if sock is ovpn_sock:
                # From OpenVPN client → send to remote agent
                try:
                    data, addr = ovpn_sock.recvfrom(4096)
                    if data:
                        client_addr = addr
                        ext_sock.send(data)
                        ovpn_packets += 1
                        last_send = time.time()
                except (BlockingIOError, OSError):
                    pass
            elif sock is ext_sock:
                # From remote agent → send to OpenVPN client
                try:
                    data = ext_sock.recv(4096)
                    if data == b"PUNCH":
                        continue  # Keepalive from agent
                    if data == b"\x00":
                        continue  # Keepalive
                    if client_addr and data:
                        ovpn_sock.sendto(data, client_addr)
                        remote_packets += 1
                except (BlockingIOError, OSError):
                    pass

        # NAT keepalive every 5s to maintain mapping
        if time.time() - last_send > 5:
            try:
                ext_sock.send(b"\x00")
                last_send = time.time()
            except OSError:
                pass


def hole_punch(udp_sock: socket.socket, remote: tuple[str, int]) -> tuple[tuple[str, int], bool]:
    """Punch NAT hole and detect agent's actual address.
    
    Returns: (actual_address, punch_received)
    """
    log.info("Hole punching...")
    time.sleep(1)  # Brief wait for agent to start punching

    udp_sock.setblocking(False)
    actual = remote
    received = False
    end = time.time() + 8  # Max 8 seconds

    while time.time() < end:
        try:
            udp_sock.sendto(b"PUNCH", remote)
            if actual != remote:
                udp_sock.sendto(b"PUNCH", actual)
        except OSError:
            pass
        try:
            data, addr = udp_sock.recvfrom(1024)
            is_stun = len(data) > 2 and data[0:2] == b"\x01\x01"
            if not is_stun and addr[0] == remote[0]:
                if not received:
                    log.info(f"Received punch from agent: {addr[0]}:{addr[1]}")
                    received = True
                    # Once we receive, just do a quick burst and exit
                    end = time.time() + 1
                actual = addr
        except (BlockingIOError, OSError):
            pass
        time.sleep(_PUNCH_INTERVAL_S)

    if not received:
        log.warning("No punch from agent — NAT may be blocking")

    return actual, received
