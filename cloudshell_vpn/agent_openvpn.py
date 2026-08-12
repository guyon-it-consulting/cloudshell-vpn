#!/usr/bin/env python3
"""CloudShell VPN agent — OpenVPN server + UDP relay.

Uploaded and executed inside CloudShell. It:
1. Installs openvpn and sets up server with inline certs
2. Binds a UDP socket, discovers public endpoint via STUN
3. Performs NAT hole punching toward the laptop
4. Relays UDP packets between the punched hole and local OpenVPN

Protocol markers printed to stdout:
    AGENT_READY:<ip>:<port>  — public endpoint discovered
    RELAY_ACTIVE             — relay running
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import struct
import subprocess
import sys
import traceback
import time

STUN_SERVER = ("stun.l.google.com", 19302)
STUN_TIMEOUT_S = 5
PUNCH_DURATION_S = 5
PUNCH_INTERVAL_S = 0.05

OVPN_PORT = 1194
OVPN_SUBNET = "10.98.0"
OVPN_SERVER_IP = f"{OVPN_SUBNET}.1"
MAX_UDP_PAYLOAD = 65535  # Max UDP datagram — smaller reads truncate silently


def _run(cmd: str, check: bool = False) -> int:
    r = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check and r != 0:
        raise RuntimeError(f"Command failed ({r}): {cmd}")
    return r


def setup_openvpn(
    ca_cert: str,
    server_cert: str,
    server_key: str,
    ta_key: str,
    dns_servers: list[str] | None = None,
) -> None:
    """Set up OpenVPN server with provided PKI."""
    dns_servers = dns_servers or ["1.1.1.1", "1.0.0.1"]
    print("SETUP: Installing openvpn...", flush=True)
    _run("sudo dnf install -y openvpn iptables iproute")

    # Write PKI files
    print("SETUP: Writing PKI files...", flush=True)
    os.makedirs("/tmp/ovpn", exist_ok=True)

    with open("/tmp/ovpn/ca.crt", "w") as f:
        f.write(ca_cert)
    with open("/tmp/ovpn/server.crt", "w") as f:
        f.write(server_cert)
    with open("/tmp/ovpn/server.key", "w") as f:
        f.write(server_key)
    os.chmod("/tmp/ovpn/server.key", 0o600)
    with open("/tmp/ovpn/ta.key", "w") as f:
        f.write(ta_key)
    os.chmod("/tmp/ovpn/ta.key", 0o600)

    # Write server config
    # Note: OpenVPN listens on 127.0.0.1:1194 — our relay bridges to external
    # Using 'dh none' to use ECDH instead of DH (no separate DH file needed)
    # Keep the pushed DNS in sync with what the client config already sets.
    dns_push = "\n".join(f'push "dhcp-option DNS {ip}"' for ip in dns_servers)
    server_conf = f"""# CloudShell VPN OpenVPN Server
local 127.0.0.1
port {OVPN_PORT}
proto udp
dev tun

# PKI
ca /tmp/ovpn/ca.crt
cert /tmp/ovpn/server.crt
key /tmp/ovpn/server.key
dh none
tls-auth /tmp/ovpn/ta.key 0

# Crypto - use ECDH for key exchange
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
ecdh-curve prime256v1

# Network
server {OVPN_SUBNET}.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
{dns_push}

# Performance
sndbuf 524288
rcvbuf 524288
push "sndbuf 524288"
push "rcvbuf 524288"

# Keepalive
keepalive 10 60

# Security — drop privileges after init
# Note: we don't use 'user nobody' because it breaks routing restoration on macOS clients
persist-key
persist-tun

# Logging
verb 3
mute 10
status /tmp/ovpn/status.log 30
"""
    with open("/tmp/ovpn/server.conf", "w") as f:
        f.write(server_conf)

    # Enable IP forwarding
    print("SETUP: Enabling IP forwarding...", flush=True)
    _run("sudo sysctl -w net.ipv4.ip_forward=1")

    # Set up NAT
    print("SETUP: Setting up NAT...", flush=True)
    _run(f"sudo iptables -t nat -A POSTROUTING -s {OVPN_SUBNET}.0/24 -o eth0 -j MASQUERADE")
    _run("sudo iptables -A FORWARD -i tun0 -j ACCEPT")
    _run("sudo iptables -A FORWARD -o tun0 -j ACCEPT")

    # Start OpenVPN
    print("SETUP: Starting OpenVPN server...", flush=True)
    result = subprocess.run(
        "sudo openvpn --config /tmp/ovpn/server.conf --daemon --log /tmp/ovpn/openvpn.log",
        shell=True, capture_output=True, text=True
    )
    
    # Wait for TUN interface
    for i in range(30):
        if _run("ip link show tun0") == 0:
            break
        time.sleep(0.5)
    else:
        print("SETUP_ERROR: tun0 interface not created", flush=True)
        # Show logs on failure
        result = subprocess.run("cat /tmp/ovpn/openvpn.log 2>/dev/null", shell=True, capture_output=True, text=True)
        if result.stdout:
            print(f"SETUP: OpenVPN log:\n{result.stdout}", flush=True)
        sys.exit(1)

    print("SETUP: OpenVPN server ready", flush=True)


def _validate_endpoint(ip: str, port: int) -> tuple[str, int]:
    """Reject non-routable addresses and out-of-range ports.

    STUN is unauthenticated UDP; the laptop side interpolates what we print
    here into its .ovpn config, so validate before printing AGENT_READY.
    """
    try:
        parsed = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise RuntimeError(f"STUN returned an invalid IPv4 address: {ip!r}") from exc
    # is_global covers RFC1918, loopback, link-local, CGNAT (100.64/10) and
    # the documentation ranges in one check. Multicast needs its own test:
    # 224.0.0.0/4 is globally routable, so is_global accepts it.
    if not parsed.is_global or parsed.is_multicast:
        raise RuntimeError(f"STUN returned a non-routable address: {ip}")
    if not 1 <= port <= 65535:
        raise RuntimeError(f"STUN returned an invalid port: {port}")
    return str(parsed), port


def stun_discover(sock: socket.socket) -> tuple[str, int]:
    txn = os.urandom(12)
    sock.settimeout(STUN_TIMEOUT_S)
    sock.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn, STUN_SERVER)
    data = sock.recv(1024)
    i = 20
    while i < len(data):
        atype, alen = struct.unpack("!HH", data[i : i + 4])
        if atype == 0x0020:
            port = struct.unpack("!H", data[i + 6 : i + 8])[0] ^ 0x2112
            raw_ip = struct.unpack("!I", data[i + 8 : i + 12])[0] ^ 0x2112A442
            ip = f"{(raw_ip >> 24) & 0xFF}.{(raw_ip >> 16) & 0xFF}.{(raw_ip >> 8) & 0xFF}.{raw_ip & 0xFF}"
            return _validate_endpoint(ip, port)
        i += 4 + alen
    raise RuntimeError("STUN: no XOR-MAPPED-ADDRESS")


def udp_relay(ext_sock: socket.socket, laptop_addr: tuple[str, int]) -> None:
    """Relay UDP packets between punched hole and local OpenVPN."""
    print(f"RELAY: Starting relay to {laptop_addr}", flush=True)
    
    ovpn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ovpn_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        ovpn_sock.bind(("127.0.0.1", 0))
        ovpn_local_port = ovpn_sock.getsockname()[1]
        print(f"RELAY: UDP relay socket bound to 127.0.0.1:{ovpn_local_port}", flush=True)
    except Exception as e:
        print(f"RELAY_ERROR: Failed to bind OVPN relay socket: {e}", flush=True)
        return
        
    ovpn_sock.setblocking(False)
    ext_sock.setblocking(False)

    actual_laptop = laptop_addr
    
    print("RELAY_ACTIVE", flush=True)
    
    packet_count = 0
    last_send = time.time()
    last_status = time.time()

    while True:
        try:
            readable, _, _ = select.select([ext_sock, ovpn_sock], [], [], 5.0)
        except Exception as e:
            print(f"RELAY_ERROR: select failed: {e}", flush=True)
            break

        # Status every 30s
        if time.time() - last_status > 30:
            print(f"RELAY_STATUS: packets={packet_count}, laptop={actual_laptop}", flush=True)
            last_status = time.time()

        for sock in readable:
            if sock is ext_sock:
                try:
                    data, addr = ext_sock.recvfrom(MAX_UDP_PAYLOAD)
                    packet_count += 1
                    
                    if data == b"PUNCH":
                        continue  # Keepalive from laptop
                    if data == b"\x00":
                        continue  # Keepalive
                    if data.startswith(b"PING:"):
                        # Respond to ping for latency measurement
                        ext_sock.sendto(b"PONG:" + data[5:], addr)
                        continue
                    
                    if addr[0] == laptop_addr[0]:
                        actual_laptop = addr
                        
                    ovpn_sock.sendto(data, ("127.0.0.1", OVPN_PORT))
                    packet_count += 1
                    if packet_count <= 5 or packet_count % 100 == 0:
                        print(f"RELAY: Ext→OVPN {len(data)}B (#{packet_count})", flush=True)
                except BlockingIOError:
                    pass
                except OSError as e:
                    print(f"RELAY: ext_sock error: {e}", flush=True)
                    
            elif sock is ovpn_sock:
                try:
                    data, ovpn_addr = ovpn_sock.recvfrom(MAX_UDP_PAYLOAD)
                    ext_sock.sendto(data, actual_laptop)
                    last_send = time.time()
                except BlockingIOError:
                    pass
                except OSError as e:
                    print(f"RELAY: ovpn_sock error: {e}", flush=True)
        
        # Send keepalive every 5s to maintain NAT mapping
        if time.time() - last_send > 5:
            try:
                ext_sock.sendto(b"PUNCH", actual_laptop)
                last_send = time.time()
            except OSError as e:
                print(f"RELAY: keepalive error: {e}", flush=True)


def main() -> None:
    if len(sys.argv) != 6:
        print(f"Usage: {sys.argv[0]} <udp_port> <laptop_ip:port> <ca_cert_b64> <server_cert_b64> <server_key_b64> <ta_key_b64>",
              file=sys.stderr)
        print(f"Got {len(sys.argv)} args: {sys.argv}", file=sys.stderr)
        sys.exit(1)

    import base64
    
    udp_port = int(sys.argv[1])
    laptop_ip, laptop_port = sys.argv[2].rsplit(":", 1)
    laptop_addr = (laptop_ip, int(laptop_port))
    
    # Decode base64-encoded PKI (to avoid shell escaping issues)
    ca_cert = base64.b64decode(sys.argv[3]).decode()
    server_cert = base64.b64decode(sys.argv[4]).decode()
    server_key = base64.b64decode(sys.argv[5]).decode()
    
    # ta_key is passed via stdin to avoid arg length limits
    print("AGENT: Reading ta_key from environment...", flush=True)
    ta_key = base64.b64decode(os.environ.get("TA_KEY_B64", "")).decode()
    if not ta_key:
        print("AGENT_ERROR: TA_KEY_B64 environment variable not set", flush=True)
        sys.exit(1)

    # DNS servers come via env var (like TA_KEY_B64) to keep the arg list stable.
    # Already validated laptop-side; re-validate here since this reaches a config
    # file read by a privileged binary.
    dns_servers = []
    for entry in os.environ.get("VPN_DNS", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            dns_servers.append(str(ipaddress.IPv4Address(entry)))
        except ValueError:
            print(f"AGENT_ERROR: invalid DNS address: {entry!r}", flush=True)
            sys.exit(1)

    print(f"AGENT: Starting with port={udp_port}, laptop={laptop_addr}", flush=True)

    # Set up OpenVPN
    setup_openvpn(ca_cert, server_cert, server_key, ta_key, dns_servers)

    # Bind UDP socket
    print(f"AGENT: Binding UDP socket to port {udp_port}", flush=True)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("", udp_port))
    print(f"AGENT: UDP socket bound", flush=True)

    # STUN discovery
    print("AGENT: STUN discovery...", flush=True)
    pub_ip, pub_port = stun_discover(udp_sock)
    print(f"AGENT_READY:{pub_ip}:{pub_port}", flush=True)

    # Hole punch
    print(f"AGENT: Hole punching to {laptop_addr}...", flush=True)
    udp_sock.setblocking(False)
    end = time.time() + PUNCH_DURATION_S
    punch_count = 0
    while time.time() < end:
        try:
            udp_sock.sendto(b"PUNCH", laptop_addr)
            punch_count += 1
        except OSError:
            pass
        time.sleep(PUNCH_INTERVAL_S)
    print(f"PUNCH_DONE: sent {punch_count} packets to {laptop_addr}", flush=True)

    # Run UDP relay
    print("AGENT: Starting UDP relay...", flush=True)
    udp_relay(udp_sock, laptop_addr)
    print("AGENT: Relay exited", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"AGENT_FATAL: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)
