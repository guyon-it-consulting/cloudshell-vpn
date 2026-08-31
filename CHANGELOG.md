# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **GCP Cloud Shell as a second provider** (`--provider gcp`). Cloud Shell there
  exposes a real SSH endpoint rather than SSM, so the backend registers an
  ephemeral RSA key through the Cloud Shell API (`addPublicKey`), drives one SSH
  session as the control channel, and removes the key on exit. Verified
  end-to-end from an isolated network namespace: tunnel up, NAT masquerade
  applied, traffic exiting from the Cloud Shell IP.
- **`--transport ssh` (GCP only).** Carries OpenVPN over TCP through an
  `ssh -L` forward instead of a NAT-punched UDP hole. No STUN, no hole punch, so
  it works behind symmetric NAT and corporate proxies — at the cost of TCP-in-TCP
  throughput. `--ssh-proxy-command` plugs in a `ProxyCommand` for proxied
  networks.
- **`--exclude-ip`** (both providers) to route additional addresses outside the
  tunnel, for a proxy or relay the tunnel itself depends on.

### Changed

- The agent installs openvpn through whichever package manager it finds
  (`dnf`/`apt-get`/`yum`) and skips the install when openvpn is already present,
  instead of assuming Amazon Linux's `dnf`.
- NAT masquerade now targets the interface carrying the default route rather
  than a hardcoded `eth0`.
- `boto3` is imported lazily, so the GCP path no longer pulls in the AWS SDK.
- OpenVPN Connect import/teardown moved into shared helpers used by both
  providers.

## [0.1.1] — 2026-08-28

### Fixed

- **IPv6 traffic no longer leaks around the VPN.** Added `block-ipv6` directive
  to the generated `.ovpn` profile. The VPN only supports IPv4; without this
  directive, IPv6 traffic bypassed the tunnel entirely and went out via the
  normal gateway — a privacy leak. IPv6 is now explicitly blocked while the VPN
  is connected.

## [0.1.0] — 2026-08-12

Reliability and security pass. The OpenVPN tunnel itself was already sound —
AES-256-GCM, `tls-auth` HMAC, ephemeral PKI, `remote-cert-tls server` — so
nothing in the crypto design changed. What changed is everything around it: the
UDP transport, the failure handling, and a shell-injection path.

### Security

- **Validate STUN-derived addresses before use.** `stun_discover` parsed an
  unauthenticated UDP response and the result was interpolated into a command
  run under `sudo` inside CloudShell. A hostile STUN server or a UDP MITM could
  inject arbitrary shell. Both the laptop and agent sides now reject anything
  that is not a routable public IPv4 (`not is_global or is_multicast`, which
  also covers CGNAT `100.64.0.0/10`) and any port outside 1–65535.
- **Validate the agent endpoint** parsed from `AGENT_READY:` before it reaches
  the `.ovpn` file as a `route` directive — that file is read by a privileged
  binary.
- **Quote every interpolated value** in the `sudo` command with `shlex.quote()`
  as defence in depth.
- **Restrict key file permissions.** `~/.cloudshell-vpn/` is now `0700` and the
  generated `.ovpn` — which embeds the client private key — is `0600`. Inside
  CloudShell, `/tmp/ovpn` is `0700`.
- **Switch default DNS from Google to Cloudflare** (`1.1.1.1` / `1.0.0.1`),
  configurable with the new `--dns` flag. The server-side push and the client
  profile are now kept in sync; previously the server still pushed `8.8.8.8`
  regardless.

### Fixed

- **Reconnection never actually ran.** The TUI had a 3-attempt retry loop, but a
  bare `except Exception` swallowed the `ConnectionError` before it could reach
  the worker — the "Reconnecting..." message was cosmetic. The exception is now
  re-raised so the existing loop works.
- **OpenVPN Connect could never reach the local relay.** The relay socket was
  bound to `127.0.0.1:1194` *after* the client was launched, so the client hit
  ICMP port-unreachable and gave up before anything was listening. The bind now
  happens before the profile import, in both execution paths.
- **UDP payloads were truncated at 4096 bytes** while the profile advertises
  `sndbuf 524288`. Oversized packets were silently cut, failed the `tls-auth`
  HMAC at the peer, and degraded the connection with no usable error. Reads now
  use the full 65535-byte datagram size.
- **Dead-tunnel detection never fired** when OpenVPN Connect failed to connect,
  because the check required an already-connected client. It is now split into
  two independent conditions: client never reached the relay (60s), and agent
  gone silent (120s). `--no-tui` gained the same detection.
- **`--no-tui` mode was broken.** `hole_punch` returns `(address, punched)` but
  the tuple was assigned whole to `actual_addr` and passed to `socket.connect()`.
- **OpenVPN Connect rejected several profile directives** as "unsupported
  options" (`ping`, `ping-restart`, `resolv-retry`, `persist-key`,
  `persist-tun`, `explicit-exit-notify`, `mute`). It manages timers and
  interface persistence internally. These were removed from the client profile;
  dead-tunnel timers now come from the server's `keepalive 10 30`, which expands
  to `push "ping 10"` + `push "ping-restart 30"` and *is* honoured.
- **CloudShell sessions were left orphaned.** `Shell.cleanup()` existed but was
  never called — both paths killed the local plugin process directly, so
  `delete_session` never ran and sessions kept consuming the 200h/region quota.
- **Sockets were leaked on error.** `udp` and `ovpn_sock` are now initialised to
  `None` and checked before closing; an early exception previously raised
  `NameError` inside `finally` and skipped the remaining cleanup. The `--no-tui`
  path did not close its sockets at all, which blocked port 1194 on re-run.
- **Fixed the agent's usage message**, which listed six arguments for five (the
  TLS-auth key is passed via the `TA_KEY_B64` environment variable).

### Added

- `--dns` flag to override the DNS servers pushed to the client, accepting a
  comma-separated list. Values are validated before any AWS call is made.
- `run.sh` launcher that checks prerequisites (Python ≥ 3.10,
  `session-manager-plugin`, OpenVPN Connect on macOS), creates and maintains a
  virtualenv, verifies AWS credentials, and starts the tool. Idempotent and safe
  to re-run; any `cloudshell_vpn` flag is passed through.

### Documentation

- Documented the **leak-protection boundary** in the README. There is no kill
  switch: dead-tunnel detection limits the common failure case, but if the relay
  process is killed abruptly, traffic falls back to the normal gateway in the
  clear. A firewall-level kill switch would require `sudo pfctl`, which this
  tool deliberately avoids.
- Documented the **privacy scope**. The exit IP belongs to an AWS pool and is
  not traceable to the user by an outside observer, but CloudTrail records the
  `cloudshell:*` calls with the caller's IAM identity and source IP, and
  outbound transfer appears on the bill. This is fine for geo-shifting; it is
  not equivalent to a no-logs VPN.

[0.1.1]: https://github.com/guyon-it-consulting/cloudshell-vpn/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/guyon-it-consulting/cloudshell-vpn/compare/fc58a11...v0.1.0
