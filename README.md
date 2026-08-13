# cloudshell-vpn

Free VPN using AWS CloudShell + NAT hole punching. Routes all traffic through any AWS region — at zero cost.

## How it works

```
macOS OpenVPN Connect (tun, full tunnel)
        ↓ OpenVPN UDP → 127.0.0.1:1194
  Local UDP relay (unprivileged)
        ↓ NAT-punched UDP hole
  AWS CloudShell (openvpn + iptables NAT)
        ↓ masquerade
  Internet (exits from AWS region IP)
```

1. Creates a non-VPC CloudShell environment in your chosen region
2. Generates ephemeral PKI (CA, server cert, client cert)
3. Inside CloudShell: sets up OpenVPN server + NAT masquerade
4. Both sides discover their public endpoints via STUN, then UDP hole-punch
5. Writes `~/.cloudshell-vpn/cloudshell-vpn.ovpn` — auto-imported into OpenVPN Connect

## Prerequisites

- macOS with [OpenVPN Connect](https://openvpn.net/client/) installed (free)
- Python 3.10+
- `session-manager-plugin` ([install](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html))
- AWS credentials configured (`AWS_PROFILE` env var, or default profile)
- Non-symmetric NAT (most home networks work)

## Quick start

The easiest way to run is with the launcher script — it checks prerequisites, manages a virtualenv, and starts the VPN:

```bash
./run.sh
```

That's it. The script will:
1. Verify Python ≥ 3.10, `session-manager-plugin`, and OpenVPN Connect are installed
2. Create/update a virtualenv with dependencies
3. Verify AWS credentials
4. Launch the VPN (interactive region picker + TUI)

Pass any flag through to the tool:

```bash
./run.sh --region eu-west-1
./run.sh --profile my-profile
./run.sh --no-tui
./run.sh --dns 9.9.9.9,149.112.112.112
```

### Manual setup

If you prefer to manage the environment yourself:

```bash
pip install -r requirements.txt
python -m cloudshell_vpn
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--region`, `-r` | AWS region (skips interactive picker) |
| `--profile`, `-p` | AWS profile name (uses default credential chain if omitted) |
| `--no-tui` | Disable TUI, use simple log output |
| `--dns` | Comma-separated DNS servers (default: `1.1.1.1,1.0.0.1`) |

### What happens

1. Pick a region (or use `--region`)
2. Ephemeral PKI is generated
3. CloudShell starts, agent is uploaded, OpenVPN server comes up
4. NAT hole punch establishes the UDP path
5. Profile is auto-imported into OpenVPN Connect

All traffic now exits from the AWS region. Press Ctrl+C to stop.

## IAM permissions

The tool requires write access to CloudShell. **AdministratorAccess** and **PowerUserAccess** work out of the box.

Read-only permission sets (**ReadOnlyAccess**, **ViewOnlyAccess**) will **not** work — they lack the write actions needed to create environments and sessions.

### Minimal IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "cloudshell:DescribeEnvironments",
        "cloudshell:CreateEnvironment",
        "cloudshell:GetEnvironmentStatus",
        "cloudshell:StartEnvironment",
        "cloudshell:CreateSession",
        "cloudshell:DeleteSession",
        "cloudshell:SendHeartBeat"
      ],
      "Resource": "*"
    }
  ]
}
```

Alternatively, attach the AWS managed policy `AWSCloudShellFullAccess` and add `ec2:DescribeRegions` + `sts:GetCallerIdentity`.

## No sudo required

Route exclusions are handled in the `.ovpn` config via `net_gateway` directives.
OpenVPN Connect manages routing automatically with its built-in privileges.

### What this means for leak protection

There is **no kill switch**. Dead-tunnel detection comes from the server's
`keepalive 10 30`, pushed to the client as `ping 10` / `ping-restart 30`, so a
stalled tunnel is torn down and retried rather than silently passing no traffic.
That closes the common failure case, but a firewall-level kill switch would
require `sudo pfctl`, which this tool deliberately avoids.

Note that OpenVPN Connect rejects `ping`, `ping-restart`, `persist-tun` and
similar directives when they appear in the `.ovpn` itself ("unsupported
options") — it manages timers and interface persistence internally. This is why
the timers are pushed by the server rather than set in the profile.

Concretely: if the relay process is killed abruptly (`kill -9`, kernel panic,
forced logout), traffic falls back to your normal gateway in the clear, with no
warning. If you need a guarantee rather than a best effort, use a client with a
built-in firewall kill switch.

## Privacy scope

The exit IP belongs to an AWS pool and is not registered to you — sites you
visit see "an AWS IP in region X" and cannot trace it back to you.

AWS itself is a different matter. CloudTrail records the `cloudshell:*` API
calls made with your credentials, including your real source IP and timestamps;
the environment is tied to your IAM principal; and outbound transfer appears on
your bill. AWS therefore holds the link between your identity and this session
by construction.

That is fine for geo-shifting or for shielding traffic on an untrusted network.
It is not equivalent to a no-logs VPN: you have replaced your ISP as the
observer with Amazon, not removed the observer.

DNS goes to Cloudflare by default (shorter retention than Google's resolvers).
Use `--dns` to point at a resolver you prefer.

## Cost

**Nearly free.** CloudShell compute is free. STUN is free. No EC2 instances, no NAT Gateway.

Outbound data transfer is billed at [standard AWS rates](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer) (~$0.09/GB). The first 100 GB/month are included in the AWS Free Tier. Casual browsing and geo-shifting should stay well within that.

## Limitations

- Only works with non-symmetric NAT (most residential, fails on some corporate firewalls)
- CloudShell has a [monthly usage quota](https://docs.aws.amazon.com/cloudshell/latest/userguide/limits.html) of 200 hours per region per account (shared across all IAM principals — ~8 days continuous, increasable via Service Quotas)
- Sessions auto-terminate after 12 hours of continuous use
- Not for production use — it's a creative hack for privacy/geo-shifting
- One connection at a time per CloudShell environment

## Project structure

```
cloudshell_vpn/
├── __init__.py       # Package marker
├── __main__.py       # CLI: region picker, PKI generation, orchestration
├── common.py         # Shared: boto3 client, Shell, STUN, PKI generation
├── agent_openvpn.py  # OpenVPN agent (runs inside CloudShell)
├── tunnel_openvpn.py # OpenVPN relay (runs on laptop)
└── tui.py            # Terminal UI (region picker, status display)
```

## Generated files

All runtime data is stored in `~/.cloudshell-vpn/`:

```
~/.cloudshell-vpn/
├── cloudshell-vpn.ovpn   # OpenVPN profile (auto-imported into OpenVPN Connect)
└── history.json           # Recently used regions
```

## Contributors

- [Brice Dauzats](https://github.com/bdauzats) — reliability and security hardening (v0.1.0): STUN validation, shell-injection fix, file permissions, DNS privacy, reconnection logic, relay binding, dead-tunnel detection, and the `run.sh` launcher.
