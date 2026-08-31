# cloudshell-vpn

Free VPN using a cloud shell as the exit node. Routes all traffic through **AWS CloudShell** (any region) or **GCP Cloud Shell** — at zero cost.

Read the story behind it: [How I built a free VPN over AWS CloudShell](https://builder.aws.com/content/3HmFxIRJFHC3cAaqUxByvcY8hDI/how-i-build-a-free-vpn-over-aws-cloudshell).

## How it works

```
macOS OpenVPN Connect (tun, full tunnel)
        ↓ OpenVPN → 127.0.0.1:1194
  Local relay  ──────────────────┐
        ↓ NAT-punched UDP hole   │  or: ssh -L forward (GCP only)
  Cloud shell (openvpn + iptables NAT)
        ↓ masquerade
  Internet (exits from the cloud shell's IP)
```

1. Starts a cloud shell environment (AWS: any region you pick; GCP: the one Google assigned you)
2. Generates ephemeral PKI (CA, server cert, client cert)
3. Inside the shell: sets up OpenVPN server + NAT masquerade
4. Establishes the data path — see **Transports** below
5. Writes `~/.cloudshell-vpn/cloudshell-vpn.ovpn` — auto-imported into OpenVPN Connect

### Transports

| Transport | Providers | How | When |
|---|---|---|---|
| `punch` (default) | AWS, GCP | Both sides discover their public endpoint via STUN, then UDP hole-punch | Fastest. Needs outbound UDP and a non-symmetric NAT |
| `ssh` | GCP only | OpenVPN/TCP through an `ssh -L` port forward | Survives symmetric NAT and corporate proxies. Slower (TCP-in-TCP) |

AWS has no `ssh` option: CloudShell is reached over SSM, which does not forward ports. GCP Cloud Shell hands out a real SSH endpoint with `AllowTcpForwarding yes`, which is what makes the second transport possible. (`PermitTunnel` is off, so `ssh -w` layer-3 tunnelling is not available on either.)

## Prerequisites

Common to both providers:

- macOS with [OpenVPN Connect](https://openvpn.net/client/) installed (free)
- Python 3.10+

**AWS:**

- `session-manager-plugin` ([install](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html))
- AWS credentials configured (`AWS_PROFILE` env var, or default profile)
- Non-symmetric NAT (most home networks work)

**GCP:**

- `gcloud` CLI, authenticated (`gcloud auth login`), and `ssh`
- Cloud Shell enabled for the account
- Non-symmetric NAT for `--transport punch`; `--transport ssh` has no NAT requirement

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

# GCP
./run.sh --provider gcp
./run.sh --provider gcp --transport ssh
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
| `--provider` | `aws` (default) or `gcp` |
| `--region`, `-r` | AWS region (skips interactive picker). Ignored on GCP |
| `--profile`, `-p` | AWS profile name (uses default credential chain if omitted) |
| `--transport` | GCP only: `punch` (default) or `ssh` |
| `--ssh-proxy-command` | GCP only: `ProxyCommand` for `ssh(1)`, to reach Cloud Shell through a proxy |
| `--exclude-ip` | Extra IPv4 address to route outside the tunnel (repeatable) |
| `--no-tui` | Disable TUI, use simple log output. Implied on GCP (no region to pick) |
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

## GCP Cloud Shell

```bash
./run.sh --provider gcp
```

The tool generates an ephemeral RSA keypair, registers it with the Cloud Shell
API (`addPublicKey`), opens one SSH session to the environment, and removes the
key again on exit. No IAM policy to write: Cloud Shell access is tied to the
account, and the API needs only the `cloud-platform` scope `gcloud auth login`
already grants.

**No region choice.** Every Google account gets exactly one Cloud Shell
environment, in a region Google assigns. `--region` is ignored. If you need a
specific exit country, use the AWS provider.

**Behind a corporate proxy.** Cloud Shell's SSH endpoint is a non-standard port
(6000), which most corporate egress filters block, and hole punching needs
outbound UDP that such networks rarely allow. Both problems go away with the
`ssh` transport plus a `ProxyCommand`:

```bash
./run.sh --provider gcp --transport ssh \
    --ssh-proxy-command 'nc -X connect -x proxy.corp:3128 %h %p' \
    --exclude-ip <proxy-ip>
```

`--exclude-ip` matters: the proxy carries the tunnel, so it must be routed
outside it. If the proxy intercepts TLS, point gcloud at your corporate CA with
`gcloud config set core/custom_ca_certs_file <ca.pem>`. Check your employer's
network policy before doing any of this.

**Limits.** 50 hours per week (vs 200 h/month/region on AWS); one environment per
account, shared with your normal Cloud Shell use; sessions end after 20 minutes
idle or 12 hours. Outbound transfer is not billed, so unlike AWS this is free
rather than nearly free.

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

The same holds on GCP, with Google in Amazon's place: the Cloud Shell API calls
are logged against your Google account, and the exit IP belongs to a Google
range that resolves to `*.bc.googleusercontent.com` — visibly a cloud IP.

DNS goes to Cloudflare by default (shorter retention than Google's resolvers).
Use `--dns` to point at a resolver you prefer.

## Cost

**Nearly free.** CloudShell compute is free. STUN is free. No EC2 instances, no NAT Gateway.

On AWS, outbound data transfer is billed at [standard rates](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer) (~$0.09/GB). The first 100 GB/month are included in the AWS Free Tier. Casual browsing and geo-shifting should stay well within that.

On GCP, Cloud Shell egress is not billed at all — the provider trade is a free exit node in exchange for no region choice.

## Limitations

- `--transport punch` only works with non-symmetric NAT (most residential, fails on some corporate firewalls). On GCP, `--transport ssh` is the way around it; AWS has no equivalent
- AWS CloudShell has a [monthly usage quota](https://docs.aws.amazon.com/cloudshell/latest/userguide/limits.html) of 200 hours per region per account (shared across all IAM principals — ~8 days continuous, increasable via Service Quotas). GCP Cloud Shell allows 50 hours per week
- GCP gives no choice of region, so no geo-shifting
- Sessions auto-terminate after 12 hours of continuous use
- Not for production use — it's a creative hack for privacy/geo-shifting
- One connection at a time per cloud shell environment

## Project structure

```
cloudshell_vpn/
├── __init__.py       # Package marker
├── __main__.py       # CLI, .ovpn generation, AWS orchestration
├── common.py         # Shared: boto3 client, Shell, STUN, PKI generation
├── gcp.py            # GCP backend: Cloud Shell API, ephemeral key, SSH shell
├── gcp_run.py        # GCP orchestration (punch and ssh transports)
├── agent_openvpn.py  # OpenVPN agent (runs inside the cloud shell, either provider)
├── tunnel_openvpn.py # OpenVPN relay (runs on laptop)
└── tui.py            # Terminal UI (region picker, status display — AWS only)
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
