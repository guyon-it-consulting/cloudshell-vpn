#!/usr/bin/env bash
#
# cloudshell-vpn launcher — for people who just want it to work.
#
# Checks prerequisites, creates/updates a virtualenv, installs dependencies,
# then starts the VPN. Safe to re-run: everything it does is idempotent.
#
# Usage:
#   ./run.sh                          # interactive region picker
#   ./run.sh --region eu-west-1       # any cloudshell_vpn flag is passed through
#   ./run.sh --profile my-profile
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
MIN_PY_MINOR=10

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

step() { printf '%s==>%s %s\n' "$BLUE$BOLD" "$RESET$BOLD" "$1$RESET"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }

# Print an error with an explanation of how to fix it, then exit.
die() {
    printf '\n%sERROR:%s %s\n' "$RED$BOLD" "$RESET" "$1" >&2
    shift
    for line in "$@"; do
        printf '  %s\n' "$line" >&2
    done
    exit 1
}

# ------------------------------------------------------------------ provider

# The provider decides which CLI and which credentials we check for, so it has
# to be resolved before the pre-flight checks — not just passed through.
PROVIDER="aws"
prev=""
for arg in "$@"; do
    case "$prev" in
        --provider) PROVIDER="$arg" ;;
    esac
    case "$arg" in
        --provider=*) PROVIDER="${arg#--provider=}" ;;
    esac
    prev="$arg"
done

case "$PROVIDER" in
    aws|gcp) ;;
    *) die "Unknown --provider '$PROVIDER' (expected 'aws' or 'gcp')." ;;
esac

# ---------------------------------------------------------------- prerequisites

step "Checking prerequisites (provider: $PROVIDER)"

# Find a Python >= 3.10. python3 is usually it, but a system python3 can be
# older than the venv-capable one installed by Homebrew, so try the explicit
# versioned names too.
PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

OS_NAME="$(uname -s)"

if [ -z "$PYTHON" ]; then
    if [ "$OS_NAME" = "Linux" ]; then
        die "Python 3.$MIN_PY_MINOR or newer is required, and none was found." \
            "" \
            "Install it with your package manager:" \
            "    sudo apt install python3 python3-venv     # Debian/Ubuntu" \
            "    sudo dnf install python3                  # Fedora/RHEL" \
            "    sudo pacman -S python                      # Arch" \
            "" \
            "Or download it from https://www.python.org/downloads/"
    else
        die "Python 3.$MIN_PY_MINOR or newer is required, and none was found." \
            "" \
            "Install it with Homebrew:" \
            "    brew install python@3.12" \
            "" \
            "Or download it from https://www.python.org/downloads/"
    fi
fi
ok "Python $("$PYTHON" -c 'import platform; print(platform.python_version())') ($PYTHON)"

if [ "$PROVIDER" = "aws" ]; then
    # session-manager-plugin is what lets the AWS CLI/boto3 open a CloudShell
    # session. Without it the tool cannot connect at all.
    if ! command -v session-manager-plugin >/dev/null 2>&1; then
        if [ "$OS_NAME" = "Linux" ]; then
            die "session-manager-plugin is not installed." \
                "" \
                "It is required to open a session inside CloudShell." \
                "" \
                "Debian/Ubuntu (x86_64):" \
                "    curl -fsSL \"https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb\" -o /tmp/session-manager-plugin.deb" \
                "    sudo dpkg -i /tmp/session-manager-plugin.deb" \
                "" \
                "RHEL/Fedora/Amazon Linux (x86_64):" \
                "    sudo dnf install -y \"https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm\"" \
                "" \
                "Other platforms/architectures: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
        else
            die "session-manager-plugin is not installed." \
                "" \
                "It is required to open a session inside CloudShell." \
                "" \
                "Install it with Homebrew:" \
                "    brew install --cask session-manager-plugin" \
                "" \
                "Other platforms: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
        fi
    fi
    ok "session-manager-plugin"
else
    # GCP talks to Cloud Shell over plain SSH; gcloud supplies the OAuth token
    # and ssh(1) is the transport.
    if ! command -v gcloud >/dev/null 2>&1; then
        if [ "$OS_NAME" = "Linux" ]; then
            die "gcloud CLI is not installed." \
                "" \
                "It is required to authenticate against Cloud Shell." \
                "" \
                "Install it with your package manager, or the interactive installer:" \
                "    curl https://sdk.cloud.google.com | bash" \
                "" \
                "Debian/Ubuntu (apt repo): https://cloud.google.com/sdk/docs/install#deb" \
                "Other platforms: https://cloud.google.com/sdk/docs/install"
        else
            die "gcloud CLI is not installed." \
                "" \
                "It is required to authenticate against Cloud Shell." \
                "" \
                "Install it with Homebrew:" \
                "    brew install --cask google-cloud-sdk" \
                "" \
                "Other platforms: https://cloud.google.com/sdk/docs/install"
        fi
    fi
    ok "gcloud"
    command -v ssh >/dev/null 2>&1 || die "ssh(1) not found — required for the GCP transport."
    ok "ssh"
fi

# OpenVPN Connect (macOS) is auto-imported into; on Linux there is no
# equivalent official GUI client, so just check that *some* OpenVPN client is
# available and point the user at how to use the generated .ovpn profile.
if [ "$OS_NAME" = "Darwin" ]; then
    if [ -d "/Applications/OpenVPN Connect/OpenVPN Connect.app" ] \
        || [ -d "/Applications/OpenVPN Connect.app" ]; then
        ok "OpenVPN Connect"
    else
        warn "OpenVPN Connect not found in /Applications."
        warn "Download it (free) from https://openvpn.net/client/ before connecting."
    fi
elif [ "$OS_NAME" = "Linux" ]; then
    if command -v openvpn >/dev/null 2>&1 || command -v nmcli >/dev/null 2>&1; then
        ok "OpenVPN client found ($(command -v openvpn || command -v nmcli))"
    else
        warn "No OpenVPN client found (openvpn / NetworkManager)."
        warn "Install one, e.g.:"
        warn "    sudo apt install openvpn                       # Debian/Ubuntu"
        warn "    sudo apt install network-manager-openvpn-gnome # NetworkManager GUI plugin"
        warn "The VPN config will be saved to ~/.cloudshell-vpn/cloudshell-vpn.ovpn"
        warn "for manual import (nmcli import, or 'sudo openvpn --config <file>')."
    fi
fi

# ---------------------------------------------------------------------- venv

step "Setting up the virtualenv"

# A venv whose interpreter has been removed (e.g. Homebrew upgraded Python and
# the old minor version is gone) is broken in a way pip cannot repair. The same
# goes for a venv whose creation was interrupted, leaving the python symlink but
# no activate script. Detect either and rebuild from scratch rather than failing
# later with a confusing error.
if [ -d "$VENV_DIR" ] \
    && { ! "$VENV_DIR/bin/python" -c "" >/dev/null 2>&1 \
         || [ ! -f "$VENV_DIR/bin/activate" ]; }; then
    warn "Existing virtualenv is broken, recreating it."
    rm -rf "$VENV_DIR"
fi

if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON" -m venv "$VENV_DIR" \
        || die "Failed to create the virtualenv at $VENV_DIR" \
               "" \
               "On Debian/Ubuntu you may need:" \
               "    sudo apt install python3-venv"
    ok "Created $VENV_DIR"
else
    ok "Using existing $VENV_DIR"
fi

# Activate so anything downstream (and the user, if they source this) sees it.
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

step "Installing dependencies"

# Only reinstall when requirements.txt changed since the last successful run.
# Keeps repeat launches fast without ever going stale.
STAMP="$VENV_DIR/.requirements.sha"
REQ_FILE="$REPO_DIR/requirements.txt"
# sha256sum is standard on Linux; shasum (Perl-based) is what macOS ships.
# Fall back between the two so this works on both without extra deps.
if command -v sha256sum >/dev/null 2>&1; then
    current_sum="$(sha256sum "$REQ_FILE" | awk '{print $1}')"
else
    current_sum="$(shasum -a 256 "$REQ_FILE" | awk '{print $1}')"
fi

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$current_sum" ]; then
    ok "Dependencies already up to date"
else
    python -m pip install --quiet --upgrade pip \
        || die "Failed to upgrade pip inside the virtualenv."
    python -m pip install --quiet -r "$REQ_FILE" \
        || die "Failed to install dependencies from requirements.txt" \
               "" \
               "Check your network connection and try again."
    printf '%s' "$current_sum" > "$STAMP"
    ok "Installed boto3, cryptography, textual"
fi

# ---------------------------------------------------------------- credentials

if [ "$PROVIDER" = "gcp" ]; then
    step "Checking GCP credentials"
    if ! gcloud auth print-access-token >/dev/null 2>&1; then
        die "Could not get a GCP access token." \
            "" \
            "Authenticate with:" \
            "    gcloud auth login"
    fi
    ok "GCP credentials valid"

    step "Starting cloudshell-vpn"
    printf '  Press %sCtrl+C%s to disconnect and clean up.\n\n' "$BOLD" "$RESET"
    cd "$REPO_DIR"
    exec python -m cloudshell_vpn "$@"
fi

# ------------------------------------------------------------ aws credentials

step "Checking AWS credentials"

# --profile is passed through to the tool, but this pre-flight check runs
# before it, so honour the flag here too and give a precise error.
PROFILE_ARG=()
prev=""
for arg in "$@"; do
    case "$prev" in
        --profile|-p) PROFILE_ARG=(--profile "$arg") ;;
    esac
    case "$arg" in
        --profile=*) PROFILE_ARG=(--profile "${arg#--profile=}") ;;
    esac
    prev="$arg"
done
if [ ${#PROFILE_ARG[@]} -eq 0 ] && [ -n "${AWS_PROFILE:-}" ]; then
    PROFILE_ARG=(--profile "$AWS_PROFILE")
fi

# Use boto3 from the venv rather than requiring the AWS CLI to be installed —
# boto3 is a dependency we just installed, the CLI may not be there at all.
# ${arr[@]+"${arr[@]}"} — expanding an empty array is an "unbound variable"
# error under `set -u` on bash 3.2, which is what macOS ships.
identity_err="$(
    python - ${PROFILE_ARG[@]+"${PROFILE_ARG[@]}"} <<'PY' 2>&1 >/dev/null
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError

profile = sys.argv[2] if len(sys.argv) > 2 else None
try:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    ident = session.client("sts").get_caller_identity()
except (BotoCoreError, ClientError) as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
print(ident["Arn"])
PY
)" && identity_ok=1 || identity_ok=0

if [ "$identity_ok" -eq 0 ]; then
    die "Could not authenticate to AWS." \
        "" \
        "$identity_err" \
        "" \
        "Configure credentials with:" \
        "    aws configure" \
        "" \
        "Or select an existing profile:" \
        "    ./run.sh --profile my-profile"
fi
ok "AWS credentials valid"

# ------------------------------------------------------------------- launch

step "Starting cloudshell-vpn"
printf '  Press %sCtrl+C%s to disconnect and clean up.\n\n' "$BOLD" "$RESET"

# Run from the repo root: the bundled boto3 CloudShell model is resolved
# relative to the package directory.
cd "$REPO_DIR"
exec python -m cloudshell_vpn "$@"
