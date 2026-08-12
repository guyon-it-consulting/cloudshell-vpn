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

# ---------------------------------------------------------------- prerequisites

step "Checking prerequisites"

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

if [ -z "$PYTHON" ]; then
    die "Python 3.$MIN_PY_MINOR or newer is required, and none was found." \
        "" \
        "Install it with Homebrew:" \
        "    brew install python@3.12" \
        "" \
        "Or download it from https://www.python.org/downloads/"
fi
ok "Python $("$PYTHON" -c 'import platform; print(platform.python_version())') ($PYTHON)"

# session-manager-plugin is what lets the AWS CLI/boto3 open a CloudShell
# session. Without it the tool cannot connect at all.
if ! command -v session-manager-plugin >/dev/null 2>&1; then
    die "session-manager-plugin is not installed." \
        "" \
        "It is required to open a session inside CloudShell." \
        "" \
        "Install it with Homebrew:" \
        "    brew install --cask session-manager-plugin" \
        "" \
        "Other platforms: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
fi
ok "session-manager-plugin"

# OpenVPN Connect is only needed on macOS, where the tool auto-imports the
# profile. Elsewhere the user brings their own client, so this is advisory.
if [ "$(uname -s)" = "Darwin" ]; then
    if [ -d "/Applications/OpenVPN Connect/OpenVPN Connect.app" ] \
        || [ -d "/Applications/OpenVPN Connect.app" ]; then
        ok "OpenVPN Connect"
    else
        warn "OpenVPN Connect not found in /Applications."
        warn "Download it (free) from https://openvpn.net/client/ before connecting."
    fi
fi

# ---------------------------------------------------------------------- venv

step "Setting up the virtualenv"

# A venv whose interpreter has been removed (e.g. Homebrew upgraded Python and
# the old minor version is gone) is broken in a way pip cannot repair. Detect
# that and rebuild from scratch rather than failing later with a confusing error.
if [ -d "$VENV_DIR" ] && ! "$VENV_DIR/bin/python" -c "" >/dev/null 2>&1; then
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
current_sum="$(shasum -a 256 "$REQ_FILE" | awk '{print $1}')"

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
