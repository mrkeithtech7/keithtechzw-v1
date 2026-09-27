#!/usr/bin/env bash
# KEITH TECH SCANNER V1.2 — installer.
# Handles Termux (Android), Debian/Ubuntu, macOS. Safe to re-run.
set -e

say() { printf "\033[1;96m[*]\033[0m %s\n" "$1"; }
ok()  { printf "\033[1;92m[+]\033[0m %s\n" "$1"; }
err() { printf "\033[1;91m[!]\033[0m %s\n" "$1" 1>&2; }

# ── detect environment ───────────────────────────────────────────────────
if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
    ENV="termux"
elif [ "$(uname -s)" = "Darwin" ]; then
    ENV="macos"
elif [ -f /etc/debian_version ]; then
    ENV="debian"
elif [ -f /etc/arch-release ]; then
    ENV="arch"
else
    ENV="unknown"
fi
say "environment: $ENV"

# ── install python + pip ─────────────────────────────────────────────────
case "$ENV" in
    termux)
        say "termux: refreshing pkg index..."
        pkg update -y >/dev/null 2>&1 || true
        say "termux: installing python + git..."
        pkg install -y python git >/dev/null 2>&1 || {
            err "pkg install failed — check network and try again"
            exit 1
        }
        ;;
    debian)
        say "apt: installing python3 + pip + git..."
        if command -v sudo >/dev/null 2>&1; then
            SUDO=sudo
        else
            SUDO=
        fi
        $SUDO apt-get update -y >/dev/null 2>&1 || true
        $SUDO apt-get install -y python3 python3-pip git >/dev/null 2>&1 || {
            err "apt install failed"
            exit 1
        }
        ;;
    arch)
        say "pacman: installing python + git..."
        sudo pacman -S --noconfirm python python-pip git >/dev/null 2>&1 || true
        ;;
    macos)
        if ! command -v python3 >/dev/null 2>&1; then
            err "python3 not found — install from https://www.python.org or 'brew install python3'"
            exit 1
        fi
        ;;
    *)
        err "unknown environment — install python3 + pip manually, then re-run."
        exit 1
        ;;
esac

# ── verify python ────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not on PATH after install"
    exit 1
fi
ok "python3: $(python3 --version 2>&1)"

# ── install dnspython (OPTIONAL — install does not fail if this fails) ───
say "installing dnspython (optional, for full DNS scan)..."
if python3 -m pip install --quiet --disable-pip-version-check --upgrade "dnspython>=2.4.0" 2>/dev/null; then
    ok "dnspython installed — full DNS records available"
else
    err "dnspython install failed — scanner still works, DNS falls back to A record"
fi

# ── make launcher executable ─────────────────────────────────────────────
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/kts" ]; then
    chmod +x "$HERE/kts"
    ok "launcher ready: $HERE/kts"
fi
if [ -f "$HERE/kts.py" ]; then
    chmod +x "$HERE/kts.py"
fi

# ── termux PATH install ──────────────────────────────────────────────────
if [ "$ENV" = "termux" ] && [ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ]; then
    LAUNCH="$PREFIX/bin/kts"
    printf '#!/data/data/com.termux/files/usr/bin/bash\ncd "%s"\nexec python3 kts.py "$@"\n' "$HERE" > "$LAUNCH"
    chmod +x "$LAUNCH"
    ok "installed to PATH → type 'kts' from anywhere on Termux"
fi

echo
ok "install complete."
echo
echo "  run now:        python3 kts.py"
echo "  self-test:      python3 kts.py --check"
if [ "$ENV" = "termux" ]; then
    echo "  from anywhere:  kts"
fi
echo "  offline mode:   KTS_OFFLINE=1 python3 kts.py"
echo
