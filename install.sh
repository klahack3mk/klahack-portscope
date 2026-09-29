#!/usr/bin/env bash
# install.sh | Author: klahack | MIT License

REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/klahack3mk/klahack-portscope/main}"
set -euo pipefail

TOOL="klahack-portscope"
SOURCE_FILE="klahack_portscope.py"
CHECKSUM_FILE="SHA256SUMS"
TERMUX=false
OS_NAME="$(uname -s 2>/dev/null || printf 'unknown')"

if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q 'com\.termux'; then
    TERMUX=true
fi

say() {
    printf '[%s] %s\n' "$TOOL" "$*"
}

have_python() {
    command -v python3 >/dev/null 2>&1 && python3 -c \
        'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 127
    fi
}

install_python() {
    say "Python 3.8+ was not found; attempting installation."
    if [ "$TERMUX" = true ]; then
        pkg install -y python
        return
    fi
    if [ "$OS_NAME" = "Darwin" ]; then
        if ! command -v brew >/dev/null 2>&1; then
            printf 'Homebrew is required to install Python automatically on macOS.\n' >&2
            printf 'Install Homebrew, or install Python 3.8+, then rerun this installer.\n' >&2
            return 1
        fi
        brew install python
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update
        run_privileged apt-get install -y python3
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y python3
    elif command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -Sy --needed --noconfirm python
    elif command -v apk >/dev/null 2>&1; then
        run_privileged apk add python3
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper --non-interactive install python3
    else
        printf 'No supported package manager was found. Install Python 3.8+ and retry.\n' >&2
        return 1
    fi
}

if ! have_python; then
    install_python
fi
if ! have_python; then
    printf 'Python 3.8 or newer is required, but is still unavailable.\n' >&2
    exit 1
fi
say "Using $(python3 --version 2>&1)."

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t klahack-portscope)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

download() {
    url="$1"
    destination="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$destination"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$destination"
    else
        python3 - "$url" "$destination" <<'PY'
# install.sh downloader | Author: klahack | MIT License
import sys
import urllib.request
urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
PY
    fi
}

say "Downloading the scanner and published checksum list."
download "${REPO_RAW%/}/$SOURCE_FILE" "$TMP_DIR/$SOURCE_FILE"
download "${REPO_RAW%/}/$CHECKSUM_FILE" "$TMP_DIR/$CHECKSUM_FILE"

EXPECTED="$(awk '$2 == "klahack_portscope.py" || $2 == "*klahack_portscope.py" {print $1; exit}' "$TMP_DIR/$CHECKSUM_FILE")"
if [ -z "$EXPECTED" ]; then
    printf '%s does not contain a checksum for %s.\n' "$CHECKSUM_FILE" "$SOURCE_FILE" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP_DIR/$SOURCE_FILE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$TMP_DIR/$SOURCE_FILE" | awk '{print $1}')"
else
    ACTUAL="$(python3 - "$TMP_DIR/$SOURCE_FILE" <<'PY'
# install.sh checksum helper | Author: klahack | MIT License
import hashlib
import sys
with open(sys.argv[1], "rb") as source:
    print(hashlib.sha256(source.read()).hexdigest())
PY
)"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
    printf 'SHA256 verification failed; refusing to install.\n' >&2
    exit 1
fi
say "SHA256 verification passed."

if [ "$TERMUX" = true ]; then
    INSTALL_DIR="$PREFIX/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$TMP_DIR/$SOURCE_FILE" "$INSTALL_DIR/$TOOL"
    chmod 0755 "$INSTALL_DIR/$TOOL"
    ln -sf "$TOOL" "$INSTALL_DIR/kla"
    ln -sf "$TOOL" "$INSTALL_DIR/klaps"
elif [ "$(id -u)" -eq 0 ] || { [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; }; then
    INSTALL_DIR="/usr/local/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$TMP_DIR/$SOURCE_FILE" "$INSTALL_DIR/$TOOL"
    chmod 0755 "$INSTALL_DIR/$TOOL"
    ln -sf "$TOOL" "$INSTALL_DIR/kla"
    ln -sf "$TOOL" "$INSTALL_DIR/klaps"
elif command -v sudo >/dev/null 2>&1; then
    INSTALL_DIR="/usr/local/bin"
    sudo mkdir -p "$INSTALL_DIR"
    sudo cp "$TMP_DIR/$SOURCE_FILE" "$INSTALL_DIR/$TOOL"
    sudo chmod 0755 "$INSTALL_DIR/$TOOL"
    sudo ln -sf "$TOOL" "$INSTALL_DIR/kla"
    sudo ln -sf "$TOOL" "$INSTALL_DIR/klaps"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$TMP_DIR/$SOURCE_FILE" "$INSTALL_DIR/$TOOL"
    chmod 0755 "$INSTALL_DIR/$TOOL"
    ln -sf "$TOOL" "$INSTALL_DIR/kla"
    ln -sf "$TOOL" "$INSTALL_DIR/klaps"
    case ":${PATH:-}:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            say "Add $INSTALL_DIR to PATH to invoke $TOOL from any directory."
            ;;
    esac
fi

say "Installed idempotently at $INSTALL_DIR/$TOOL."
say "Aliases installed: $INSTALL_DIR/kla and $INSTALL_DIR/klaps."
"$INSTALL_DIR/$TOOL" --version
say "Installation verified."
