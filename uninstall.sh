#!/usr/bin/env bash
# uninstall.sh | Author: klahack | MIT License

set -euo pipefail
TOOL="klahack-portscope"
TERMUX=false

if [ -n "${PREFIX:-}" ] && printf '%s' "$PREFIX" | grep -q 'com\.termux'; then
    TERMUX=true
fi

remove_file() {
    target="$1"
    if [ ! -e "$target" ]; then
        return
    fi
    if [ -w "$target" ] || [ -w "$(dirname "$target")" ] || [ "$(id -u)" -eq 0 ]; then
        rm -f "$target"
    elif command -v sudo >/dev/null 2>&1; then
        sudo rm -f "$target"
    else
        printf 'Cannot remove %s without elevated privileges.\n' "$target" >&2
        return 1
    fi
    printf '[%s] Removed %s\n' "$TOOL" "$target"
}

if [ "$TERMUX" = true ]; then
    remove_file "$PREFIX/bin/$TOOL"
else
    remove_file "$HOME/.local/bin/$TOOL"
    remove_file "/usr/local/bin/$TOOL"
fi

printf '[%s] Uninstall complete; no files remain from the script installation.\n' "$TOOL"
