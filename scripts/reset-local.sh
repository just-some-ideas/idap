#!/usr/bin/env bash
# Reset all local IDAP state for testing.
# Usage: ./scripts/reset-local.sh [--proxy-only | --ios-only]
#
# Works while the app is running in Xcode — just hit Cmd+R to relaunch after.
set -euo pipefail

export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

PROXY_DIR="$(cd "$(dirname "$0")/../proxy" && pwd)"
BUNDLE_ID="app.idap"

reset_proxy() {
    echo "=== Proxy ==="
    local db="${PROXY_DIR}/idap.db"
    if [ -f "$db" ]; then
        rm -f "$db" "${db}-wal" "${db}-shm"
        echo "  Deleted $db"
    else
        echo "  No proxy DB found at $db"
    fi
}

reset_ios_simulator() {
    echo "=== iOS Simulator ==="

    # Find the data container for the booted simulator
    local container
    container=$(xcrun simctl get_app_container booted "$BUNDLE_ID" data 2>/dev/null) || {
        echo "  Could not find app container. Is the simulator booted with the app installed?"
        return 1
    }
    echo "  Container: $container"

    # Wipe databases
    local app_support="$container/Library/Application Support/IDAP"
    if [ -d "$app_support" ]; then
        rm -f "$app_support"/*.db "$app_support"/*-wal "$app_support"/*-shm
        rm -f "$app_support"/recovery_map.json "$app_support"/activity.json
        echo "  Deleted databases and data files"
    fi

    # Wipe UserDefaults plist
    local prefs="$container/Library/Preferences/${BUNDLE_ID}.plist"
    if [ -f "$prefs" ]; then
        rm -f "$prefs"
        echo "  Deleted UserDefaults plist"
    fi

    # Wipe keychain entries for this app
    xcrun simctl keychain booted reset 2>/dev/null && echo "  Reset simulator keychain" || true

    echo "  Done. Relaunch the app in Xcode (Cmd+R)."
}

case "${1:-all}" in
    --proxy-only)  reset_proxy ;;
    --ios-only)    reset_ios_simulator ;;
    all)           reset_proxy; echo; reset_ios_simulator ;;
    *)             echo "Usage: $0 [--proxy-only | --ios-only]"; exit 1 ;;
esac

echo
echo "Reset complete."
