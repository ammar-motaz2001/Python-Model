#!/usr/bin/env bash
# Stream macOS WiFi-related unified logs into project logs/wifi.log (append).
# Run from project root:  chmod +x scripts/wifi_stream_macos.sh && ./scripts/wifi_stream_macos.sh
# Requires: macOS with `log` command. May prompt for Full Disk Access in System Settings.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/logs/wifi.log"
mkdir -p "$(dirname "$OUT")"

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [wifi_stream] started (macOS log stream) -> $OUT" >> "$OUT"

# Filter WiFi subsystems; adjust if your OS version uses different names.
exec log stream --style compact --predicate \
  'subsystem == "com.apple.wifi" OR subsystem == "com.apple.wifi.debug" OR eventMessage CONTAINS[c] "WiFi"' \
  2>&1 | while IFS= read -r line; do
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") $line" >> "$OUT"
done
