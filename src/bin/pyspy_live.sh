#!/bin/bash
#
# Attach py-spy to the running Flask server and concurrently drive every
# discovered idempotent GET route via curl from inside the container.
# Produces a speedscope-format flamegraph in /scan/outputs/profiles/.
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

DURATION="${PYSPY_DURATION:-30}"
RATE="${PYSPY_RATE:-100}"
HOST="${PYSPY_HOST:-127.0.0.1}"
PORT="${FLASK_RUN_PORT:-7275}"
OUT_DIR="${PYSPY_OUTPUT_DIR:-/scan/outputs/profiles}"
FILTER_RE="${PYSPY_FILTER:-}"

usage() {
    cat <<EOF
Usage: pyspy_live.sh [--duration N] [--filter <regex>] [--rate Hz]

Environment overrides:
  PYSPY_DURATION (default: 30 s)
  PYSPY_RATE     (default: 100 Hz)
  PYSPY_FILTER   (default: empty — hit every discovered route)
  PYSPY_HOST     (default: 127.0.0.1)
  PYSPY_OUTPUT_DIR (default: /scan/outputs/profiles)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --filter)   FILTER_RE="$2"; shift 2 ;;
        --rate)     RATE="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
    esac
done

if ! command -v py-spy &>/dev/null; then
    echo "Error: py-spy not installed in this image. Rebuild with the updated Dockerfile." >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d_%H%M%S)"
OUT_FILE="$OUT_DIR/live_${TS}.json"

# Locate the Flask worker PID. `flask run` may spawn a reloader child; pick
# the last (deepest) match so we attach to the actual request handler process.
FLASK_PID="$(pgrep -f 'flask.*src.bin.webapp.*run' | tail -n1 || true)"
if [[ -z "$FLASK_PID" ]]; then
    echo "Error: no running Flask process found. Start the server with 'vulnscout --serve' first." >&2
    exit 1
fi
echo "[pyspy/live] attaching to PID=$FLASK_PID for ${DURATION}s -> $OUT_FILE"

# Discover URLs via the bench harness (--list-only does no work, just parses url_map).
mapfile -t URLS < <(
    BENCH_ARGS=(--list-only)
    [[ -n "$FILTER_RE" ]] && BENCH_ARGS+=(--filter "$FILTER_RE")
    cd /scan && python3 -m src.bin.pyspy_bench "${BENCH_ARGS[@]}" 2>/dev/null \
        | awk -F'\t' 'NF==2 {print $2}'
)
if [[ ${#URLS[@]} -eq 0 ]]; then
    echo "Error: route discovery returned no URLs." >&2
    exit 1
fi
echo "[pyspy/live] driving ${#URLS[@]} route(s) against http://${HOST}:${PORT}"

# Start py-spy in the background.
py-spy record \
    --pid "$FLASK_PID" \
    --output "$OUT_FILE" \
    --format speedscope \
    --rate "$RATE" \
    --duration "$DURATION" &
PYSPY_PID=$!

# Drive traffic for the entire capture window. Round-robin across URLs so
# every route gets samples. Counter is appended to a tempfile per request
# (instead of held in a subshell variable) so it survives a kill from the
# parent when py-spy's --duration window closes first.
COUNT_FILE="$(mktemp)"
END_AT=$(( $(date +%s) + DURATION ))
(
    while [[ $(date +%s) -lt $END_AT ]]; do
        for url in "${URLS[@]}"; do
            curl -fsS --max-time 5 -o /dev/null "http://${HOST}:${PORT}${url}" 2>/dev/null || true
            echo . >> "$COUNT_FILE"
            [[ $(date +%s) -ge $END_AT ]] && break
        done
    done
) &
LOAD_PID=$!

wait "$PYSPY_PID"
PYSPY_EXIT=$?
kill "$LOAD_PID" 2>/dev/null || true
wait "$LOAD_PID" 2>/dev/null || true
COUNT="$(wc -c < "$COUNT_FILE" 2>/dev/null | tr -d ' ' || echo 0)"
rm -f "$COUNT_FILE"

echo "[pyspy/live] sent $COUNT request(s); profile written to $OUT_FILE (exit=$PYSPY_EXIT)"
echo "[pyspy/live] open with: https://www.speedscope.app/  (drag the JSON in)"
exit $PYSPY_EXIT
