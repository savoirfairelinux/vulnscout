#!/bin/bash
set -euo pipefail

ROOT_DIR=$(readlink -f "$(dirname "$0")/../..")
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/podman" <<'EOF'
#!/bin/bash
set -euo pipefail

log_call() {
    printf '%q ' "$@" >> "$VULNSCOUT_TEST_LOG"
    printf '\n' >> "$VULNSCOUT_TEST_LOG"
}

case "$1" in
    ps)
        if [ -z "${VULNSCOUT_TEST_NOT_RUNNING:-}" ]; then
            echo "vulnscout"
        fi
        ;;
    cp)
        ;;
    exec)
        log_call "$@"
        exit "${VULNSCOUT_TEST_EXEC_EXIT:-0}"
        ;;
    rm|run|pull)
        log_call "$@"
        ;;
    inspect)
        log_call "$@"
        echo "${VULNSCOUT_TEST_IMAGE_VERSION:-v0.24}"
        ;;
    *)
        echo "Unexpected podman command: $*" >&2
        exit 99
        ;;
esac
EOF
chmod +x "$TEST_DIR/bin/podman"

SBOM="$TEST_DIR/input.spdx.json"
printf '{}\n' > "$SBOM"
export PATH="$TEST_DIR/bin:/usr/bin:/bin"
export VULNSCOUT_BUILD_DIR="$TEST_DIR/build"
export VULNSCOUT_TEST_LOG="$TEST_DIR/container.log"
: > "$VULNSCOUT_TEST_LOG"

reset_log() {
    : > "$VULNSCOUT_TEST_LOG"
}

# run_ok <args...>: run the wrapper with stdin off any TTY; a non-zero exit aborts the test (set -e).
run_ok() {
    reset_log
    "$ROOT_DIR/vulnscout" "$@" < /dev/null > "$TEST_DIR/stdout" 2> "$TEST_DIR/stderr"
}

assert_log() {
    if ! grep -qF -- "$1" "$VULNSCOUT_TEST_LOG"; then
        echo "Expected container call containing: $1" >&2
        cat "$VULNSCOUT_TEST_LOG" >&2
        exit 1
    fi
}

refute_log() {
    if grep -qF -- "$1" "$VULNSCOUT_TEST_LOG"; then
        echo "Unexpected container call containing: $1" >&2
        cat "$VULNSCOUT_TEST_LOG" >&2
        exit 1
    fi
}

assert_stderr() {
    if ! grep -qF -- "$1" "$TEST_DIR/stderr"; then
        echo "Expected stderr containing: $1" >&2
        cat "$TEST_DIR/stderr" >&2
        exit 1
    fi
}

refute_stderr() {
    if grep -qF -- "$1" "$TEST_DIR/stderr"; then
        echo "Unexpected stderr containing: $1" >&2
        cat "$TEST_DIR/stderr" >&2
        exit 1
    fi
}

assert_stdout() {
    if ! grep -qF -- "$1" "$TEST_DIR/stdout"; then
        echo "Expected stdout containing: $1" >&2
        cat "$TEST_DIR/stdout" >&2
        exit 1
    fi
}

# expect_fail <stderr substring> <args...>: exit 1, the message on stderr, no entrypoint call.
expect_fail() {
    local expected="$1" status=0
    shift
    reset_log
    "$ROOT_DIR/vulnscout" "$@" < /dev/null > "$TEST_DIR/stdout" 2> "$TEST_DIR/stderr" || status=$?
    if [ "$status" -ne 1 ]; then
        echo "Expected exit 1 from 'vulnscout $*', got $status." >&2
        cat "$TEST_DIR/stderr" >&2
        exit 1
    fi
    assert_stderr "$expected"
    refute_log "/scan/src/entrypoint.sh"
}


"$ROOT_DIR/vulnscout" --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --project cli --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant default --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --variant default --project cli --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --match-condition affected' "$VULNSCOUT_TEST_LOG"
if grep -q -- '--project\|--variant' "$VULNSCOUT_TEST_LOG"; then
    echo "Default scope was forwarded as explicit scope." >&2
    exit 1
fi

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --project cli --match-condition affected' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant release --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --project cli --variant release --match-condition affected' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project default --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project cli --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant release --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project cli --variant release --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --add-spdx "$SBOM" --match-condition affected
grep -q -- '--project cli --add-spdx /tmp/vulnscout_stage_input.spdx.json --match-condition affected' \
    "$VULNSCOUT_TEST_LOG"
if grep -q -- '--variant' "$VULNSCOUT_TEST_LOG"; then
    echo "Default variant was forwarded as an explicit variant." >&2
    exit 1
fi

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant default \
    --add-spdx "$SBOM" --refresh-vulnerability-data
grep -q -- \
    '--project cli --variant default --add-spdx /tmp/vulnscout_stage_input.spdx.json --refresh-vulnerability-data' \
    "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --add-spdx "$SBOM"
if grep -q -- '--refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"; then
    echo "Refresh flag was propagated when absent." >&2
    exit 1
fi

export VULNSCOUT_TEST_EXEC_EXIT=7
if "$ROOT_DIR/vulnscout" --add-spdx "$SBOM" --refresh-vulnerability-data; then
    echo "Container execution failure was not propagated." >&2
    exit 1
else
    status=$?
fi
if [[ "$status" -ne 7 ]]; then
    echo "Expected exit 7, got $status." >&2
    exit 1
fi

unset VULNSCOUT_TEST_EXEC_EXIT
DATA="$TEST_DIR/data.json"
printf '{}\n' > "$DATA"

# --- Legacy grammar: deprecation warnings ---
run_ok --refresh-vulnerability-data
assert_stderr "deprecated: --refresh-vulnerability-data (removed in v0.26); use 'vulnscout refresh'"

run_ok --add-spdx "$SBOM" --add-spdx "$SBOM"
assert_stderr "deprecated: --add-spdx (removed in v0.26); use 'vulnscout add --spdx <path>'"
if [ "$(grep -c 'deprecated: --add-spdx' "$TEST_DIR/stderr")" -ne 1 ]; then
    echo "A repeated legacy token must warn once." >&2
    exit 1
fi

export VULNSCOUT_NO_DEPRECATION_WARNING=1
run_ok --refresh-vulnerability-data
unset VULNSCOUT_NO_DEPRECATION_WARNING
refute_stderr "deprecated:"

run_ok --import-custom-vulnscout-data "$DATA" --use-current-timestamps
assert_stderr "deprecated: --use-current-timestamps (removed in v0.26); use 'vulnscout import <kind> <path> --timestamps current'"
assert_log "--project default --import-custom-vulnscout-data /tmp/vulnscout_stage_data.json --use-current-timestamps"

run_ok config LEGACY_KEY legacy-value
assert_stderr "deprecated: config (removed in v0.26); use 'vulnscout config set <key> <value>'"
grep -qx 'LEGACY_KEY=legacy-value' "$VULNSCOUT_BUILD_DIR/cache/config.env"

# Review focus 1 (legacy side): a -p value equal to a legacy token is a value, not a token.
run_ok -p list-scans --refresh-vulnerability-data
assert_log "/scan/src/entrypoint.sh --project list-scans --refresh-vulnerability-data"
refute_stderr "deprecated: list-scans"

# -p / -v are accepted in legacy calls.
run_ok -p cli -v x86 --refresh-vulnerability-data
assert_log "/scan/src/entrypoint.sh --variant x86 --project cli --refresh-vulnerability-data"

# The --perform-scans capability probe is gone (D10).
run_ok --perform-scans nvd,osv
assert_log "/scan/src/entrypoint.sh --perform-scans nvd\,osv"
refute_log "--help"

run_ok --perform-nvd-scan
assert_stderr "use 'vulnscout scan nvd'"
assert_log "/scan/src/entrypoint.sh --perform-nvd-scan"

# Legacy custom OpenVEX export keeps the entrypoint's "default" variant.
run_ok --export-custom-openvex-assessments
assert_log "/scan/src/entrypoint.sh --project default --export-custom-openvex-assessments"
refute_log "--all-variants"

# Legacy delete never prompts.
run_ok --delete-outdated
assert_log "/scan/src/entrypoint.sh --delete-outdated"

# Undocumented spellings are dropped (D4).
for dropped in perform-grype-scan perform-nvd-scan perform-osv-scan perform-sbom-cve-check-scan \
    sbom-cve-check-scan --sbom-cve-check-scan; do
    expect_fail "Unknown command: $dropped" "$dropped"
done

# --- New grammar: parser, help, lifecycle verbs ---
run_ok --help
assert_stdout "scan [types|all]"
assert_stdout "still works until v0.26"
refute_stderr "deprecated:"

run_ok
assert_stdout "Usage: vulnscout [global options] <command>"

run_ok help scan
assert_stdout "Usage: vulnscout [-p <project>] [-v <variant>] scan [types|all]"

run_ok scan --help
assert_stdout "Usage: vulnscout [-p <project>] [-v <variant>] scan [types|all]"
if [ -s "$VULNSCOUT_TEST_LOG" ]; then
    echo "Help must not call the container engine." >&2
    exit 1
fi

run_ok version
assert_stdout "VulnScout v0.24"
run_ok --version
assert_stdout "VulnScout v0.24"

run_ok update
assert_log "pull "
assert_stdout "Image already up to date (v0.24)."

run_ok stop
assert_log "rm -f vulnscout"

run_ok start
assert_log "run -d --name vulnscout"

run_ok restart
assert_log "rm -f vulnscout"
assert_log "run -d --name vulnscout"

run_ok serve
assert_log "exec vulnscout pkill -f"
assert_log "/scan/src/entrypoint.sh --serve"

expect_fail "missing command. Run 'vulnscout help' for usage." -p cli
expect_fail "Unknown command: frobnicate" frobnicate
expect_fail "Unknown command: frobnicate" frobnicate --help
expect_fail "'start' does not accept --project or --variant." -p cli start
expect_fail "'serve' does not accept --project or --variant." serve -v x86
expect_fail "'stop' does not accept argument 'now'." stop now
expect_fail "'version' does not accept option --json." version --json
expect_fail "-p requires a value." scan -p
expect_fail "--variant requires a value." --variant --dev scan

echo "Host wrapper scope tests passed."
