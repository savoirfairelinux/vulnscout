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
    info)
        echo false
        ;;
    ps)
        if [ -z "${VULNSCOUT_TEST_NOT_RUNNING:-}" ]; then
            echo "vulnscout"
        fi
        ;;
    cp)
        ;;
    exec)
        log_call "$@"
        if [ -n "${VULNSCOUT_TEST_ASSESS_BLOCK:-}" ]; then
            case " $* " in
                *" --ai-assess "*)
                    # A running assessment: "started" stands for its PID file (published once the
                    # optional gate opens); it reports and exits 1 after the expected forwarded signals.
                    if [ -n "${VULNSCOUT_TEST_ASSESS_GATE:-}" ]; then
                        for _ in $(seq 100); do
                            [ -f "$VULNSCOUT_TEST_ASSESS_BLOCK/assess-gate" ] && break
                            sleep 0.1
                        done
                    fi
                    : > "$VULNSCOUT_TEST_ASSESS_BLOCK/assess-started"
                    for _ in $(seq 100); do
                        forwarded=$(cat "$VULNSCOUT_TEST_ASSESS_BLOCK/assess-forwarded" 2>/dev/null || true)
                        if [ "$(grep -c . <<< "$forwarded")" -ge "${VULNSCOUT_TEST_ASSESS_SIGNALS:-1}" ]; then
                            echo REPORT; exit 1
                        fi
                        sleep 0.1
                    done
                    echo "no signal forwarded" >&2; exit 3 ;;
                *" sh -c "*)
                    # Like the container: nothing to signal before the PID file exists.
                    [ -f "$VULNSCOUT_TEST_ASSESS_BLOCK/assess-started" ] || exit 1
                    echo "${*: -2}" >> "$VULNSCOUT_TEST_ASSESS_BLOCK/assess-forwarded" ;;
            esac
        fi
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

refute_stdout() {
    if grep -qF -- "$1" "$TEST_DIR/stdout"; then
        echo "Unexpected stdout containing: $1" >&2
        cat "$TEST_DIR/stdout" >&2
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
assert_stderr "deprecated: --refresh-vulnerability-data (removed in v0.25); use 'vulnscout refresh'"

run_ok --add-spdx "$SBOM" --add-spdx "$SBOM"
assert_stderr "deprecated: --add-spdx (removed in v0.25); use 'vulnscout add --spdx <path>'"
if [ "$(grep -c 'deprecated: --add-spdx' "$TEST_DIR/stderr")" -ne 1 ]; then
    echo "A repeated legacy token must warn once." >&2
    exit 1
fi

export VULNSCOUT_NO_DEPRECATION_WARNING=1
run_ok --refresh-vulnerability-data
unset VULNSCOUT_NO_DEPRECATION_WARNING
refute_stderr "deprecated:"

run_ok --import-custom-vulnscout-data "$DATA" --use-current-timestamps
assert_stderr "deprecated: --use-current-timestamps (removed in v0.25); use 'vulnscout import <kind> <path> --timestamps current'"
assert_log "--project default --import-custom-vulnscout-data /tmp/vulnscout_stage_data.json --use-current-timestamps"

run_ok config LEGACY_KEY legacy-value
assert_stderr "deprecated: config (removed in v0.25); use 'vulnscout config set <key> <value>'"
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
assert_stdout "Run vulnerability scans"
refute_stdout "Examples:"
assert_stdout "still works until v0.25"
refute_stderr "deprecated:"

run_ok
assert_stdout "Usage: vulnscout [global options] <command>"

run_ok scan --help
assert_stdout "Usage: vulnscout [-p <project>] [-v <variant>] scan [scanner options] [types|all]"
assert_stdout "vulnscout scan --grype --osv --sbom-cve-check"
assert_stdout "Examples:"
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

expect_fail "missing command. Run 'vulnscout --help' for usage." --dev
expect_fail "'-p' is a command option; put it after the command" -p cli
expect_fail "'--variant' is a command option; put it after the command" --variant x86 export spdx
expect_fail "Unknown command: frobnicate" frobnicate
expect_fail "Unknown command: frobnicate" frobnicate --help
expect_fail "Unknown command: help" help
expect_fail "'refresh' --variant requires --project." refresh -v x86
refute_log "exec vulnscout"
expect_fail "'match-condition' --variant requires --project." match-condition -v x86 "cvss >= 9.0"
refute_log "exec vulnscout"
expect_fail "'start' does not accept --project or --variant." start -p cli
expect_fail "'serve' does not accept --project or --variant." serve -v x86
expect_fail "'stop' does not accept argument 'now'." stop now
expect_fail "'version' does not accept option --json." version --json
expect_fail "-p requires a value." scan -p
expect_fail "--variant requires a value." scan --variant --dev

# --- add ---
run_ok add -p demo -v x86 --spdx "$SBOM" --cve-check "$DATA"
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --add-spdx /tmp/vulnscout_stage_input.spdx.json --add-cve-check /tmp/vulnscout_stage_data.json"
refute_stderr "deprecated:"

run_ok add --spdx "$SBOM" --spdx "$SBOM" --dev
assert_log "/scan/src/entrypoint.sh --add-spdx /tmp/vulnscout_stage_input.spdx.json --add-spdx /tmp/vulnscout_stage_input.spdx.json"
refute_log "/scan/src/entrypoint.sh --project"
assert_log "DEV_MODE=true"

expect_fail "'add' needs at least one input option" add
expect_fail "'add' does not accept argument 'sbom.json'." add sbom.json
expect_fail "'add' does not accept option --format." add --format spdx
expect_fail "add --spdx requires a path." add --spdx

# Review focus 2: a missing file fails before the container is started.
export VULNSCOUT_TEST_NOT_RUNNING=1
expect_fail "file not found: $TEST_DIR/missing.json" add --spdx "$SBOM" --cdx "$TEST_DIR/missing.json"
refute_log "run -d"
unset VULNSCOUT_TEST_NOT_RUNNING

# --- scan ---
run_ok scan
assert_log "/scan/src/entrypoint.sh --perform-scans all"

run_ok scan -p demo nvd osv
assert_log "/scan/src/entrypoint.sh --project demo --perform-scans nvd\,osv"

run_ok scan grype,sbom-cve-check -v x86
assert_log "/scan/src/entrypoint.sh --variant x86 --perform-scans grype\,sbom-cve-check"

# Scanner flags select a subset; it runs in one entrypoint call (one scan run).
run_ok scan --grype --osv --sbom-cve-check
assert_log "/scan/src/entrypoint.sh --perform-scans grype\,osv\,sbom-cve-check"
if [ "$(grep -c "/scan/src/entrypoint.sh" "$VULNSCOUT_TEST_LOG")" -ne 1 ]; then
    echo "Expected one entrypoint call for a multi-scanner selection." >&2
    cat "$VULNSCOUT_TEST_LOG" >&2
    exit 1
fi

run_ok scan -p demo --sbom-cve-check --nvd --osv --nvd -v x86
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --perform-scans nvd\,osv\,sbom-cve-check"

run_ok scan --osv
assert_log "/scan/src/entrypoint.sh --perform-scans osv"

run_ok scan --all
assert_log "/scan/src/entrypoint.sh --perform-scans all"

run_ok scan --nvd --all
assert_log "/scan/src/entrypoint.sh --perform-scans all"

run_ok scan osv --grype nvd,osv
assert_log "/scan/src/entrypoint.sh --perform-scans grype\,nvd\,osv"

run_ok scan all
assert_log "/scan/src/entrypoint.sh --perform-scans all"

expect_fail "unknown scan type 'x'" scan x
expect_fail "unknown scan type 'x'" scan --nvd x
expect_fail "scan requires scan types" scan nvd,
expect_fail "'scan' does not accept option --foo. Expected --grype, --nvd, --osv, --sbom-cve-check, or --all." scan --nvd --foo
expect_fail "'scan' does not accept option --grype=x." scan --grype=x

# --- match-condition ---
run_ok match-condition affected
assert_log "/scan/src/entrypoint.sh --match-condition affected"
refute_log "--project"

run_ok match-condition -p demo affected
assert_log "/scan/src/entrypoint.sh --project demo --match-condition affected"

export VULNSCOUT_TEST_EXEC_EXIT=2
status=0
"$ROOT_DIR/vulnscout" match-condition affected < /dev/null > /dev/null 2>&1 || status=$?
unset VULNSCOUT_TEST_EXEC_EXIT
if [ "$status" -ne 2 ]; then
    echo "match-condition must exit 2 when the condition matches, got $status." >&2
    exit 1
fi

expect_fail "'match-condition' needs exactly one condition expression" match-condition
expect_fail "'match-condition' needs exactly one condition expression" match-condition a b
expect_fail "match-condition requires a non-empty condition" match-condition ""

# --- assess ---
run_ok assess --cve CVE-2024-3094 --cve CVE-2023-4863
assert_log "/scan/src/entrypoint.sh --ai-assess --cve CVE-2024-3094 --cve CVE-2023-4863"
refute_log "--project"

run_ok assess -p demo -v x86 --filter "pending and cvss >= 9" --model gpt-5 --timeout 30 --dry-run --json
assert_log '/scan/src/entrypoint.sh --project demo --ai-assess --variant x86 --filter pending\ and\ cvss\ \>=\ 9 --model gpt-5 --timeout 30 --dry-run --json'

run_ok assess -p demo -v x86 --cve CVE-1 -v arm64 -v x86
assert_log "/scan/src/entrypoint.sh --project demo --ai-assess --variant x86 --variant arm64 --variant x86 --cve CVE-1"

expect_fail "'assess' needs exactly one of --cve or --filter." assess
expect_fail "'assess' needs exactly one of --cve or --filter; to combine them, list the IDs in the filter" assess --cve CVE-1 --filter pending
expect_fail "'assess' accepts only one --filter." assess --filter pending --filter new
expect_fail "--filter requires a non-empty expression." assess --filter ""
expect_fail "invalid vulnerability ID 'bad id'." assess --cve "bad id"
expect_fail "--timeout must be a positive number of seconds." assess --cve CVE-1 --timeout 0
expect_fail "'assess' --variant requires --project." assess -v x86 --cve CVE-1
expect_fail "'assess' does not accept option --force." assess --cve CVE-1 --force

# --- assess: Ctrl-C / CI cancel / hangup reach the command in the container ---
# start_assess [stderr path]: run 'assess' in its own process group, like a foreground job in a terminal.
start_assess() {
    reset_log
    rm -f "$TEST_DIR"/assess-*
    set -m
    VULNSCOUT_TEST_ASSESS_BLOCK="$TEST_DIR" "$ROOT_DIR/vulnscout" assess --cve CVE-2024-3094 --json \
        < /dev/null > "$TEST_DIR/stdout" 2> "${1:-$TEST_DIR/stderr}" &
    wrapper=$!
    set +m
}

wait_until() {
    for _ in $(seq 100); do "$@" && return 0; sleep 0.1; done
    echo "timed out waiting for: $*" >&2
    exit 1
}

forwarded_count() { [ "$(grep -c . "$TEST_DIR/assess-forwarded" 2>/dev/null)" -ge "$1" ]; }

# signal_job <signal>: what the terminal (Ctrl-C), a CI runner or a hangup sends to the job.
signal_job() { kill "-$1" -- "-$wrapper"; }

# finish_assess <label> <forwarded signal>...: the container's report, exit 1, and the signals
# forwarded in order to the run ID that the client passed to the container.
finish_assess() {
    local label="$1" status=0 run_id expected
    shift
    wait "$wrapper" || status=$?
    run_id=$(grep -o 'VULNSCOUT_RUN_ID=host-[0-9]*-[0-9]*' "$VULNSCOUT_TEST_LOG" | head -n 1)
    run_id="${run_id#*=}"
    expected=$(printf "$run_id %s\n" "$@")
    if [ "$status" -ne 1 ] || ! grep -qx REPORT "$TEST_DIR/stdout" || [ -z "$run_id" ] ||
        [ "$(cat "$TEST_DIR/assess-forwarded")" != "$expected" ]; then
        echo "$label: expected the container's report, exit 1 and forwarded '$*', got $status" >&2
        cat "$TEST_DIR/stdout" "$TEST_DIR/assess-forwarded" "$VULNSCOUT_TEST_LOG" >&2
        exit 1
    fi
    assert_log "vulnscout-ai-assess-"
}

for signal in INT TERM HUP; do
    start_assess
    wait_until test -f "$TEST_DIR/assess-started"
    signal_job "$signal"
    finish_assess "SIG$signal" INT
done

# A second Ctrl-C stops now (SIGTERM).
export VULNSCOUT_TEST_ASSESS_SIGNALS=2
start_assess
wait_until test -f "$TEST_DIR/assess-started"
signal_job INT
wait_until forwarded_count 1
signal_job INT
finish_assess "second Ctrl-C" INT TERM
unset VULNSCOUT_TEST_ASSESS_SIGNALS

# A Ctrl-C before the assessment publishes its PID reaches nothing and does not count as the first one.
export VULNSCOUT_TEST_ASSESS_GATE=1
start_assess
wait_until grep -qF -- "--ai-assess" "$VULNSCOUT_TEST_LOG"
signal_job INT
wait_until grep -qF -- " sh -c " "$VULNSCOUT_TEST_LOG"
: > "$TEST_DIR/assess-gate"
wait_until test -f "$TEST_DIR/assess-started"
signal_job INT
finish_assess "Ctrl-C before start" INT
unset VULNSCOUT_TEST_ASSESS_GATE

# A broken stderr (closed terminal, full disk) must not stop the forwarding.
start_assess /dev/full
wait_until test -f "$TEST_DIR/assess-started"
signal_job HUP
finish_assess "SIGHUP with broken stderr" INT

# --- refresh ---
run_ok refresh
assert_log "/scan/src/entrypoint.sh --refresh-vulnerability-data"
refute_log "--project"

run_ok refresh -v x86 -p demo
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --refresh-vulnerability-data"

# Review focus 1 (new grammar): a -p value equal to a legacy token does not select the legacy grammar.
run_ok refresh -p list-scans
assert_log "/scan/src/entrypoint.sh --project list-scans --refresh-vulnerability-data"
refute_stderr "deprecated:"

# A value equal to a legacy flag is an argument of the new grammar, never a legacy action.
run_ok config set MY_VALUE --stop
refute_stderr "deprecated:"
grep -qx 'MY_VALUE=--stop' "$VULNSCOUT_BUILD_DIR/cache/config.env"
refute_log "rm"

expect_fail "'refresh' does not accept option --epss." refresh --epss

# --- asset add ---
printf 'png\n' > "$TEST_DIR/logo.png"
run_ok asset add "$TEST_DIR/logo.png" "$TEST_DIR/logo.png"
assert_log "/scan/src/entrypoint.sh --add-asset /tmp/vulnscout_stage_logo.png --add-asset /tmp/vulnscout_stage_logo.png"

expect_fail "'asset' does not accept --project or --variant." asset add -p demo "$TEST_DIR/logo.png"
expect_fail "usage: vulnscout asset add <path>..." asset remove "$TEST_DIR/logo.png"
expect_fail "'asset add' needs at least one path." asset add
expect_fail "file not found: $TEST_DIR/missing.png" asset add "$TEST_DIR/missing.png"

# --- report ---
run_ok report summary.adoc
assert_log "/scan/src/entrypoint.sh --project default --report summary.adoc"

run_ok report -p demo -v x86 summary.adoc all_assessments.adoc --format pdf
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --report summary.adoc --report all_assessments.adoc --report-format pdf"

printf '= Custom\n' > "$TEST_DIR/custom.adoc"
run_ok report "$TEST_DIR/custom.adoc"
assert_log "--report /tmp/vulnscout_stage_custom.adoc"

# Review focus 4: with --condition, a match (exit 2) still exits 0.
export VULNSCOUT_TEST_EXEC_EXIT=2
run_ok report summary.adoc --condition affected
assert_log "/scan/src/entrypoint.sh --project default --match-condition affected --report summary.adoc"
status=0
"$ROOT_DIR/vulnscout" report summary.adoc < /dev/null > /dev/null 2>&1 || status=$?
unset VULNSCOUT_TEST_EXEC_EXIT
if [ "$status" -ne 2 ]; then
    echo "Without --condition, report must propagate the entrypoint status, got $status." >&2
    exit 1
fi

export VULNSCOUT_TEST_EXEC_EXIT=1
status=0
"$ROOT_DIR/vulnscout" report summary.adoc --condition affected < /dev/null > /dev/null 2>&1 || status=$?
unset VULNSCOUT_TEST_EXEC_EXIT
if [ "$status" -ne 1 ]; then
    echo "report --condition must propagate errors other than 2, got $status." >&2
    exit 1
fi

expect_fail "'report' needs at least one template name or path." report
expect_fail "'report' needs at least one template name or path." report --format html
expect_fail "template file not found: ./missing/t.adoc" report ./missing/t.adoc
expect_fail "report --format must be pdf or html, got 'docx'." report summary.adoc --format docx
expect_fail "report --condition requires an expression." report summary.adoc --condition
expect_fail "'report' does not accept option --amend." report summary.adoc --amend

# --- export ---
run_ok export spdx cdx
assert_log "/scan/src/entrypoint.sh --project default --export-spdx --export-cdx"

run_ok export -p demo custom-openvex
assert_log "/scan/src/entrypoint.sh --project demo --export-custom-openvex-assessments --all-variants"

run_ok export -p demo -v x86 custom-openvex --amend
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --export-custom-openvex-assessments --amend"
refute_log "--all-variants"

run_ok export custom-data openvex context --amend
assert_log "/scan/src/entrypoint.sh --project default --export-custom-vulnscout-data --export-openvex --export-context --amend"

expect_fail "--amend only applies to the custom-data and custom-openvex exports." export spdx --amend
expect_fail "unknown export kind 'assessments-openvex'." export assessments-openvex
expect_fail "'export' needs at least one kind" export
expect_fail "use 'export <kind> --amend'" export custom-data amend

# --- import ---
run_ok import custom-data "$DATA"
assert_log "/scan/src/entrypoint.sh --project default --import-custom-vulnscout-data /tmp/vulnscout_stage_data.json"

run_ok import -p demo custom-data "$DATA" --timestamps original
assert_log "/scan/src/entrypoint.sh --project demo --use-original-timestamps --import-custom-vulnscout-data /tmp/vulnscout_stage_data.json"

run_ok import -p demo custom-openvex "$DATA"
assert_log "/scan/src/entrypoint.sh --project demo --all-variants --import-custom-openvex-assessments /tmp/vulnscout_stage_data.json"

run_ok import -p demo -v x86 custom-openvex "$DATA" --timestamps current
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --use-current-timestamps --import-custom-openvex-assessments /tmp/vulnscout_stage_data.json"
refute_log "--all-variants"

run_ok import context "$DATA"
assert_log "/scan/src/entrypoint.sh --import-context /tmp/vulnscout_stage_data.json"

run_ok import -p demo context "$DATA"
assert_log "/scan/src/entrypoint.sh --project demo --retarget-context --import-context /tmp/vulnscout_stage_data.json"

run_ok import -p demo -v x86 context "$DATA"
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --retarget-context --import-context /tmp/vulnscout_stage_data.json"

# Review focus 5: -v without -p fails before anything is staged.
export VULNSCOUT_TEST_NOT_RUNNING=1
expect_fail "'import context' --variant requires --project." import context -v x86 "$DATA"
refute_log "run -d"
unset VULNSCOUT_TEST_NOT_RUNNING

expect_fail "'import custom-data' does not accept --variant; variants come from the file." \
    import custom-data -v x86 "$DATA"
expect_fail "'import context' does not accept --timestamps." import context "$DATA" --timestamps original
expect_fail "--timestamps must be original or current, got 'now'." import custom-data "$DATA" --timestamps now
expect_fail "--timestamps original|current" import custom-data "$DATA" --use-current-timestamps
expect_fail "'import' does not accept argument 'extra.json'." import custom-data "$DATA" extra.json
expect_fail "'import custom-data' needs a file path." import custom-data
expect_fail "file not found: $TEST_DIR/missing.json" import custom-data "$TEST_DIR/missing.json"
expect_fail "use 'vulnscout add --spdx <path>'" import spdx "$SBOM"
expect_fail "unknown import kind 'foo'." import foo "$DATA"
expect_fail "'import' needs a kind and a path" import

# --- delete ---
# Without a terminal and without --yes, delete runs without asking (CI).
run_ok delete outdated
assert_log "/scan/src/entrypoint.sh --delete-outdated"
refute_log "--dry-run"

run_ok delete scan 42 --dry-run
assert_log "/scan/src/entrypoint.sh --dry-run --delete-scan 42"
refute_log "/scan/src/entrypoint.sh --delete-scan 42"

run_ok delete orphaned-vulnerabilities --yes
assert_log "/scan/src/entrypoint.sh --delete-orphaned-vulns"

run_ok delete empty-scans
assert_log "/scan/src/entrypoint.sh --delete-empty-scans"

expect_fail "'delete' does not accept --project or --variant." delete -p demo outdated
expect_fail "'delete scan' needs a scan ID" delete scan
expect_fail "'delete scan' needs a scan ID" delete scan --yes
expect_fail "unknown delete target 'everything'." delete everything
expect_fail "'delete' needs a target" delete
expect_fail "'delete' does not accept option -y." delete outdated -y

# On a terminal: preview, then prompt.
if command -v script > /dev/null; then
    delete_cmd="$(printf '%q ' "$ROOT_DIR/vulnscout" delete outdated)"

    reset_log
    status=0
    printf 'n\n' | SHELL=/bin/bash script -qec "$delete_cmd" /dev/null > "$TEST_DIR/stdout" 2>&1 || status=$?
    if [ "$status" -ne 1 ]; then
        echo "Declining the delete prompt must exit 1, got $status." >&2
        cat "$TEST_DIR/stdout" >&2
        exit 1
    fi
    assert_stdout "Proceed with deletion? [y/N]"
    assert_stdout "Aborted."
    assert_log "/scan/src/entrypoint.sh --dry-run --delete-outdated"
    refute_log "/scan/src/entrypoint.sh --delete-outdated"

    reset_log
    printf 'y\n' | SHELL=/bin/bash script -qec "$delete_cmd" /dev/null > "$TEST_DIR/stdout" 2>&1
    assert_log "/scan/src/entrypoint.sh --dry-run --delete-outdated"
    assert_log "/scan/src/entrypoint.sh --delete-outdated"

    reset_log
    SHELL=/bin/bash script -qec "$delete_cmd--yes" /dev/null < /dev/null > "$TEST_DIR/stdout" 2>&1
    refute_log "--dry-run"
    assert_log "/scan/src/entrypoint.sh --delete-outdated"
else
    echo "script(1) not found; skipping the delete prompt tests." >&2
fi

# --- list ---
run_ok list projects --json
assert_log "/scan/src/entrypoint.sh --list-projects --json"

run_ok list scans
assert_log "/scan/src/entrypoint.sh --list-scans"
refute_log "--json"

expect_fail "'list' does not accept --project or --variant." list -p demo scans
expect_fail "unknown list target 'variants'." list variants
expect_fail "'list' needs projects or scans." list
expect_fail "'list' does not accept option --format." list scans --format json

# --- config ---
run_ok config set NVD_API_KEY secret-value
assert_stdout "Config set: NVD_API_KEY=secret-value"

run_ok config get NVD_API_KEY
if [ "$(cat "$TEST_DIR/stdout")" != "secret-value" ]; then
    echo "config get must print only the value." >&2
    cat "$TEST_DIR/stdout" >&2
    exit 1
fi

run_ok config list
assert_stdout "NVD_API_KEY=****"
assert_stdout "LEGACY_KEY=legacy-value"
if grep -qF "secret-value" "$TEST_DIR/stdout"; then
    echo "config list must mask secret values." >&2
    exit 1
fi

run_ok config unset NVD_API_KEY
assert_stdout "Config cleared: NVD_API_KEY"
expect_fail "config key not set: NVD_API_KEY" config get NVD_API_KEY

expect_fail "invalid config key 'bad-key'" config set bad-key x
expect_fail "usage: vulnscout config set <key> <value>" config set ONLY_KEY
expect_fail "'config' does not accept --project or --variant." config list -p demo
expect_fail "unknown config action 'show'." config show
expect_fail "'config' needs get, set, unset, or list." config

echo "Host wrapper scope tests passed."
