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
                *" --ai-assess "*|*" --ai-review "*)
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
        case " $* " in
            *" --variant-id-only "*) echo "00000000-0000-4000-8000-000000000001" ;;
            *" --ai-context-attach --host-permit "*)
                while [[ "$1" != --host-permit ]]; do shift; done
                python3 - "$VULNSCOUT_BUILD_DIR/cache/host-helper/helper.sock" "${@:2}" <<'PY'
import json, os, socket, sys, uuid
os.chdir(os.path.dirname(sys.argv[1]))
def call(op, **params):
    with socket.socket(socket.AF_UNIX) as client:
        client.connect(os.path.basename(sys.argv[1]))
        client.sendall(json.dumps(dict(op=op, **params)).encode() + b"\n")
        reply = json.loads(client.makefile("rb").readline())
        assert reply["ok"], reply
        return reply["result"]
for mapping in sys.argv[3:]:
    alias, path = mapping.split("=", 1)
    binding = dict(variant_id="00000000-0000-4000-8000-000000000001", attachment_id=str(uuid.uuid4()),
                   alias=alias, path=path)
    staged = call("stage", **binding, host_permit=sys.argv[2])
    assert staged["path"] == path and staged["approval_proof"]
    call("activate", **binding, approval_proof=staged["approval_proof"])
PY
                ;;
            *" --ai-assess "*" --json "*|*" --ai-review "*" --json "*) echo '{"results": []}' ;;
        esac
        exit "${VULNSCOUT_TEST_EXEC_EXIT:-0}"
        ;;
    rm|pull)
        log_call "$@"
        ;;
    run)
        log_call "$@"
        if [[ "${3:-}" = --entrypoint && "${4:-}" = cat ]]; then
            cat "$VULNSCOUT_TEST_IMAGE_HELPER"
        fi
        # Like 'run -d': the new container's ID on stdout.
        [ "${2:-}" != -d ] || echo 0123456789ab
        ;;
    inspect)
        log_call "$@"
        if [[ "${*: -1}" == '{{.ProcessLabel}}' ]]; then
            echo "${VULNSCOUT_TEST_PROCESS_LABEL:-}"; exit 0
        fi
        if [[ "${*: -1}" == '{{.Image}}' && -n "${VULNSCOUT_TEST_RUNNING_IMAGE:-}" ]]; then
            echo "$VULNSCOUT_TEST_RUNNING_IMAGE"; exit 0
        fi
        echo "${VULNSCOUT_TEST_IMAGE_VERSION:-v0.24}"
        ;;
    image)
        [[ "$2" = inspect ]] || exit 99
        printf 'sha256:%064d\n' "${VULNSCOUT_TEST_IMAGE_GENERATION:-1}"
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
export VULNSCOUT_TEST_IMAGE_HELPER="$ROOT_DIR/src/helpers/host_mount_helper.py"
: > "$VULNSCOUT_TEST_LOG"

reset_log() {
    : > "$VULNSCOUT_TEST_LOG"
}

# run_ok <args...>: run the wrapper with stdin off any TTY; a non-zero exit aborts the test (set -e).
run_ok() {
    reset_log
    "$ROOT_DIR/vulnscout" "$@" < /dev/null > "$TEST_DIR/stdout" 2> "$TEST_DIR/stderr" || {
        cat "$TEST_DIR/stderr" >&2
        return 1
    }
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


DATA="$TEST_DIR/data.json"
printf '{}\n' > "$DATA"

# --- Removed legacy grammar: exit 1 naming the replacement, no entrypoint call ---
expect_fail "'--add-spdx' was removed in v0.25; use 'vulnscout add --spdx <path>'" --add-spdx "$SBOM"
assert_stderr "doc/source/cli-migration.md"
expect_fail "'--refresh-vulnerability-data' was removed in v0.25; use 'vulnscout refresh'" \
    --refresh-vulnerability-data
expect_fail "'--report' was removed in v0.25; use 'vulnscout report <template>'" \
    --project cli --variant x86 --report summary.adoc
expect_fail "'list-scans' was removed in v0.25; use 'vulnscout list scans'" list-scans
expect_fail "'--use-current-timestamps' was removed in v0.25" --use-current-timestamps
expect_fail "'--start' was removed in v0.25; use 'vulnscout start'" --dev --start
refute_log "run -d"
expect_fail "'config <key> <value>' was removed in v0.25; use 'vulnscout config set <key> <value>'" \
    config LEGACY_KEY legacy-value
if grep -q '^LEGACY_KEY=' "$VULNSCOUT_BUILD_DIR/cache/config.env" 2>/dev/null; then
    echo "A removed config call must not write the config file." >&2
    exit 1
fi

# Undocumented spellings are dropped (D4).
for dropped in perform-grype-scan perform-nvd-scan perform-osv-scan perform-sbom-cve-check-scan \
    sbom-cve-check-scan --sbom-cve-check-scan; do
    expect_fail "Unknown command: $dropped" "$dropped"
done

# --- New grammar: parser, help, lifecycle verbs ---
run_ok --help
assert_stdout "Run vulnerability scans"
refute_stdout "Examples:"
assert_stdout "was removed in v0.25"

run_ok
assert_stdout "Usage: vulnscout <command> [arguments] [options] [global options]"

run_ok scan --help
assert_stdout "Usage: vulnscout scan [-p <project>] [-v <variant>] [scanner options] [types|all]"
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
refute_stderr "was removed"

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

# With the container stopped, startup output must not corrupt the --json report on stdout.
# A fresh cache directory also covers the "Created default config" message.
export VULNSCOUT_TEST_NOT_RUNNING=1 VULNSCOUT_CACHE_DIR="$TEST_DIR/stopped-cache"
run_ok assess --cve CVE-2024-3094 --json
unset VULNSCOUT_TEST_NOT_RUNNING VULNSCOUT_CACHE_DIR
assert_log "run -d"
assert_log "/scan/src/entrypoint.sh --ai-assess --cve CVE-2024-3094 --json"
if [ "$(cat "$TEST_DIR/stdout")" != '{"results": []}' ]; then
    echo "Expected only the JSON report on stdout:" >&2
    cat "$TEST_DIR/stdout" >&2
    exit 1
fi
assert_stderr "Container not running, starting..."
assert_stderr "0123456789ab"

expect_fail "'assess' needs exactly one of --cve or --filter." assess
expect_fail "'assess' needs exactly one of --cve or --filter; to combine them, list the IDs in the filter" assess --cve CVE-1 --filter pending
expect_fail "'assess' accepts only one --filter." assess --filter pending --filter new
expect_fail "--filter requires a non-empty expression." assess --filter ""
expect_fail "invalid vulnerability ID 'bad id'." assess --cve "bad id"
expect_fail "--timeout must be a positive number of seconds." assess --cve CVE-1 --timeout 0
expect_fail "'assess' --variant requires --project." assess -v x86 --cve CVE-1
expect_fail "'assess' does not accept option --force." assess --cve CVE-1 --force

# --- assess: Ctrl-C / CI cancel / hangup reach the command in the container ---
# start_assess [stderr path]: run $START_VERB_ARGS in its own process group, like a foreground job in a terminal.
START_VERB_ARGS=(assess --cve CVE-2024-3094)
start_assess() {
    reset_log
    rm -f "$TEST_DIR"/assess-*
    set -m
    VULNSCOUT_TEST_ASSESS_BLOCK="$TEST_DIR" "$ROOT_DIR/vulnscout" "${START_VERB_ARGS[@]}" --json \
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

# 'review' reuses the same PID file and signal forwarding.
START_VERB_ARGS=(review -p demo --cve CVE-2024-3094)
start_assess
wait_until test -f "$TEST_DIR/assess-started"
signal_job INT
finish_assess "review Ctrl-C" INT
assert_log "--ai-review"
START_VERB_ARGS=(assess --cve CVE-2024-3094)

# --- review ---
UUID1=3f2b6c1e-0000-4000-8000-000000000001
UUID2=3f2b6c1e-0000-4000-8000-000000000002
run_ok review -p demo --assessment-id "$UUID1" --assessment-id "$UUID2"
assert_log "/scan/src/entrypoint.sh --project demo --ai-review --assessment-id $UUID1 --assessment-id $UUID2"

run_ok review -p demo -v x86 -v arm64 --cve CVE-2024-3094 --re-review --model gpt-5 --timeout 30 --dry-run --json
assert_log "/scan/src/entrypoint.sh --project demo --ai-review --variant x86 --variant arm64 --cve CVE-2024-3094 --re-review --model gpt-5 --timeout 30 --dry-run --json"
if [ "$(cat "$TEST_DIR/stdout")" != '{"results": []}' ]; then
    echo "Expected only the JSON report on stdout:" >&2
    cat "$TEST_DIR/stdout" >&2
    exit 1
fi

expect_fail "'review' requires --project." review --cve CVE-1
expect_fail "'review' requires --project." review --assessment-id "$UUID1"
expect_fail "'review' requires --project." review -v x86 --cve CVE-1
expect_fail "'review' requires --project." review --assessment-id nope
expect_fail "'review' requires --project." review --cve "bad id"
expect_fail "'review' needs exactly one of --assessment-id or --cve." review -p demo
expect_fail "'review' needs exactly one of --assessment-id or --cve." review -p demo --cve CVE-1 --assessment-id "$UUID1"
expect_fail "'review' --variant cannot be used with --assessment-id, which reviews every target in the project." review -p demo -v x86 --assessment-id "$UUID1"
expect_fail "invalid assessment ID 'nope'." review -p demo --assessment-id nope
expect_fail "invalid vulnerability ID 'bad id'." review -p demo --cve "bad id"
expect_fail "--timeout must be a positive number of seconds." review -p demo --cve CVE-1 --timeout 0
expect_fail "'review' does not accept option --filter." review -p demo --cve CVE-1 --filter x

# --- refresh ---
run_ok refresh
assert_log "/scan/src/entrypoint.sh --refresh-vulnerability-data"
refute_log "--project"

run_ok refresh -v x86 -p demo
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --refresh-vulnerability-data"

# A -p value equal to a removed flag is a value, not a command.
run_ok refresh -p list-scans
assert_log "/scan/src/entrypoint.sh --project list-scans --refresh-vulnerability-data"
refute_stderr "was removed"

# A value equal to a removed flag is a command argument.
run_ok config set MY_VALUE --stop
refute_stderr "was removed"
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

run_ok config set PLAIN_KEY plain-value
run_ok config list
assert_stdout "NVD_API_KEY=****"
assert_stdout "PLAIN_KEY=plain-value"
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

# --- ai-context: attached host folders ---
# Neither executable lines nor launcher settings from the shared config are host input.
app_config="$VULNSCOUT_BUILD_DIR/cache/config.env"
printf 'exit 87\nVULNSCOUT_IMAGE=cache-image\nVULNSCOUT_OUTPUTS_DIR=/unapproved\nVULNSCOUT_BIND_ADDRESS=0.0.0.0\n' >> "$app_config"
expect_fail "config key not set: VULNSCOUT_IMAGE" config get VULNSCOUT_IMAGE
run_ok config set VULNSCOUT_IMAGE operator-image
run_ok start
assert_log "operator-image daemon"
assert_log "-p 127.0.0.1:7275:7275 --tmpfs /run/vulnscout-loopback-published:ro"
refute_log "-p 7275:7275"
refute_log "/unapproved"
refute_log "cache-image"
refute_log "VULNSCOUT_BIND_ADDRESS="
run_ok config set VULNSCOUT_BIND_ADDRESS 192.0.2.10
assert_log "-p 192.0.2.10:7275:7275"
refute_log "vulnscout-loopback-published"
run_ok start
assert_log "-p 192.0.2.10:7275:7275"
refute_log "vulnscout-loopback-published"
VULNSCOUT_BIND_ADDRESS=0.0.0.0 run_ok start
assert_log "-p 0.0.0.0:7275:7275"
refute_log "vulnscout-loopback-published"
VULNSCOUT_BIND_ADDRESS=127.0.0.2 run_ok start
assert_log "-p 127.0.0.2:7275:7275 --tmpfs /run/vulnscout-loopback-published:ro"
for invalid in localhost ::1 127.0.0.1:8080 127.1 127.0.0.256 0127.0.0.1 127.00.0.1 ''; do
    expect_fail "IPv4 address" config set VULNSCOUT_BIND_ADDRESS "$invalid"
done
run_ok config get VULNSCOUT_BIND_ADDRESS
grep -Fxq '192.0.2.10' "$TEST_DIR/stdout"
VULNSCOUT_BIND_ADDRESS=invalid expect_fail "IPv4 address" restart
refute_log "rm -f"
run_ok config unset VULNSCOUT_BIND_ADDRESS
assert_log "-p 127.0.0.1:7275:7275 --tmpfs /run/vulnscout-loopback-published:ro"
VULNSCOUT_IMAGE=exported-image run_ok version
assert_log exported-image
run_ok config set VULNSCOUT_HOST_HELPER_STATE_DIR "$TEST_DIR/with spaces"
run_ok config get VULNSCOUT_HOST_HELPER_STATE_DIR
grep -Fxq "$TEST_DIR/with spaces" "$TEST_DIR/stdout"
run_ok config list
assert_stdout "VULNSCOUT_HOST_HELPER_STATE_DIR=$TEST_DIR/with spaces"
refute_stdout "/unapproved"
if grep -Fq "$TEST_DIR/with spaces" "$app_config"; then exit 1; fi
run_ok config unset VULNSCOUT_HOST_HELPER_STATE_DIR
run_ok config unset VULNSCOUT_IMAGE
ln -s "$TEST_DIR/other-cache" "$TEST_DIR/cache-alias"
(cd "$TEST_DIR" && VULNSCOUT_BUILD_DIR=build run_ok config set VULNSCOUT_CACHE_DIR cache-alias)
assert_log "-v $TEST_DIR/other-cache:/cache/vulnscout:Z"
[[ -f "$TEST_DIR/other-cache/config.env" ]]
assert_log "-v $VULNSCOUT_BUILD_DIR/outputs:/scan/outputs:Z"
run_ok config get VULNSCOUT_CACHE_DIR
grep -Fxq "$TEST_DIR/other-cache" "$TEST_DIR/stdout"
run_ok config unset VULNSCOUT_CACHE_DIR
assert_log "-v $VULNSCOUT_BUILD_DIR/cache:/cache/vulnscout:Z"
ln -sfn "$VULNSCOUT_BUILD_DIR/cache" "$TEST_DIR/cache-alias"
expect_fail "config key not set: VULNSCOUT_HOST_HELPER_STATE_DIR" config get VULNSCOUT_HOST_HELPER_STATE_DIR
expect_fail "outside container mounts" config set VULNSCOUT_OUTPUTS_DIR "$VULNSCOUT_BUILD_DIR"
# A substituted cache file must not turn the config command into a host-policy writer.
mv "$app_config" "$app_config.saved"
ln -s "$VULNSCOUT_BUILD_DIR/launcher.env" "$app_config"
expect_fail "refusing unsafe application config" config set PLAIN_KEY bad
mv -Tf "$app_config.saved" "$app_config"

expect_fail "'ai-context' needs attach, list, detach, or helper." ai-context
expect_fail "unknown ai-context action 'mount'." ai-context mount
expect_fail "invalid alias 'Bad'" ai-context attach -p demo "Bad=$TEST_DIR"
expect_fail "expected <alias>=<host path>, got 'src'." ai-context attach src
expect_fail "host folder not found: $TEST_DIR/missing" ai-context attach "src=$TEST_DIR/missing"
expect_fail "alias 'src' is given twice." ai-context attach "src=$TEST_DIR" "src=$TEST_DIR"
expect_fail "cannot attach the host root directory" ai-context attach "src=/"
expect_fail "'ai-context helper' does not accept --project or --variant." ai-context helper status -p demo
expect_fail "invalid alias '../x'" ai-context detach ../x
expect_fail "'ai-context list' does not accept option --all." ai-context list --all

run_ok ai-context list -p demo -v x86 --json
assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --ai-context-list --json"
run_ok ai-context detach -p demo src build
assert_log "/scan/src/entrypoint.sh --project demo --ai-context-detach src build"

# A host python3 older than 3.9 (here a stub failing the version check) cannot run the helper.
mkdir -p "$TEST_DIR/oldpython"
printf '#!/bin/sh\nexit 1\n' > "$TEST_DIR/oldpython/python3"
chmod +x "$TEST_DIR/oldpython/python3"
if [ "$(id -u)" -ne 0 ]; then
    PATH="$TEST_DIR/oldpython:$PATH" \
        expect_fail "host folders need python3 (3.9 or newer)" ai-context attach "src=$TEST_DIR"
fi

if command -v python3 > /dev/null && [ "$(id -u)" -ne 0 ]; then
    roots="$TEST_DIR/roots"
    mkdir -p "$roots/app" "$roots/build"
    socket="$VULNSCOUT_BUILD_DIR/cache/host-helper/helper.sock"
    state="$TEST_DIR/private-state"
    (cd "$TEST_DIR" && run_ok config set VULNSCOUT_HOST_HELPER_STATE_DIR private-state)
    run_ok config get VULNSCOUT_HOST_HELPER_STATE_DIR
    grep -Fxq "$state" "$TEST_DIR/stdout"
    trap '"$ROOT_DIR/vulnscout" ai-context helper stop > /dev/null 2>&1 || true; rm -rf "$TEST_DIR"' EXIT

    # Resolve the configured cache alias, but never resolve a link planted inside it.
    mkdir -m 755 "$TEST_DIR/not-socket-state"
    ln -s "$TEST_DIR/not-socket-state" "${socket%/*}"
    VULNSCOUT_CACHE_DIR="$TEST_DIR/cache-alias" expect_fail "helper did not start" ai-context attach "src=$roots/app"
    assert_log "/scan/src/helpers/host_mount_helper.py"
    [[ "$(stat -c %a "$TEST_DIR/not-socket-state")" == 755 && ! -e "$TEST_DIR/not-socket-state/helper.sock" ]]
    rm "${socket%/*}"
    (cd "$TEST_DIR" && VULNSCOUT_BUILD_DIR=build VULNSCOUT_CACHE_DIR=cache-alias \
        VULNSCOUT_HOST_HELPER_STATE_DIR=private-state \
        run_ok ai-context attach -p demo -v x86 "src=$roots/app/../app" "build=$roots/build")
    assert_log "/scan/src/entrypoint.sh --project demo --variant x86 --ai-context-attach --host-permit permit."
    assert_log "src=$roots/app build=$roots/build"
    assert_stdout "Host folder helper running as"
    [[ -s "$state/helper.log" && -s "$state/helper.pid" ]]
    if [ ! -S "$socket" ] || [ "$(stat -c %a "$socket")" != 600 ] ||
        [ "$(stat -c %a "$(dirname "$socket")")" != 700 ]; then
        echo "The helper socket must be owner-only inside a private directory." >&2
        ls -la "$(dirname "$socket")" >&2
        exit 1
    fi

    run_ok ai-context helper status
    refute_stdout "$roots"

    # An unchanged configuration reuses the running helper.
    pid="$(cat "$state/helper.pid")"
    run_ok config set VULNSCOUT_HOST_HELPER_STATE_DIR "$state/."
    expect_fail "before changing the host helper state directory" config set VULNSCOUT_HOST_HELPER_STATE_DIR "$roots"
    mv "$socket" "$socket.saved"
    VULNSCOUT_HOST_HELPER_STATE_DIR="$roots" \
        expect_fail "before changing the host helper state directory" config unset VULNSCOUT_HOST_HELPER_STATE_DIR
    mv "$socket.saved" "$socket"
    run_ok config get VULNSCOUT_HOST_HELPER_STATE_DIR
    grep -Fxq "$state" "$TEST_DIR/stdout"
    run_ok ai-context list
    if [ "$(cat "$state/helper.pid")" != "$pid" ]; then
        echo "The helper must not restart when its image is unchanged." >&2
        exit 1
    fi

    (
        source "$ROOT_DIR/vulnscout" --help >/dev/null
        host_helper_socket_label() { echo test-label; }
        python3() {
            local -a args=()
            while (( $# )); do
                if [[ "$1" == --socket-label ]]; then
                    [[ "$2" == test-label ]] || return 1
                    echo launch >> "$state/launches"
                    sleep 0.3   # Let the competing refresh reach the startup path.
                    shift 2
                else
                    args+=("$1"); shift
                fi
            done
            command python3 "${args[@]}"
        }
        start_host_helper > "$state/refresh1" & first=$!
        start_host_helper > "$state/refresh2" & second=$!
        wait "$first"
        wait "$second"
        [[ "$(cat "$state/launches")" == launch && "$(cat "$state/helper.pid")" != "$pid" ]]
        pid="$(cat "$state/helper.pid")"
        ai_context_helper status
        start_host_helper
        [[ "$(cat "$state/helper.pid")" == "$pid" && "$(cat "$state/launches")" == launch ]]
        ai_context_helper restart
        [[ "$(cat "$state/helper.pid")" != "$pid" ]]
        ai_context_helper status
    )
    pid="$(cat "$state/helper.pid")"

    # A rebuilt image needs a matching daemon.
    export VULNSCOUT_TEST_IMAGE_GENERATION=2 VULNSCOUT_TEST_RUNNING_IMAGE=previous
    run_ok update
    assert_log "/scan/src/helpers/host_mount_helper.py"
    [[ "$(cat "$state/helper.pid")" != "$pid" ]]
    run_ok ai-context helper status

    run_ok stop
    if [ -S "$socket" ] || [ -f "$state/helper.pid" ]; then
        echo "'vulnscout stop' must stop the host folder helper." >&2
        exit 1
    fi
    expect_fail "" ai-context helper status
    run_ok config unset VULNSCOUT_HOST_HELPER_STATE_DIR
    # First stage created a key, but activation never wrote a registry.
    # Relative state from a legacy private launcher.env must also survive daemonization.
    cd "$TEST_DIR"
    printf 'VULNSCOUT_HOST_HELPER_STATE_DIR=interrupted-stage\n' >> "$VULNSCOUT_BUILD_DIR/launcher.env"
    mkdir -m 700 interrupted-stage
    cp "$state/.approval.key" interrupted-stage/
    run_ok start
    run_ok ai-context helper status
else
    echo "python3 not found or running as root; skipping the host folder helper tests." >&2
fi

echo "Host wrapper scope tests passed."
