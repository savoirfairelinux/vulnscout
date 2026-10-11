#!/bin/bash
set -euo pipefail

ROOT_DIR=$(readlink -f "$(dirname "$0")/../..")
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/podman" <<'EOF'
#!/bin/bash
set -euo pipefail

case "$1" in
    ps)
        echo "vulnscout"
        ;;
    cp)
        ;;
    exec)
        printf '%q ' "$@" >> "$VULNSCOUT_TEST_LOG"
        printf '\n' >> "$VULNSCOUT_TEST_LOG"
        printf '%s' "${VULNSCOUT_TEST_EXEC_STDOUT:-}"
        exit "${VULNSCOUT_TEST_EXEC_EXIT:-0}"
        ;;
    *)
        echo "Unexpected podman command: $*" >&2
        exit 99
        ;;
esac
EOF
chmod +x "$TEST_DIR/bin/podman"

cat > "$TEST_DIR/bin/python3" <<'EOF'
#!/bin/bash
printf '%q ' "$@" >> "$VULNSCOUT_TEST_RUNNER_LOG"
printf 'PYTHONPATH=%s\n' "${PYTHONPATH:-}" >> "$VULNSCOUT_TEST_RUNNER_LOG"
printf 'INTERPRETER=%s\n' "$0" >> "$VULNSCOUT_TEST_RUNNER_LOG"
EOF
chmod +x "$TEST_DIR/bin/python3"

SBOM="$TEST_DIR/input.spdx.json"
printf '{}\n' > "$SBOM"
export PATH="$TEST_DIR/bin:/usr/bin:/bin"
export VULNSCOUT_BUILD_DIR="$TEST_DIR/build"
export VULNSCOUT_TEST_LOG="$TEST_DIR/container.log"

"$ROOT_DIR/vulnscout" --help | grep -q -- '--refresh-vulnerability-data'

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

WORK_DIR="$TEST_DIR/work"
mkdir -p "$WORK_DIR"
export VULNSCOUT_TEST_RUNNER_LOG="$TEST_DIR/runner.log"
# $ROOT_DIR/venv/bin/python may exist; pin the fake interpreter explicitly
export VULNSCOUT_PYTHON="$TEST_DIR/bin/python3"

expect_fail() {
    if "$@" > /dev/null 2>&1; then
        echo "Expected failure: $*" >&2
        exit 1
    fi
}

"$ROOT_DIR/vulnscout" --help | grep -q -- 'cve-assessment'

# --cve mode: runner receives IDs, container is not queried
: > "$VULNSCOUT_TEST_LOG"; : > "$VULNSCOUT_TEST_RUNNER_LOG"
"$ROOT_DIR/vulnscout" cve-assessment --cve CVE-2026-0001 --cve CVE-2026-0002 \
    --dir "$WORK_DIR" --timeout 60 --force
grep -qF -- "-m vulnscout_assess --dir $WORK_DIR --timeout 60 --force --cve CVE-2026-0001 --cve CVE-2026-0002" \
    "$VULNSCOUT_TEST_RUNNER_LOG"
grep -qF -- "PYTHONPATH=$ROOT_DIR" "$VULNSCOUT_TEST_RUNNER_LOG"
# VULNSCOUT_PYTHON is honored as the interpreter
grep -qF -- "INTERPRETER=$TEST_DIR/bin/python3" "$VULNSCOUT_TEST_RUNNER_LOG"
if [ -s "$VULNSCOUT_TEST_LOG" ]; then
    echo "--cve mode queried the container." >&2
    exit 1
fi

# --filter mode: scope forwarded, log lines ignored, IDs passed to runner
: > "$VULNSCOUT_TEST_LOG"; : > "$VULNSCOUT_TEST_RUNNER_LOG"
VULNSCOUT_TEST_EXEC_STDOUT=$'merger_ci: Start evaluating conditions\nCVE-2026-0003\n\nCVE-2026-0004\n' \
    "$ROOT_DIR/vulnscout" cve-assessment --project cli --variant release --filter "cvss >= 9.0" --dir "$WORK_DIR"
grep -qF -- '/scan/src/entrypoint.sh --project cli --variant release --list-matching cvss\ \>=\ 9.0' \
    "$VULNSCOUT_TEST_LOG"
grep -qF -- '--project cli --variant release --cve CVE-2026-0003 --cve CVE-2026-0004' "$VULNSCOUT_TEST_RUNNER_LOG"
if grep -q -- 'merger_ci' "$VULNSCOUT_TEST_RUNNER_LOG"; then
    echo "Container log line was passed as a CVE ID." >&2
    exit 1
fi

# empty filter result: message, exit 0, runner not called
: > "$VULNSCOUT_TEST_RUNNER_LOG"
out="$(VULNSCOUT_TEST_EXEC_STDOUT='' "$ROOT_DIR/vulnscout" cve-assessment --filter affected --dir "$WORK_DIR")"
[[ "$out" == *"No CVEs matched filter."* ]]
if [ -s "$VULNSCOUT_TEST_RUNNER_LOG" ]; then
    echo "Runner started for an empty filter result." >&2
    exit 1
fi

# container failure during filter resolution is propagated, runner not called
: > "$VULNSCOUT_TEST_RUNNER_LOG"
expect_fail env VULNSCOUT_TEST_EXEC_EXIT=1 "$ROOT_DIR/vulnscout" cve-assessment --filter 'bad >>>' --dir "$WORK_DIR"
if [ -s "$VULNSCOUT_TEST_RUNNER_LOG" ]; then
    echo "Runner started after filter resolution failed." >&2
    exit 1
fi

# usage errors
expect_fail "$ROOT_DIR/vulnscout" cve-assessment --dir "$WORK_DIR"
expect_fail "$ROOT_DIR/vulnscout" cve-assessment --cve CVE-2026-0001
expect_fail "$ROOT_DIR/vulnscout" cve-assessment --cve CVE-2026-0001 --dir "$TEST_DIR/missing"
expect_fail "$ROOT_DIR/vulnscout" cve-assessment --cve
expect_fail "$ROOT_DIR/vulnscout" cve-assessment --cve CVE-2026-0001 --dir "$WORK_DIR" --bogus
set +e
"$ROOT_DIR/vulnscout" cve-assessment --cve CVE-2026-0001 --filter affected --dir "$WORK_DIR" > /dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 1 ]]; then
    echo "Expected exit 1 for --cve with --filter, got $status." >&2
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

echo "Host wrapper scope tests passed."
