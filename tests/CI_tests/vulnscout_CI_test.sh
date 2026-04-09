#!/bin/bash
# CI test: invokes Flask commands directly (no Docker) since this runs inside cqfd.
set -euo pipefail

BASE_DIR=$(readlink -f "$PWD/../../")
cd "$BASE_DIR"

SPDX3="$(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json"
CVE3="$(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json"
SPDX2="$(pwd)/example/spdx2/example.rootfs.spdx.tar.zst"
CVE2="$(pwd)/example/spdx2/example.rootfs.json"

# Shared helper: fresh DB in a temp dir, merge files, then run process and return its exit code
run_scan() {
    local condition="$1"; shift   # match condition string
    local tmp_db
    tmp_db=$(mktemp -d)
    export FLASK_SQLALCHEMY_DATABASE_URI="sqlite:///${tmp_db}/vulnscout.db"
    export IGNORE_PARSING_ERRORS=true

    flask --app src.bin.webapp db upgrade
    flask --app src.bin.webapp merge --project ci --variant default "$@"

    export MATCH_CONDITION="$condition"
    local rc=0
    flask --app src.bin.webapp process || rc=$?

    unset MATCH_CONDITION FLASK_SQLALCHEMY_DATABASE_URI IGNORE_PARSING_ERRORS
    rm -rf "$tmp_db"
    return $rc
}

# Test 1: condition must be triggered (exit 2) — SPDX3 + CVE3
rc=0
run_scan "cvss >= 8.0 or (cvss >= 7.0 and epss >= 50%)" --spdx "$SPDX3" --yocto-cve "$CVE3" || rc=$?
if [ "$rc" -eq 2 ]; then
    echo "**Vulnscout condition match correctly triggered**"
else
    echo "**VulnScout condition match should have been triggered (got exit $rc)**"
    exit 1
fi

# Test 2: condition must NOT be triggered (exit 0) — SPDX3 + CVE3
rc=0
run_scan "cvss >= 11.0" --spdx "$SPDX3" --yocto-cve "$CVE3" || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "**VulnScout condition match correctly not triggered**"
else
    echo "**VulnScout condition match should not have been triggered (got exit $rc)**"
    exit 1
fi

# Test 3: condition must be triggered (exit 2) — SPDX2 archive + CVE2
rc=0
run_scan "cvss >= 9.0" --spdx "$SPDX2" --yocto-cve "$CVE2" || rc=$?
if [ "$rc" -eq 2 ]; then
    echo "**Vulnscout condition match correctly triggered**"
else
    echo "**VulnScout condition match should have been triggered (got exit $rc)**"
    exit 1
fi
