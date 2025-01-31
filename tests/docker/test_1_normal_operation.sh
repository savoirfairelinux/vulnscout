#!/bin/bash
#
# Test the following specifications about container:
# - Server don't fail at scanning valid and invalid files with IGNORE_PARSING_ERRORS enabled
# - Scan reach a status of Completed within 60s
# - API endpoints are reachable and return expected packages and CVE.
# - Server root path respond a non-empty 200 HTML page
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking

function main () {
    local base_domain=$1
    local test_value="None"

    if [[ -z "$base_domain" ]]; then
        echo "Usage: ./test_1_normal_operation.sh <domain.com:port>"
        exit 1
    fi

    test_value=$(wait_scan_finished "$base_domain" 60)

    if [[ "$test_value" == "OK" ]]; then
        echo "[OK] Test 'server reach completed state in 60s' passed"
    else
        echo "[FAIL] Test 'server reach completed state in 60s' failed for: $test_value"
        exit 3
    fi

    local Packages_expected=("cairo@1.16.0" "busybox@1.35.0" "c-ares@1.18.1")
    test_value=$(verify_packages_list "$base_domain" "${Packages_expected[*]}")

    if [[ "$test_value" == "OK" ]]; then
        echo "[OK] Test 'verify packages list' passed"
    else
        echo "[FAIL] Test 'verify packages list' failed for: $test_value"
        exit 4
    fi

    local CVEs_expected=("CVE-2018-19876" "CVE-2022-28391" "CVE-2020-14354")
    test_value=$(verify_cve_list "$base_domain" "${CVEs_expected[*]}")

    if [[ "$test_value" == "OK" ]]; then
        echo "[OK] Test 'verify CVE list' passed"
    else
        echo "[FAIL] Test 'verify CVE list' failed for: $test_value"
        exit 5
    fi
}


#######################################
# Call packages endpoint and check if all keywords are present
# Arguments:
#   domain name with port
#   array of expected keywords
# Outputs:
#   echo "OK" in stdout if found all keywords, or error message
#######################################
function verify_packages_list() {
    local base_domain=$1
    local expected_packages=$2
    local packages=""

    packages=$(curl -s "http://$base_domain/api/packages")

    for package in $expected_packages; do
        if ! echo "$packages" | grep -q "$package"; then
            echo "Expected to find package '$package' but not found in /api/packages"
            exit 4
        fi
    done

    echo "OK"
}


#######################################
# Call vulnerabilities endpoint and check if all keywords are present
# Arguments:
#   domain name with port
#   array of expected keywords
# Outputs:
#   echo "OK" in stdout if found all keywords, or error message
#######################################
function verify_cve_list() {
    local base_domain=$1
    local expected_cves=$2
    local cves=""

    cves=$(curl -s "http://$base_domain/api/vulnerabilities")

    for cve in $expected_cves; do
        if ! echo "$cves" | grep -q "$cve"; then
            echo "Expected to find CVE '$cve' but not found in /api/vulnerabilities"
            exit 5
        fi
    done

    echo "OK"
}


#######################################
# Wait until endpoint return "Scan complete" message, or timeout reached
# Arguments:
#   domain name with port
#   timeout in seconds
# Outputs:
#   echo "OK" in stdout if scan is completed, or error message
#######################################
function wait_scan_finished() {
    local base_domain=$1
    local timeout_seconds=$2
    local elapsed_time=0

    while [[ $elapsed_time -lt $timeout_seconds ]]; do
        if curl -s "http://$base_domain/api/scan/status" | grep -q "Scan complete"; then
            break
        fi

        echo "Waiting for scan to complete... [$elapsed_time / 60 seconds]" >&2
        sleep 5
        elapsed_time=$((elapsed_time + 5))
    done

    if [[ $elapsed_time -ge $timeout_seconds ]]; then
        echo "Timeout reached"
    fi
    echo "OK"
}

main "$@"
