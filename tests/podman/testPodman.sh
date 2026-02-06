#!/bin/bash
#
# Perform a succession of tests to validate the Podman image
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking

BASE_DIR="$(pwd)/tests/podman"


function main() {
    local podmanimage=$1
    local flask_port=24835

    if [[ -z "$podmanimage" ]]; then
        echo "Usage: ./testPodman <podman/image:tag>"
        exit 1
    fi

    cd "$BASE_DIR"

    verify_image_exist "$podmanimage"
    local container_id
    container_id=$(run_with_data "$podmanimage" "$flask_port" 'true')

    # shellcheck disable=SC2064 # we intentionnaly expand container_id now, so even a later change in the variable won't affect the trap
    trap "{ echo 'Exiting script, shutting down container $container_id'; podman rm -vf $container_id > /dev/null; }" EXIT

    chmod +x ./test_1_normal_operation.sh
    ./test_1_normal_operation.sh "localhost:$flask_port"

    echo "[OK, FINAL] All tests passed"
}


#######################################
# Use podman inspect exit code to check if specified image exists
# Arguments:
#   podman image name (with tag)
# Outputs:
#   exit with 0 if exist, exit with >= 1 if not
#######################################
function verify_image_exist() {
    local podmanimage=$1

    if ! podman inspect "$podmanimage" &> /dev/null; then
        echo "Image does not exist!"
        exit 2
    fi
}


#######################################
# Run podman container based on image with test data mounted
# Arguments:
#   podman image name (with tag)
#   http port to bind
#   is script should ignore parsing errors
# Outputs:
#   echo container_id in stdout
#######################################
function run_with_data() {
    local podmanimage=$1
    local flask_port=$2
    local ignore_errors=$3

    container_id="$(podman run --rm -d \
        -v "./cdx:/scan/inputs/cdx:ro" \
        -v "./spdx:/scan/inputs/spdx:ro" \
        -v "./yocto.json:/scan/inputs/yocto_cve_check/yocto.json:ro" \
        -e "FLASK_RUN_PORT=$flask_port" \
        -e "FLASK_RUN_HOST=0.0.0.0" \
        -e "IGNORE_PARSING_ERRORS=$ignore_errors" \
        -p "$flask_port:$flask_port" \
        "$podmanimage")"

    echo "$container_id"
}

main "$@"
