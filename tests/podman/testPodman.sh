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
    container_id=$(start_daemon "$podmanimage" "$flask_port" 'true')

    # shellcheck disable=SC2064 # we intentionnaly expand container_id now, so even a later change in the variable won't affect the trap
    trap "{ echo 'Exiting script, shutting down container $container_id'; podman rm -vf $container_id > /dev/null; }" EXIT

    # Copy input files into the container then run scan+serve via entrypoint commands
    for f in ./spdx/*.spdx.json; do
        podman cp "$f" "$container_id:/tmp/$(basename "$f")"
    done
    for f in ./cdx/*.json; do
        podman cp "$f" "$container_id:/tmp/$(basename "$f")"
    done
    podman cp "./yocto.json" "$container_id:/tmp/yocto.json"

    podman exec "$container_id" /scan/src/entrypoint.sh \
        $(for f in ./spdx/*.spdx.json; do echo "--add-spdx /tmp/$(basename "$f")"; done) \
        $(for f in ./cdx/*.json; do echo "--add-cdx /tmp/$(basename "$f")"; done) \
        --add-cve-check /tmp/yocto.json \
        --serve &

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
# Run podman container based on image in daemon mode (no input files)
# Arguments:
#   podman image name (with tag)
#   http port to bind
#   is script should ignore parsing errors
# Outputs:
#   echo container_id in stdout
#######################################
function start_daemon() {
    local podmanimage=$1
    local flask_port=$2
    local ignore_errors=$3

    container_id="$(podman run --rm -d \
        -e "FLASK_RUN_PORT=$flask_port" \
        -e "FLASK_RUN_HOST=0.0.0.0" \
        -e "IGNORE_PARSING_ERRORS=$ignore_errors" \
        -p "$flask_port:$flask_port" \
        "$podmanimage" daemon)"

    echo "$container_id"
}

main "$@"
