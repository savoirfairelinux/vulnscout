#!/bin/bash
# Usage: bash tests/CI_tests/helper_selinux_podman_test.sh <local VulnScout image>
set -euo pipefail

image="${1:?Pass a local image built with the current host folder helper}"
if [[ ! -r /sys/fs/selinux/enforce || "$(< /sys/fs/selinux/enforce)" != 1 ||
      "$(podman info --format '{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}}')" != "true true" ]]; then
    echo "This check requires enforcing SELinux and rootless Podman." >&2
    exit 77
fi
image="$(podman image inspect --format '{{.Id}}' "$image")"
root="$(cd "$(dirname "$0")/../.." && pwd)"
name="vulnscout-helper-$(cat /proc/sys/kernel/random/uuid)"
state="$PWD/.$name"
mkdir -m 700 -- "$state"
mkdir -- "$state/cache"
containers=()
helper() {
    env -i HOME="$HOME" PATH="$PATH" XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:?}" \
        VULNSCOUT_IMAGE="$image" VULNSCOUT_CONTAINER="$name" VULNSCOUT_BUILD_DIR="$state" \
        "$root/vulnscout" ai-context helper "$@"
}
cleanup() {
    helper stop
    for cid in "${containers[@]}"; do podman rm -ft 0 "$cid" >/dev/null; done
    rm -r -- "$state"
}
trap cleanup EXIT

for generation in 1 2; do
    cid="$(podman run -d --pull=never --network=none --name "$name" \
        --userns=keep-id:uid=0,gid=0 --user=0:0 -v "$state/cache:/cache/vulnscout:Z" \
        --entrypoint sleep "$image" infinity)"
    containers+=("$cid")
    label="$(podman inspect --format '{{.ProcessLabel}}' "$cid")"
    [[ -n "$label" && "$label" != "${previous_label:-}" ]]
    helper start
    pid="$(cat "$state/host-helper/helper.pid")"
    [[ "$pid" != "${previous_pid:-}" ]]
    podman exec "$cid" python3 /scan/src/helpers/host_mount_helper.py ping \
        --socket /cache/vulnscout/host-helper/helper.sock
    if [[ "$generation" == 1 ]]; then
        # Keep the old MCS allocation reserved while reusing the deployment name.
        podman rename "$cid" "$name-old"
        previous_label="$label"
        previous_pid="$pid"
    fi
done
echo "Confined socket connectivity passed before and after MCS label change."
