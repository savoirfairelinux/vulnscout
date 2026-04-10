#!/usr/bin/env bash
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# migration.sh — Migrate from the legacy docker-compose workflow to the new
# vulnscout entrypoint + SQLite database workflow.
#
# The old workflow stored input files as docker-compose volume mounts and
# exports (openvex.json, sbom.spdx.json, …) in an output directory.
# The new workflow uses the 'vulnscout' wrapper and a SQLite database.
#
# This script:
#   1. Scans <vulnscout_dir> for sub-directories that contain YAML files.
#   2. Each sub-directory name becomes the --variant for that import batch.
#   3. Parses every YAML file to extract host-side input file paths from the
#      container volume mounts under /scan/inputs/*.
#   4. If the sub-directory contains an output/openvex.json (old assessments),
#      adds it as --add-openvex so existing statuses are preserved.
#   5. Calls './vulnscout' with the discovered flags to populate the DB.
#   6. Once all imports succeed, asks whether to delete the old YAML files and
#      output directories (can be skipped with --keep-old or --remove-old).
#
# Usage:
#   ./migration.sh <vulnscout_dir> [--project <name>] [--dry-run] [--keep-old|--remove-old]
#
# Arguments:
#   <vulnscout_dir>   Path to the .vulnscout directory (contains sub-dirs with
#                     docker-compose YAML files).  Required.
#
# Options:
#   --project <name>  Project name passed to vulnscout for all imports.
#                     Defaults to the basename of <vulnscout_dir>'s parent.
#   --dry-run         Print the vulnscout commands without executing them.
#   --keep-old        Keep old YAML files and output directories after migration.
#   --remove-old      Remove old YAML files and output directories without prompting.
#   -h, --help        Show this help.

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
VULNSCOUT="$SCRIPT_DIR/vulnscout"

VULNSCOUT_DIR=""
PROJECT=""
DRY_RUN=false
CLEAN_OLD=""   # empty = ask interactively; "yes" = remove; "no" = keep

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)    PROJECT="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=true; shift ;;
        --keep-old)   CLEAN_OLD="no"; shift ;;
        --remove-old) CLEAN_OLD="yes"; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^[^#]/{ /^[^#]/d; s/^# \?//; p }' "$0"
            exit 0 ;;
        -*)
            echo "Unknown option: $1  (run with --help for usage)"; exit 1 ;;
        *)
            if [[ -z "$VULNSCOUT_DIR" ]]; then
                VULNSCOUT_DIR="$1"; shift
            else
                echo "Unexpected argument: $1"; exit 1
            fi ;;
    esac
done

if [[ -z "$VULNSCOUT_DIR" ]]; then
    sed -n '/^# Usage:/,/^[^#]/{ /^[^#]/d; s/^# \?//; p }' "$0"
    exit 0
fi

if [[ ! -d "$VULNSCOUT_DIR" ]]; then
    echo "Error: directory not found: $VULNSCOUT_DIR"
    exit 1
fi

VULNSCOUT_DIR="$(readlink -f "$VULNSCOUT_DIR")"

# Default project name = parent directory basename
if [[ -z "$PROJECT" ]]; then
    PROJECT="$(basename "$(dirname "$VULNSCOUT_DIR")")"
fi

if [[ ! -x "$VULNSCOUT" ]]; then
    echo "Error: vulnscout wrapper not found or not executable: $VULNSCOUT"
    exit 1
fi

# ---------------------------------------------------------------------------
# Inline Python: parse a single YAML compose file and return JSON with volumes
# and the detected output directory
# ---------------------------------------------------------------------------
parse_compose_yaml() {
    python3 - "$1" <<'PYEOF'
import sys, json

compose_file = sys.argv[1]

def parse_volumes_naive(path):
    """Fallback line-by-line parser when PyYAML is not available."""
    volumes = []
    environment = {}
    in_volumes = in_env = False
    with open(path) as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("volumes:"):
                in_volumes, in_env = True, False; continue
            if s.startswith("environment:"):
                in_env, in_volumes = True, False; continue
            if s.startswith("- ") and in_volumes:
                volumes.append(s[2:].strip().strip("'\""))
            elif s.startswith("- ") and in_env:
                item = s[2:].strip().strip("'\"")
                if "=" in item:
                    k, v = item.split("=", 1); environment[k] = v
            elif s and not s.startswith("#") and not s.startswith("- "):
                in_volumes = in_env = False
    return volumes, environment

try:
    import yaml
    with open(compose_file) as fh:
        data = yaml.safe_load(fh)
    svc = next(iter(data.get("services", {}).values()))
    raw_vols = svc.get("volumes", [])
    env = svc.get("environment", {})
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env if "=" in item)
except ImportError:
    raw_vols, env = parse_volumes_naive(compose_file)

# Normalise volume entries to (host, container) pairs
parsed = []
for v in raw_vols:
    if isinstance(v, dict):
        parsed.append((v.get("source", ""), v.get("target", "")))
    else:
        parts = str(v).split(":")
        parsed.append((parts[0] if len(parts) > 0 else "",
                        parts[1] if len(parts) > 1 else ""))

import os
compose_dir = os.path.dirname(os.path.abspath(compose_file))

def resolve(path):
    """Resolve path relative to the compose file's directory."""
    if not path:
        return path
    if not os.path.isabs(path):
        return os.path.normpath(os.path.join(compose_dir, path))
    return path

# Container-path prefix → vulnscout flag
TYPE_MAP = {
    "/scan/inputs/spdx/":            "--add-spdx",
    "/scan/inputs/cdx/":             "--add-cdx",
    "/scan/inputs/openvex/":         "--add-openvex",
    "/scan/inputs/yocto_cve_check/": "--add-cve-check",
}

inputs = []   # list of [flag, host_path]
output_dir = ""

for host, container in parsed:
    host = resolve(host)
    if container.rstrip("/") == "/scan/outputs":
        output_dir = host
        continue
    for prefix, flag in TYPE_MAP.items():
        if container.startswith(prefix):
            inputs.append([flag, host])
            break

print(json.dumps({"inputs": inputs, "output_dir": output_dir}))
PYEOF
}

# ---------------------------------------------------------------------------
# Ensure a clean container state before starting (stale overlay mounts can
# cause "not a directory" errors when the container is reused across sessions)
# ---------------------------------------------------------------------------
CONTAINER_NAME="${VULNSCOUT_CONTAINER:-vulnscout}"
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container '$CONTAINER_NAME' for a clean start..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
fi

# Point the vulnscout wrapper's cache and outputs at the target directory so
# the DB and config land there rather than next to the vulnscout script itself.
export VULNSCOUT_CACHE_DIR="$VULNSCOUT_DIR/cache"
export VULNSCOUT_OUTPUTS_DIR="$VULNSCOUT_DIR/outputs"

# ---------------------------------------------------------------------------
# Main loop — walk sub-directories of <vulnscout_dir>
# ---------------------------------------------------------------------------
found_any=false
found_yaml=false
cleanup_yaml_files=()
cleanup_dirs=()
cleanup_subdirs=()

while IFS= read -r -d '' yaml_file; do
    subdir="$(dirname "$yaml_file")"
    variant="$(basename "$subdir")"

    found_yaml=true
    echo "──────────────────────────────────────────────"
    echo "Variant : $variant"
    echo "YAML    : $yaml_file"

    # Parse the compose file
    parsed=$(parse_compose_yaml "$yaml_file")

    mapfile -t input_pairs < <(python3 - "$parsed" <<'PYEOF'
import sys, json
data = json.loads(sys.argv[1])
for flag, path in data["inputs"]:
    print(flag + "||" + path)
PYEOF
)
    output_dir=$(python3 - "$parsed" <<'PYEOF'
import sys, json
data = json.loads(sys.argv[1])
print(data.get("output_dir", ""))
PYEOF
)

    # Build vulnscout argument list
    vulnscout_args=(--project "$PROJECT" --variant "$variant")
    sbom_input_count=0   # count of real SBOM/CVE inputs (not just openvex/assessments)

    for pair in "${input_pairs[@]:-}"; do
        [[ -z "$pair" ]] && continue
        flag="${pair%%||*}"
        path="${pair##*||}"
        if [[ ! -f "$path" ]] && [[ ! -d "$path" ]]; then
            echo "  Warning: path not found, skipping: $path"
            continue
        fi
        echo "  $flag $path"
        vulnscout_args+=("$flag" "$path")
        # openvex-only imports are not useful without SBOM data
        [[ "$flag" != "--add-openvex" ]] && sbom_input_count=$(( sbom_input_count + 1 ))
    done

    # Re-import old assessments from openvex.json.
    # Primary source: the /scan/outputs mount declared in the compose file.
    # Fallback: a sibling output/ directory next to the compose file (the
    # natural layout when each variant has its own output folder).
    openvex_src=""
    if [[ -n "$output_dir" && -f "$output_dir/openvex.json" ]]; then
        openvex_src="$output_dir/openvex.json"
    elif [[ -f "$subdir/output/openvex.json" ]]; then
        openvex_src="$subdir/output/openvex.json"
    fi

    if [[ -n "$openvex_src" ]]; then
        echo "  --add-openvex $openvex_src  (legacy assessments)"
        vulnscout_args+=(--add-openvex "$openvex_src")
    fi

    if [[ $sbom_input_count -eq 0 ]]; then
        echo "  (no SBOM/CVE input files found — skipping variant '$variant')"
        continue
    fi

    echo ""
    echo "  Command: $VULNSCOUT ${vulnscout_args[*]}"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  (dry-run — skipping)"
    else
        "$VULNSCOUT" "${vulnscout_args[@]}"
        echo "  ✓ Import complete."

        # Collect files/dirs to clean up after all imports
        cleanup_yaml_files+=("$yaml_file")
        if [[ -n "$output_dir" && -d "$output_dir" ]]; then
            cleanup_dirs+=("$output_dir")
        fi
        if [[ -d "$subdir/output" ]]; then
            cleanup_dirs+=("$subdir/output")
        fi
        cleanup_subdirs+=("$subdir")
    fi

    found_any=true

done < <(find "$VULNSCOUT_DIR" -maxdepth 2 \
    \( -name "docker-*.yml" -o -name "docker-*.yaml" \
       -o -name "compose*.yml" -o -name "compose*.yaml" \) \
    -print0 | sort -z)

echo "──────────────────────────────────────────────"

if [[ "$found_yaml" == "false" ]]; then
    echo "No docker-compose YAML files found under $VULNSCOUT_DIR"
    exit 1
fi

if [[ "$found_any" == "false" ]]; then
    echo "Warning: YAML files were found but all variants were skipped (no SBOM/CVE input files)."
    echo "Check that the input paths in the compose files are accessible."
    exit 1
fi

if [[ "$DRY_RUN" == "false" ]]; then
    echo ""
    echo "Migration complete. Run 'export VULNSCOUT_BUILD_DIR=\"$VULNSCOUT_DIR\" && ./vulnscout serve' to browse the imported data."

    # -----------------------------------------------------------------------
    # Cleanup prompt
    # -----------------------------------------------------------------------
    if [[ ${#cleanup_yaml_files[@]} -gt 0 || ${#cleanup_dirs[@]} -gt 0 ]]; then
        if [[ -z "$CLEAN_OLD" ]]; then
            echo ""
            echo "The following legacy files/directories are no longer needed:"
            for f in "${cleanup_yaml_files[@]}"; do echo "  $f"; done
            for d in "${cleanup_dirs[@]}";      do echo "  $d/"; done
            read -r -p "Delete them now? [y/N] " _answer
            case "$_answer" in
                [Yy]*) CLEAN_OLD="yes" ;;
                *)     CLEAN_OLD="no"  ;;
            esac
        fi

        if [[ "$CLEAN_OLD" == "yes" ]]; then
            echo "Cleaning up legacy artefacts..."
            for f in "${cleanup_yaml_files[@]}"; do
                echo "  Removing $f"
                rm -f "$f"
            done
            for d in "${cleanup_dirs[@]}"; do
                echo "  Removing $d"
                rm -rf "$d"
            done
            # Remove sub-directories that are now empty
            for subdir in "${cleanup_subdirs[@]}"; do
                if [[ -d "$subdir" ]] && [[ -z "$(find "$subdir" -mindepth 1 -print -quit)" ]]; then
                    echo "  Removing empty dir $subdir"
                    rmdir "$subdir"
                fi
            done
        else
            echo "Legacy files kept."
        fi
    fi
fi
