#!/bin/bash
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking
set -m # enable job control to allow `fg` command

CONFIG_FILE="${VULNSCOUT_CONFIG:-/etc/vulnscout/config.env}"
INPUTS_DIR="/scan/inputs"
VARIANT_NAME="default"
PROJECT_NAME="default"

readonly BASE_DIR="/scan"
INTERACTIVE_MODE="${INTERACTIVE_MODE:-false}"
DEV_MODE="${DEV_MODE:-false}"

# Load config file if present
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
fi

show_help() {
    cat <<EOF
VulnScout Entrypoint
Usage: docker exec <container> /scan/src/entrypoint.sh [COMMAND] [OPTIONS]

Setting:
  --project <name>          Project name for the next input command (default: 'default')
  --variant <name>          Variant name for the next input command (default: 'default')

Input commands:
  --add-spdx <path>         Add an SPDX 2/3 SBOM file or archive
  --add-cve-check <path>    Add a Yocto CVE check JSON file
  --add-openvex <path>      Add an OpenVEX JSON file
  --add-cdx <path>          Add a CycloneDX file
  --add-report-template <path>  Add a custom report template to /scan/templates/
  --perform-grype-scan      Perform a Grype scan on the added inputs

Scan & output commands:
  --serve                   Run scan then start interactive web UI (port 7275)
  --report <template>       Generate a report from a template in /scan/templates/
  --export-spdx             Export project as SPDX 3.0 SBOM to /scan/outputs/
  --export-cdx              Export project as CycloneDX 1.6 SBOM to /scan/outputs/
  --export-openvex          Export project as OpenVEX document to /scan/outputs/
  --match-condition <expr>  Exit code 2 if condition met (e.g. "cvss >= 9.0")

Configuration commands:
  --config <key> <value>    Set a persistent config value
  --config-list             Show current configuration
  --config-clear <key>      Remove a config key

Container lifecycle:
  --help, -h                Show this help message

Examples:
  /scan/src/entrypoint.sh --project test --variant x86 --add-cve-check ./cve.json --add-spdx ./sbom.json
  /scan/src/entrypoint.sh --project test scan --match-condition "cvss >= 9.0"
  /scan/src/entrypoint.sh --project test --variant x86 scan --match-condition "cvss >= 9.0"
  /scan/src/entrypoint.sh --serve
  /scan/src/entrypoint.sh --report summary.adoc
  /scan/src/entrypoint.sh --config NVD_API_KEY abc123

Exit codes:
  0   Success
  1   Execution error
  2   Match condition triggered
EOF
}

setup_user() {
    if [ -n "${USER_UID:-}" ] && [ -n "${USER_GID:-}" ]; then
        groupadd -og "$USER_GID" -f builders 2>/dev/null || true
        if ! id -u builder &>/dev/null; then
            useradd -s /bin/sh -oN -u "$USER_UID" -g "$USER_GID" -d /builder builder
        fi
        mkdir -p /builder
        chown "$USER_UID:$USER_GID" /builder /scan /cache
    fi
}

#######################################
# Extract a .tar, .tar.gz or .tar.zst file into a given folder
#######################################
extract_tar_file() {
    local file="$1"
    local folder="$2"
    case "$file" in
        *.tar)     tar -xf "$file" -C "$folder" ;;
        *.tar.gz)  tar -xzf "$file" -C "$folder" ;;
        *.tar.zst)
            unzstd "$file" -o "${file%.zst}" --force
            tar -xf "${file%.zst}" -C "$folder"
            rm -f "${file%.zst}"
            ;;
        *) echo "Unsupported archive format: $file"; return 1 ;;
    esac
}

cmd_add_file() {
    local type="$1"
    local src="$2"
    mkdir -p "$INPUTS_DIR/$type"

    # For SPDX inputs, archives (.tar/.tar.gz/.tar.zst) must be extracted first
    if [[ "$type" == "spdx" ]] && [[ "$src" == *.tar || "$src" == *.tar.gz || "$src" == *.tar.zst ]]; then
        local tmp_extract
        tmp_extract=$(mktemp -d)
        echo "Extracting SPDX archive: $src"
        extract_tar_file "$src" "$tmp_extract"
        local count=0
        while IFS= read -r -d '' f; do
            cp "$f" "$INPUTS_DIR/$type/$(basename "$f")"
            echo "Added spdx input (from archive): $INPUTS_DIR/$type/$(basename "$f")"
            count=$(( count + 1 ))
        done < <(find "$tmp_extract" -name "*.spdx.json" -print0)
        rm -rf "$tmp_extract"
        if [[ $count -eq 0 ]]; then
            echo "Warning: no .spdx.json files found inside archive $src"
        fi
    else
        local dest="$INPUTS_DIR/$type/$(basename "$src")"
        cp "$src" "$dest"
        echo "Added $type input: $dest"
    fi
}

cmd_add_report_template() {
    local src="$1"
    local dest_name
    dest_name="$(basename "$src")"
    dest_name="${dest_name#vulnscout_stage_}"  # strip staging prefix added by the wrapper
    mkdir -p "/scan/templates"
    cp "$src" "/scan/templates/$dest_name"
    echo "Added report template: /scan/templates/$dest_name"
}



cmd_scan() {
    # Export all variables from config file
    if [ -f "$CONFIG_FILE" ]; then
        while IFS='=' read -r key value; do
            [ -z "$key" ] || [ "${key#\#}" != "$key" ] && continue
            export "$key=$value"
        done < "$CONFIG_FILE"
    fi

    # Pass config values as env vars to scan.sh
    export PRODUCT_NAME="${PRODUCT_NAME:-}"
    export PRODUCT_VERSION="${PRODUCT_VERSION:-}"
    export AUTHOR_NAME="${AUTHOR_NAME:-}"
    export CONTACT_EMAIL="${CONTACT_EMAIL:-}"
    export DOCUMENT_URL="${DOCUMENT_URL:-}"
    export NVD_API_KEY="${NVD_API_KEY:-}"
    export HTTP_PROXY="${HTTP_PROXY:-}"
    export HTTPS_PROXY="${HTTPS_PROXY:-}"
    export NO_PROXY="${NO_PROXY:-}"
    export IGNORE_PARSING_ERRORS="${IGNORE_PARSING_ERRORS:-false}"

    if [[ -n "${MATCH_CONDITION:-}" ]]; then
        export MATCH_CONDITION
        export INTERACTIVE_MODE="false"
    fi

    cd $BASE_DIR

    # 0. Run server to start page
    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        set_status "0" "Server started"
        FLASK_ARGS=(--app src.bin.webapp run)
        if [[ "${DEV_MODE}" == "true" ]]; then
            FLASK_ARGS+=(--debug)
        fi
        (cd "$BASE_DIR" && flask "${FLASK_ARGS[@]}") &
    fi

    python3 -m src.bin.epss_db_builder &

    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        python3 -m src.bin.nvd_db_builder &
    else
        set_status "0" "NVD sync skipped in CI Mode"
    fi

    # All input files belong to a single variant set for this invocation
    PROJECT_NAME=${PROJECT_NAME:-"$PRODUCT_NAME"}
    VARIANT_NAME=${VARIANT_NAME:-"default"}
    INIT_APP_ARGS=(--project "$PROJECT_NAME" --variant "$VARIANT_NAME")
    if [[ -d "$INPUTS_DIR/spdx" ]]; then
        for f in "$INPUTS_DIR/spdx"/*.spdx.json; do [[ -f "$f" ]] && INIT_APP_ARGS+=(--spdx "$f"); done
    fi
    if [[ -d "$INPUTS_DIR/cdx" ]]; then
        for f in "$INPUTS_DIR/cdx"/*.json; do [[ -f "$f" ]] && INIT_APP_ARGS+=(--cdx "$f"); done
    fi
    if [[ -d "$INPUTS_DIR/openvex" ]]; then
        for f in "$INPUTS_DIR/openvex"/*openvex*.json; do [[ -f "$f" ]] && INIT_APP_ARGS+=(--openvex "$f"); done
    fi
    if [[ -d "$INPUTS_DIR/yocto_cve_check" ]]; then
        for f in "$INPUTS_DIR/yocto_cve_check"/*.json; do [[ -f "$f" ]] && INIT_APP_ARGS+=(--yocto-cve "$f"); done
    fi
    if [[ -d "$INPUTS_DIR/grype" ]]; then
        for f in "$INPUTS_DIR/grype"/*.grype.json; do [[ -f "$f" ]] && INIT_APP_ARGS+=(--grype "$f"); done
    fi
    (cd "$BASE_DIR" && flask --app src.bin.webapp db upgrade)

    # INIT_APP_ARGS always starts with --project <name> --variant <name> (4 elements).
    # Has new input files when length > 4.
    local has_inputs=false
    local has_condition=false
    local _cmd_scan_exit=0
    [[ ${#INIT_APP_ARGS[@]} -gt 4 ]]     && has_inputs=true
    [[ -n "${MATCH_CONDITION:-}" ]]       && has_condition=true

    if [[ "$has_inputs" == "true" ]] || [[ "$has_condition" == "true" ]] || [[ "${GRYPE_SCAN_REQUESTED:-false}" == "true" ]]; then
        if [[ "$has_inputs" == "true" ]]; then
            if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
                set_status "1" "Merging inputs and processing vulnerabilities"
            fi
            (cd "$BASE_DIR" && flask --app src.bin.webapp merge "${INIT_APP_ARGS[@]}")
        fi

        # If a Grype scan was requested, export the current DB as SPDX (which
        # already contains any just-merged inputs), run grype on it, then merge
        # the Grype results back in before running process.
        if [[ "${GRYPE_SCAN_REQUESTED:-false}" == "true" ]]; then
            local grype_tmp
            grype_tmp=$(mktemp -d)
            echo "Exporting current project as CycloneDX for Grype scan..."
            (cd "$BASE_DIR" && flask --app src.bin.webapp export --format cdx16 --output-dir "$grype_tmp")
            local exported_cdx="$grype_tmp/sbom_cyclonedx_v1_6.cdx.json"
            if [[ -f "$exported_cdx" ]]; then
                mkdir -p "$INPUTS_DIR/grype"
                local grype_out="$INPUTS_DIR/grype/grype_from_db.grype.json"
                echo "Grype scan: $exported_cdx -> $grype_out"
                grype --add-cpes-if-none "sbom:$exported_cdx" -o json > "$grype_out"
                echo "Merging Grype results..."
                (cd "$BASE_DIR" && flask --app src.bin.webapp merge \
                    --project "$PROJECT_NAME" --variant "$VARIANT_NAME" --grype "$grype_out")
                has_inputs=true
            else
                echo "Warning: CycloneDX export produced no file, skipping Grype scan."
            fi
            rm -rf "$grype_tmp"
        fi

        # merger_ci.py emits lines of the form  ::STATUS::<step>::<message>
        # which are intercepted here to drive set_status; everything else is
        # passed through to stdout unchanged.
        # With set -o pipefail the non-zero exit code from flask (e.g. 2 for a
        # triggered fail condition) is still propagated through the pipeline.
        (cd "$BASE_DIR" && flask --app src.bin.webapp process) | \
            while IFS= read -r _line; do
                if [[ "$_line" =~ ^::STATUS::([0-9]+)::(.*)$ ]]; then
                    set_status "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
                else
                    echo "$_line"
                fi
            done || _cmd_scan_exit=$?
        if [[ "$has_inputs" == "true" ]]; then
            # Clean up input files now that they are fully processed
            for _type in spdx cdx openvex yocto_cve_check grype osv; do
                rm -f "${INPUTS_DIR:?}/$_type"/*
            done
            # Also clean up any staged temp files
            rm -f /tmp/vulnscout_stage_*
        fi
    elif [[ "${INTERACTIVE_MODE}" == "true" ]] && [[ "$has_inputs" == "false" ]]; then
        set_status "1" "No new input files to merge, skipping"
    fi

    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        set_status "2" "<!-- __END_OF_SCAN_SCRIPT__ -->"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "---------- Initialization Done - Loading is over and WebUI is ready ----------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        fg %?flask 2>/dev/null || true # Bring back process named 'flask' (flask run) to foreground.
    fi
    return $_cmd_scan_exit
}

cmd_serve() {
    export INTERACTIVE_MODE="true"
}

cmd_report() {
    local template="$1"
    setup_user
    cd "$BASE_DIR"
    local output_dir="${OUTPUTS_DIR:-/scan/outputs}"
    flask --app src.bin.webapp db upgrade
    flask --app src.bin.webapp report "$template" --output-dir "$output_dir"
}

cmd_export() {
    local fmt="$1"
    setup_user
    cd "$BASE_DIR"
    local output_dir="${OUTPUTS_DIR:-/scan/outputs}"
    flask --app src.bin.webapp db upgrade
    flask --app src.bin.webapp export --format "$fmt" --output-dir "$output_dir"
}

cmd_config_list() {
    if [ -f "$CONFIG_FILE" ]; then
        echo "Config ($CONFIG_FILE):"
        sed 's/\(API_KEY\|PASSWORD\|SECRET\)=.*/\1=****/' "$CONFIG_FILE"
    else
        echo "No config file found at $CONFIG_FILE"
    fi
}

cmd_config_set() {
    local key="$1"
    local value="$2"
    mkdir -p "$(dirname "$CONFIG_FILE")"
    touch "$CONFIG_FILE"
    grep -v "^${key}=" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE" || true
    echo "${key}=${value}" >> "$CONFIG_FILE"
    echo "Config: set ${key}"
}

cmd_config_clear() {
    local key="$1"
    if [ -f "$CONFIG_FILE" ]; then
        grep -v "^${key}=" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        echo "Config: removed ${key}"
    else
        echo "No config file found at $CONFIG_FILE"
    fi
}

cmd_list_projects() {
    cd /scan/src
    flask --app bin.webapp list-projects
}

cmd_daemon() {
    setup_user
    echo "VulnScout ready. Use '/scan/src/entrypoint.sh --help' for available commands."
    tail -f /dev/null
}

cmd_clear_inputs() {
    rm -f "$INPUTS_DIR"/*/*
    echo "Cleared all inputs"
}

#######################################
# Print status update to file + console
# Globals:
#   BASE_DIR
# Arguments:
#   Step number
#   Message to describe running step
# Outputs:
#   to /scan/status.txt and console
#######################################
function set_status() {
    local step=$1
    local message=$2

    echo "$step $message" >> "$BASE_DIR/status.txt"
    echo "Step ($step/2): $message"
}

INPUTS_ADDED=false
MATCH_CONDITION=""
SERVE_REQUESTED=false
GRYPE_SCAN_REQUESTED=false
REPORT_TEMPLATES=()
EXPORT_FORMATS=()
SCAN_REQUIRED=false

if [[ $# -eq 0 ]]; then
    cmd_daemon
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            show_help; exit 0 ;;
        --project)
            PROJECT_NAME="$2"; shift 2 ;;
        --variant)
            VARIANT_NAME="$2"; shift 2 ;;
        --match-condition)
            if [[ "$SERVE_REQUESTED" == "true" ]]; then
                echo "Error: --serve and --match-condition are incompatible."; exit 1
            fi
            MATCH_CONDITION="$2"; SCAN_REQUIRED=true; shift 2 ;;
        --add-spdx)
            cmd_add_file spdx "$2"; INPUTS_ADDED=true; SCAN_REQUIRED=true; shift 2 ;;
        --add-cve-check)
            cmd_add_file yocto_cve_check "$2"; INPUTS_ADDED=true; SCAN_REQUIRED=true; shift 2 ;;
        --add-openvex)
            cmd_add_file openvex "$2"; INPUTS_ADDED=true; SCAN_REQUIRED=true; shift 2 ;;
        --add-cdx)
            cmd_add_file cdx "$2"; INPUTS_ADDED=true; SCAN_REQUIRED=true; shift 2 ;;
        --add-report-template)
            cmd_add_report_template "$2"; shift 2 ;;
        --perform-grype-scan)
            GRYPE_SCAN_REQUESTED=true; SCAN_REQUIRED=true; shift ;;
        --clear-inputs)
            cmd_clear_inputs; shift ;;
        --serve)
            if [[ -n "$MATCH_CONDITION" ]]; then
                echo "Error: --serve and --match-condition are incompatible."; exit 1
            fi
            SERVE_REQUESTED=true; SCAN_REQUIRED=true
            shift; cmd_serve "$@" ;;
        daemon)
            cmd_daemon; exit 0 ;;
        --report)
            REPORT_TEMPLATES+=("$2"); shift 2 ;;
        --export-spdx)
            EXPORT_FORMATS+=("spdx3"); shift ;;
        --export-cdx)
            EXPORT_FORMATS+=("cdx16"); shift ;;
        --export-openvex)
            EXPORT_FORMATS+=("openvex"); shift ;;
        --list-projects)
            cmd_list_projects; exit 0 ;;
        --config)
            cmd_config_set "$2" "$3"; shift 3 ;;
        --config-list)
            cmd_config_list; exit 0 ;;
        --config-clear)
            cmd_config_clear "$2"; shift 2 ;;
        *)
            echo "Unknown command: $1"; echo "Run --help for usage."; exit 1 ;;
    esac
done

# Step 1: Scan the new inputs/match condition if any 
match_exit=0
if [[ "$SCAN_REQUIRED" == "true" ]]; then
    cmd_scan || match_exit=$?
fi

# Step 2: Generate reports if requested (all in a single flask call to avoid re-evaluating condition)
if [[ ${#REPORT_TEMPLATES[@]} -gt 0 ]]; then
    _first_tpl="${REPORT_TEMPLATES[0]}"
    if [[ ${#REPORT_TEMPLATES[@]} -gt 1 ]]; then
        _extra="${REPORT_TEMPLATES[*]:1}"
        export GENERATE_DOCUMENTS="${_extra// /,}"
    fi
    cmd_report "$_first_tpl"
    unset GENERATE_DOCUMENTS
fi
rm -f /tmp/vulnscout_matched_vulns.json

# Step 3: Export SBOM in requested formats
for _fmt in "${EXPORT_FORMATS[@]:-}"; do
    [[ -n "$_fmt" ]] && cmd_export "$_fmt"
done

exit $match_exit
