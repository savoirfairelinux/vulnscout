#!/bin/bash
#
# Perform the following actions step by step and report status in /scan/status.txt
# 0. Start Flask API server
# 1. Extract tar files in /scan/inputs
# 2. Search for SPDX JSON files in /scan/inputs/spdx and merge them
# 3. Search for CycloneDX JSON or XML files in /scan/inputs/cdx and merge them
# 4. Scan SPDX and CDX with Grype to find vulnerabilities
# 5. Scan SPDX and CDX with OSV to find vulnerabilities
# 7. Merge all vulnerability from scan results
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only


set +e
set -m # enable job control to allow `fg` command
#set -x # Enable debugging by writing command which are executed


# Initialize variables
PRODUCT_NAME=${PRODUCT_NAME-"PRODUCT_NAME"}
PRODUCT_VERSION=${PRODUCT_VERSION-"1.0.0"}
COMPANY_NAME=${COMPANY_NAME-"Savoir-faire Linux"}
CONTACT_EMAIL=${CONTACT_EMAIL-""}
DOCUMENT_URL=${DOCUMENT_URL-"https://spdx.org/spdxdocs/${PRODUCT_NAME}-${PRODUCT_VERSION}.spdx.json"}
INTERACTIVE_MODE=${INTERACTIVE_MODE-"true"}
VERBOSE_MODE=${VERBOSE_MODE-"false"}

readonly BASE_DIR="/scan"

readonly INPUTS_PATH="$BASE_DIR/inputs"
readonly SPDX_INPUTS_PATH="$INPUTS_PATH/spdx"
readonly CDX_INPUTS_PATH="$INPUTS_PATH/cdx"
readonly YOCTO_CVE_INPUTS_PATH="$INPUTS_PATH/yocto_cve_check"

readonly TMP_PATH="$BASE_DIR/tmp"
readonly SPDX_TMP_PATH="$TMP_PATH/spdx"
readonly CDX_TMP_PATH="$TMP_PATH/cdx"
readonly YOCTO_CVE_TMP_PATH="$TMP_PATH/yocto_cve_check"

readonly OUTPUTS_PATH="$BASE_DIR/outputs"

readonly CHECKSUM_FILE="$BASE_DIR/checksum.json"
readonly CHECKSUM_NEW_FILE="$BASE_DIR/checksum.new.json"
export SKIP_VALIDATION="false"


function main() {
    cd $BASE_DIR

    set_status "0" "Computing input checksums" "0"
    compute_checksums
    finalize_checksums

    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        set_status "0" "Server started" "0"
        (cd "$BASE_DIR/src" && flask --app bin.webapp run) &
    fi

    python3 -m src.bin.epss_db_builder &
    python3 -m src.bin.nvd_db_builder &

    if [[ "${DEBUG_SKIP_SCAN-}" != "true" ]]; then
        full_scan_steps
    fi

    # 7. Merge all vulnerability from scan results
    set_status "7" "Merging vulnerability results" "0"

    python3 -m src.bin.merger_ci

    set_status "7" "<!-- __END_OF_SCAN_SCRIPT__ -->" "0"

    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        fg %?flask # Bring back process named 'flask' (flask run) to foreground.
    fi
}


function full_scan_steps() {
    # 1. Search for .tar , .tar.gz and .tar.zst files in /scan/inputs and extract them
    set_status "1" "Extracting tar files" "0"
    extract_tar_folder $INPUTS_PATH

    # 2. Search for SPDX JSON files in /scan/inputs/spdx and merge them
    if [[ -e "$SPDX_INPUTS_PATH" ]]; then
        set_status "2" "Searching SPDX JSON files" "0"

        rm -Rf $SPDX_TMP_PATH
        mkdir -p $SPDX_TMP_PATH

        copy_spdx_files $SPDX_INPUTS_PATH $SPDX_TMP_PATH

        set_status "2" "Merging $((SPDX_FILE_COUNTER-1)) SPDX files" "0"
        INPUT_SPDX_FOLDER="$SPDX_TMP_PATH" OUTPUT_SPDX_FILE="$TMP_PATH/merged.spdx.json" python3 -m src.bin.spdx_merge
    else
        set_status "2" "No SPDX files found, skipping" "0"
    fi


    # 3. Search for CycloneDX JSON or XML files in /scan/inputs/cdx and merge them
    if [[ -e "$CDX_INPUTS_PATH" ]]; then
        set_status "3" "Searching CDX JSON files" "0"

        rm -Rf $CDX_TMP_PATH
        mkdir -p $CDX_TMP_PATH

        copy_cdx_files $CDX_INPUTS_PATH $CDX_TMP_PATH

        if [[ ${#CDX_FILE_LIST[@]} -ge 1 ]]; then
            set_status "3" "Merging ${#CDX_FILE_LIST[@]} CDX files" "0"

            cyclonedx-cli merge \
                --output-file "$TMP_PATH/merged.cdx.json" \
                --output-format json \
                --name "$PRODUCT_NAME" \
                --version "$PRODUCT_VERSION" \
                --input-files "${CDX_FILE_LIST[@]}"
        else
            set_status "3" "No CDX files found, skipping" "0"
        fi
    fi

    if [[ -f "$TMP_PATH/merged.spdx.json" ]]; then
        set_status "4" "Scanning SPDX with Grype" "0"
        grype --add-cpes-if-none "sbom:$TMP_PATH/merged.spdx.json" -o json > "$TMP_PATH/vulns-spdx.grype.json"
    fi
    if [[ -f "$TMP_PATH/merged.cdx.json" ]]; then
        set_status "4" "Scanning CDX with Grype" "0"
        grype --add-cpes-if-none "sbom:$TMP_PATH/merged.cdx.json" -o json > "$TMP_PATH/vulns-cdx.grype.json"
    fi

    set_status "5" "Scanning CDX with OSV (WIP)" "0"
    if [[ -f "$TMP_PATH/merged.cdx.json" ]]; then
        osv-scanner --offline-vulnerabilities --download-offline-databases /cache/vulnscout/osv/ --sbom="$TMP_PATH/merged.cdx.json" --format json --output "$TMP_PATH/vulns-cdx.osv.json" || true
        osv-scanner --offline-vulnerabilities --download-offline-databases /cache/vulnscout/osv/ --sbom="$TMP_PATH/merged.cdx.json" --format sarif --output "$TMP_PATH/vulns-cdx.osv.sarif.json" || true
    fi

    if [[ -e "$YOCTO_CVE_INPUTS_PATH" ]]; then
        set_status "6" "Copy CVE-check result from Yocto" "0"

        rm -Rf $YOCTO_CVE_TMP_PATH
        mkdir -p $YOCTO_CVE_TMP_PATH

        copy_yocto_cve_files $YOCTO_CVE_INPUTS_PATH $YOCTO_CVE_TMP_PATH

        set_status "6" "Found $((YOCTO_CVE_FILE_COUNTER-1)) CVE files issued by Yocto CVE check" "0"
    else
        set_status "6" "No CVE check result found from Yocto" "0"
    fi
}

#######################################
# Compute SHA256 checksums for all files under INPUTS_PATH
# and write them as JSON to CHECKSUM_NEW_FILE
#######################################
function compute_checksums() {
    local folder="$INPUTS_PATH"
    local tmpfile="$BASE_DIR/checksum.tmp"
    rm -f "$tmpfile"

    # Generate a JSON object for each file
    find "$folder" -type f -print0 | sort -z | while IFS= read -r -d '' f; do
        sum=$(sha256sum "$f" | awk '{print $1}')
        jq -n --arg path "$f" --arg sum "$sum" '{($path):$sum}' >> "$tmpfile"
    done

    # Merge all JSON objects into a single JSON object under "files" key
    jq -s 'reduce .[] as $item ({}; . * $item) | {files:.}' "$tmpfile" | jq --sort-keys . > "$CHECKSUM_NEW_FILE"
    rm -f "$tmpfile"
}

#######################################
# Compare the new checksum file with the old one.
# If identical, SKIP_VALIDATION=true. Otherwise, update CHECKSUM_FILE.
#######################################
function finalize_checksums() {
    # If old checksum exists and is identical to new one
    if [[ -f "$CHECKSUM_FILE" ]] && jq --sort-keys . "$CHECKSUM_FILE" | cmp -s - "$CHECKSUM_NEW_FILE"; then
        SKIP_VALIDATION="true"
        rm -f "$CHECKSUM_NEW_FILE"
    else
        mv -f "$CHECKSUM_NEW_FILE" "$CHECKSUM_FILE"
        SKIP_VALIDATION="false"
    fi
}

#######################################
# Print status update to file + console
# Globals:
#   BASE_DIR
# Arguments:
#   Step number
#   Message to describe running step
#   Progression (0-100)
# Outputs:
#   to /scan/status.txt and console
#######################################
function set_status() { 
    local step=$1
    local message=$2
    local progress=$3

    echo "$step $message $progress" >> "$BASE_DIR/status.txt"
    echo "$message"
}


#######################################
# Read files in a folder and theses sub-folder and extract all .tar it found.
# Arguments:
#   Path to a folder
# Outputs:
#   Each .tar file is extracted in a folder named with _extracted suffix
#######################################
function extract_tar_folder() {
    local folder=$1

    mapfile -t tar_files < <(find "$folder" -type f \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tar.zst" \))
    local total_files=${#tar_files[@]}

    local count=0
    for file in "${tar_files[@]}"; do
        ((count++))
        local progress=$((count * 100 / total_files))
        set_status "1" "Extracting file $count of $total_files" "$progress"
        mkdir -p "${file}_extracted"
        extract_tar_file "$file" "${file}_extracted"
    done
}


#######################################
# Extract $1 if format is .tar, .tar.gz and .tar.zst into folder $2.
# Arguments:
#   Path to a tar file
#   Path to a folder
# Outputs:
#   If format recognized, the tar file is extracted in the folder
#######################################
function extract_tar_file() {
    local file=$1
    local folder=$2

    if [[ -z "$file" || -z "$folder" ]]; then
        echo "Usage: extract_tar_file <tar_file> <output_folder>"
        exit 1
    fi

    if [[ ! -e "$file" ]]; then # File does not exists
        echo "File $file not found"
        return
    fi

    case "$file" in
        *.tar)
            echo "Extracting $file as tar"
            tar -xf "$file" -C "$folder"
            ;;
        *.tar.gz)
            echo "Extracting $file as tar.gz"
            tar -xzf "$file" -C "$folder"
            ;;
        *.tar.zst)
            echo "Extracting $file as tar.zst"
            unzstd "$file"
            tar -xf "${file//.zst/}" -C "$folder"
            rm -f "${file//.zst/}"
            ;;
        *)
            echo "File $file is not a tar, tar.gz or tar.zst file"
            ;;
    esac
}


#######################################
# List files in a folder and theses sub-folder and copy all .spdx.json it found into $2.
# Globals:
#   SPDX_FILE_COUNTER
# Arguments:
#   Path to folder to search
#   Path to folder to copy in
# Outputs:
#   Each .spdx.json file is copied in the destination folder
#######################################
SPDX_FILE_COUNTER=1

SPDX_FILE_COUNTER=1

function copy_spdx_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_spdx_files <folder> <destination>"
        exit 1
    fi

    local total_files
    total_files=$(find "$folder" -type f -name '*.spdx.json' | wc -l)

    local current_file=1

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_spdx_files "$file" "$destination"
        else
            if [[ "$file" == *.spdx.json ]]; then
                cp "$file" "$destination/${SPDX_FILE_COUNTER}_$(basename "$file")"
                set_status "2" "Copying SPDX file $current_file of $total_files" "$(awk "BEGIN {printf \"%.2f\", ($current_file/$total_files)*100}")"
                ((SPDX_FILE_COUNTER++))
                ((current_file++))
            fi
        fi
    done
}


#######################################
# Copy all .cdx.json files in a folder and theses sub-folder into $2.
# Also copy .cdx.xml files and convert them to .cdx.json
# Globals:
#   CDX_FILE_COUNTER
#   CDX_FILE_LIST
# Arguments:
#   Path to folder to search
#   Path to folder to copy in
# Outputs:
#   destination folder contains all .cdx.json files
#######################################
CDX_FILE_COUNTER=1
CDX_FILE_LIST=()

function copy_cdx_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_cdx_files <folder> <destination>"
        exit 1
    fi

    local total_files
    total_files=$(find "$folder" -type f \( -name '*.json' -o -name '*.xml' \) | wc -l)

    local current_file=1

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_cdx_files "$file" "$destination"
        else
            local filename
            filename=$(basename "$file")

            if [[ "$file" == *.json ]]; then
                if [[ "$SKIP_VALIDATION" != "true" ]]; then
                    if [[ "$IGNORE_PARSING_ERRORS" != "true" ]]; then
                        if ! cyclonedx-cli validate --input-file "$file" --fail-on-errors &> /dev/null; then
                            echo "Skipping invalid CycloneDX JSON file: $file"
                            ((current_file++))
                            continue
                        fi
                    fi
                fi
                set_status "3" "Copying CycloneDX file $current_file of $total_files" "$(awk "BEGIN {printf \"%.2f\", ($current_file/$total_files)*100}")"
                cp "$file" "$destination/${CDX_FILE_COUNTER}_$filename"
                CDX_FILE_LIST+=("$destination/${CDX_FILE_COUNTER}_$filename")
                ((CDX_FILE_COUNTER++))
                ((current_file++))
            fi

            if [[ "$file" == *.xml ]]; then
                if [[ "$SKIP_VALIDATION" != "true" ]]; then
                    if [[ "$IGNORE_PARSING_ERRORS" != "true" ]]; then
                        if ! cyclonedx-cli validate --input-file "$file" --fail-on-errors &> /dev/null; then
                            echo "Skipping invalid CycloneDX XML file: $file"
                            ((current_file++))
                            continue
                        fi
                    fi
                fi
                new_file_name=${filename//.xml/.json}
                cyclonedx-cli convert --input-file "$file" --output-format json --output-file "$destination/${CDX_FILE_COUNTER}_$new_file_name"
                CDX_FILE_LIST+=("$destination/${CDX_FILE_COUNTER}_$new_file_name")
                set_status "3" "Copying CycloneDX file $current_file of $total_files" "$(awk "BEGIN {printf \"%.2f\", ($current_file/$total_files)*100}")"
                ((CDX_FILE_COUNTER++))
                ((current_file++))
            fi
        fi
    done
}


#######################################
# List files in a folder and theses sub-folder and copy all .json it found into $2.
# Globals:
#   YOCTO_CVE_FILE_COUNTER
# Arguments:
#   Path to folder to search
#   Path to folder to copy in
# Outputs:
#   Each .json file is copied in the destination folder
#######################################
YOCTO_CVE_FILE_COUNTER=1

YOCTO_CVE_FILE_COUNTER=1

function copy_yocto_cve_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_yocto_cve_files <folder> <destination>"
        exit 1
    fi

    local total_files
    total_files=$(find "$folder" -type f -name '*.json' | wc -l)

    local current_file=1

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_yocto_cve_files "$file" "$destination"
        else
            if [[ "$file" == *.json ]]; then
                cp "$file" "$destination/${YOCTO_CVE_FILE_COUNTER}_$(basename "$file")"
                set_status "6" "Copying Yocto CVE file $current_file of $total_files" "$(awk "BEGIN {printf \"%.2f\", ($current_file/$total_files)*100}")"
                ((YOCTO_CVE_FILE_COUNTER++))
                ((current_file++))
            fi
        fi
    done
}

main "$@"