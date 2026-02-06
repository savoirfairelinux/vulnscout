#!/bin/bash
#
# Perform the following actions step by step and report status in /scan/status.txt
# 0. Start Flask API server
# 1. Extract tar files in /scan/inputs
# 2. Search for SPDX JSON files in /scan/inputs/spdx and merge them
# 3. Search for OPENVEX files in /scan/inputs/openvex and merge them
# 4. Search for CycloneDX JSON or XML files in /scan/inputs/cdx and merge them
# 5. Scan SPDX and CDX with Grype to find vulnerabilities
# 6. Scan SPDX and CDX with OSV to find vulnerabilities
# 7. Copy CVE-check result from Yocto
# 8. Merge all vulnerability from scan results
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only


set -euo pipefail # Enable error checking
set -m # enable job control to allow `fg` command
#set -x # Enable debugging by writing command which are executed


# Initialize variables
PRODUCT_NAME=${PRODUCT_NAME-"PRODUCT_NAME"}
PRODUCT_VERSION=${PRODUCT_VERSION-"1.0.0"}
AUTHOR_NAME=${AUTHOR_NAME-"Savoir-faire Linux"}
CONTACT_EMAIL=${CONTACT_EMAIL-""}
DOCUMENT_URL=${DOCUMENT_URL-"https://spdx.org/spdxdocs/${PRODUCT_NAME}-${PRODUCT_VERSION}.spdx.json"}
INTERACTIVE_MODE=${INTERACTIVE_MODE-"true"}
VERBOSE_MODE=${VERBOSE_MODE-"false"}
VULNSCOUT_VERSION=${VULNSCOUT_VERSION-"unknown"}

echo "VulnScout $VULNSCOUT_VERSION"

readonly BASE_DIR="/scan"

readonly INPUTS_PATH="$BASE_DIR/inputs"
readonly SPDX_INPUTS_PATH="$INPUTS_PATH/spdx"
readonly CDX_INPUTS_PATH="$INPUTS_PATH/cdx"
readonly OPENVEX_INPUTS_PATH="$INPUTS_PATH/openvex"
readonly YOCTO_CVE_INPUTS_PATH="$INPUTS_PATH/yocto_cve_check"

readonly TMP_PATH="$BASE_DIR/tmp"
readonly SPDX_TMP_PATH="$TMP_PATH/spdx"
readonly CDX_TMP_PATH="$TMP_PATH/cdx"
readonly OPENVEX_TMP_PATH="$TMP_PATH/openvex"
readonly YOCTO_CVE_TMP_PATH="$TMP_PATH/yocto_cve_check"

readonly OUTPUTS_PATH="$BASE_DIR/outputs"


function main() {
    cd $BASE_DIR


    # 0. Run server to start page
    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        set_status "0" "Server started"
        (cd "$BASE_DIR/src" && flask --app bin.webapp run) &
    fi

    python3 -m src.bin.epss_db_builder &

    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        python3 -m src.bin.nvd_db_builder &
    else
        set_status "0" "NVD sync skipped in CI Mode"
    fi

    if [[ "${DEBUG_SKIP_SCAN-}" != "true" ]]; then
        full_scan_steps
    fi

    # 8. Merge all vulnerability from scan results
    set_status "8" "Merging vulnerability results"

    python3 -m src.bin.merger_ci

    set_status "8" "<!-- __END_OF_SCAN_SCRIPT__ -->"

    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "---------- Initialization Done - Loading is over and WebUI is ready ----------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        echo "------------------------------------------------------------------------------"
        fg %?flask # Bring back process named 'flask' (flask run) to foreground.
    fi
}


function full_scan_steps() {
    # 1. Search for .tar , .tar.gz and .tar.zst files in /scan/inputs and extract them
    set_status "1" "Extracting tar files"
    extract_tar_folder $INPUTS_PATH

    # 2. Search for SPDX JSON files in /scan/inputs/spdx and merge them
    if [[ -e "$SPDX_INPUTS_PATH" ]]; then
        set_status "2" "Searching SPDX JSON files"

        rm -Rf $SPDX_TMP_PATH
        mkdir -p $SPDX_TMP_PATH

        copy_spdx_files $SPDX_INPUTS_PATH $SPDX_TMP_PATH

        set_status "2" "Merging $((SPDX_FILE_COUNTER-1)) SPDX files"
        INPUT_SPDX_FOLDER="$SPDX_TMP_PATH" OUTPUT_SPDX_FILE="$TMP_PATH/merged.spdx.json" python3 -m src.bin.spdx_merge
    else
        set_status "2" "No SPDX files found, skipping"
    fi

    # 3. Search for OPENVEX files in /scan/inputs/openvex and merge them
    if [[ -e "$OPENVEX_INPUTS_PATH" ]]; then
        set_status "3" "Searching OPENVEX files"

        rm -Rf $OPENVEX_TMP_PATH
        mkdir -p $OPENVEX_TMP_PATH

        copy_openvex_files $OPENVEX_INPUTS_PATH $OPENVEX_TMP_PATH

        set_status "3" "Merging $((OPENVEX_FILE_COUNTER-1)) OPENVEX files"
        INPUT_OPENVEX_FOLDER="$OPENVEX_TMP_PATH" OUTPUT_OPENVEX_FILE="$TMP_PATH/merged.openvex.json" python3 -m src.bin.openvex_merge
    else
        set_status "3" "No OPENVEX files found, skipping"
    fi

    # 4. Search for CycloneDX JSON or XML files in /scan/inputs/cdx and merge them
    if [[ -e "$CDX_INPUTS_PATH" ]]; then
        set_status "4" "Searching CDX JSON files"

        rm -Rf $CDX_TMP_PATH
        mkdir -p $CDX_TMP_PATH

        copy_cdx_files $CDX_INPUTS_PATH $CDX_TMP_PATH

        if [[ ${#CDX_FILE_LIST[@]} -ge 1 ]]; then
            set_status "4" "Merging ${#CDX_FILE_LIST[@]} CDX files"

            cyclonedx-cli merge \
                --output-file "$TMP_PATH/merged.cdx.json" \
                --output-format json \
                --name "$PRODUCT_NAME" \
                --version "$PRODUCT_VERSION" \
                --input-files "${CDX_FILE_LIST[@]}"
        else
            set_status "4" "No CDX files found, skipping"
        fi
    fi

    if [[ -f "$TMP_PATH/merged.spdx.json" ]]; then
        set_status "5" "Scanning SPDX with Grype"
        grype --add-cpes-if-none "sbom:$TMP_PATH/merged.spdx.json" -o json > "$TMP_PATH/vulns-spdx.grype.json"
    fi
    if [[ -f "$TMP_PATH/merged.cdx.json" ]]; then
        set_status "5" "Scanning CDX with Grype"
        grype --add-cpes-if-none "sbom:$TMP_PATH/merged.cdx.json" -o json > "$TMP_PATH/vulns-cdx.grype.json"
    fi

    set_status "6" "Scanning CDX with OSV (WIP)"
    if [[ -f "$TMP_PATH/merged.cdx.json" ]]; then
        osv-scanner --offline-vulnerabilities --download-offline-databases /cache/vulnscout/osv/ --sbom="$TMP_PATH/merged.cdx.json" --format json --output "$TMP_PATH/vulns-cdx.osv.json" || true
        osv-scanner --offline-vulnerabilities --download-offline-databases /cache/vulnscout/osv/ --sbom="$TMP_PATH/merged.cdx.json" --format sarif --output "$TMP_PATH/vulns-cdx.osv.sarif.json" || true
    fi

    if [[ -e "$YOCTO_CVE_INPUTS_PATH" ]]; then
        set_status "7" "Copy CVE-check result from Yocto"

        rm -Rf $YOCTO_CVE_TMP_PATH
        mkdir -p $YOCTO_CVE_TMP_PATH

        copy_yocto_cve_files $YOCTO_CVE_INPUTS_PATH $YOCTO_CVE_TMP_PATH

        set_status "7" "Found $((YOCTO_CVE_FILE_COUNTER-1)) CVE files issued by Yocto CVE check"
    else
        set_status "7" "No CVE check result found from Yocto"
    fi
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
    echo "Step ($step/8): $message"
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

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then # Is a folder
            extract_tar_folder "$file"
        else
            if [[ "$file" == *.tar || "$file" == *.tar.gz || "$file" == *.tar.zst ]]; then
                mkdir -p "${file}_extracted"
                extract_tar_file "$file" "${file}_extracted"
            fi
        fi
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
# Also copy .spdx files and convert them to .spdx.json
# Globals:
#   SPDX_FILE_COUNTER
# Arguments:
#   Path to folder to search
#   Path to folder to copy in
# Outputs:
#   Each .spdx.json file is copied in the destination folder
#######################################
SPDX_FILE_COUNTER=1

function copy_spdx_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_spdx_files <folder> <destination>"
        exit 1
    fi

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_spdx_files "$file" "$destination"
        else
            local filename
            filename=$(basename "$file")

            if [[ "$file" == *.spdx.json ]]; then
                cp "$file" "$destination/${SPDX_FILE_COUNTER}_$filename"
                ((SPDX_FILE_COUNTER++))
            fi
            if [[ "$file" == *.spdx ]] && [[ "$file" != *.spdx.json ]]; then
                echo "Converting SPDX tag value file $file to JSON"
                local new_file_name="${filename}.json"
                pyspdxtools --infile "$file" --outfile "$destination/${SPDX_FILE_COUNTER}_$new_file_name"
                ((SPDX_FILE_COUNTER++))
            fi
        fi
    done
}

#######################################
# List files in a folder and sub-folders and copy all .openvex.json
# and .openvex files into $2.
# If a file ends in .openvex (non-JSON), convert it to .openvex.json.
#
# Globals:
#   OPENVEX_FILE_COUNTER
# Arguments:
#   Path to folder to search
#   Path to folder to copy into
# Outputs:
#   Each .openvex.json file is copied to destination folder
#######################################
OPENVEX_FILE_COUNTER=1

function copy_openvex_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_openvex_files <folder> <destination>"
        exit 1
    fi

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_openvex_files "$file" "$destination"
        else
            local filename
            filename=$(basename "$file")
            if [[ "$file" == *openvex*.json ]]; then
                cp "$file" "$destination/${OPENVEX_FILE_COUNTER}_$filename"
                ((OPENVEX_FILE_COUNTER++))
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

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_cdx_files "$file" "$destination"
        else
            local filename
            filename=$(basename "$file")

            if [[ "$file" == *.json ]]; then
                if ! cyclonedx-cli validate --input-file "$file" --fail-on-errors &> /dev/null; then
                    echo "File $file is not a valid CycloneDX JSON file"
                    if [[ "$IGNORE_PARSING_ERRORS" != 'true' ]]; then
                        echo "Hint: set IGNORE_PARSING_ERRORS=true to ignore this error"
                        exit 1
                    fi
                else
                    cp "$file" "$destination/${CDX_FILE_COUNTER}_$filename"

                    CDX_FILE_LIST+=("$destination/${CDX_FILE_COUNTER}_$filename")
                    ((CDX_FILE_COUNTER++))
                fi
            fi
            if [[ "$file" == *.xml ]]; then
                if ! cyclonedx-cli validate --input-file "$file" --fail-on-errors &> /dev/null; then
                    echo "File $file is not a valid CycloneDX XML file"
                    if [[ "$IGNORE_PARSING_ERRORS" != 'true' ]]; then
                        echo "Hint: set IGNORE_PARSING_ERRORS=true to ignore this error"
                        exit 1
                    fi
                else
                    local new_file_name=${filename//.xml/.json}
                    cyclonedx-cli convert --input-file "$file" --output-format json --output-file "$destination/${CDX_FILE_COUNTER}_$new_file_name"

                    CDX_FILE_LIST+=("$destination/${CDX_FILE_COUNTER}_$new_file_name")
                    ((CDX_FILE_COUNTER++))
                fi
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

function copy_yocto_cve_files() {
    local folder=$1
    local destination=$2

    if [[ -z "$folder" || -z "$destination" ]]; then
        echo "Usage: copy_yocto_cve_files <folder> <destination>"
        exit 1
    fi

    for file in "$folder"/* ; do
        if [[ -d "$file" ]]; then
            copy_yocto_cve_files "$file" "$destination"
        else
            if [[ "$file" == *.json ]]; then
                cp "$file" "$destination/${YOCTO_CVE_FILE_COUNTER}_$(basename "$file")"
                ((YOCTO_CVE_FILE_COUNTER++))
            fi
        fi
    done
}

main "$@"
