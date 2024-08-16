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


set -euo pipefail # Enable error checking
set -m # enable job control to allow `fg` command
#set -x # Enable debugging by writing command which are executed


# Initialize variables
PRODUCT_NAME=${PRODUCT_NAME-"PRODUCT_NAME"}
PRODUCT_VERSION=${PRODUCT_VERSION-"1.0.0"}
COMPANY_NAME=${COMPANY_NAME-"Savoir-faire Linux"}
CONTACT_EMAIL=${CONTACT_EMAIL-""}
DOCUMENT_URL=${DOCUMENT_URL-"https://spdx.org/spdxdocs/${PRODUCT_NAME}-${PRODUCT_VERSION}.spdx.json"}
INTERACTIVE_MODE=${INTERACTIVE_MODE-"true"}

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


function main() {
    cd $BASE_DIR


    # 0. Run server to start page
    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        set_status "0" "Server started"
        (cd "$BASE_DIR/src" && flask --app bin.webapp run) &
    fi

    if [[ "${DEBUG_SKIP_SCAN-}" != "true" ]]; then
        full_scan_steps
    fi

    # 7. Merge all vulnerability from scan results
    set_status "7" "Merging vulnerability results"

    python3 -m src.bin.merger_ci

    set_status "7" "<!-- __END_OF_SCAN_SCRIPT__ -->"

    if [[ "${INTERACTIVE_MODE}" == "true" ]]; then
        fg # Bring back last background process (flask run) to foreground.
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

        set_status "2" "Merging SPDX files"
        python ./SPDXMerge/spdxmerge/SPDXMerge.py \
            --docpath $SPDX_TMP_PATH \
            --outpath "$TMP_PATH/" \
            --mergetype 1 \
            --filetype "J" \
            --name "${PRODUCT_NAME}-${PRODUCT_VERSION}" \
            --author "$COMPANY_NAME" \
            --email "$CONTACT_EMAIL" \
            --docnamespace "$DOCUMENT_URL"

        mv "$TMP_PATH/merged-SBoM-deep.json" "$TMP_PATH/merged.spdx.json"
    else
        set_status "2" "No SPDX files found, skipping"
    fi


    # 3. Search for CycloneDX JSON or XML files in /scan/inputs/cdx and merge them
    if [[ -e "$CDX_INPUTS_PATH" ]]; then
        set_status "3" "Searching CDX JSON files"

        rm -Rf $CDX_TMP_PATH
        mkdir -p $CDX_TMP_PATH

        copy_cdx_files $CDX_INPUTS_PATH $CDX_TMP_PATH

        if [[ ${#CDX_FILE_LIST[@]} -ge 1 ]]; then
            set_status "3" "Merging ${#CDX_FILE_LIST[@]} CDX files"

            cyclonedx-cli merge \
                --output-file "$TMP_PATH/merged.cdx.json" \
                --output-format json \
                --name "$PRODUCT_NAME" \
                --version "$PRODUCT_VERSION" \
                --input-files "${CDX_FILE_LIST[@]}"

            cp "$TMP_PATH/merged.cdx.json" "/$OUTPUTS_PATH/sbom.cdx.json"
        else
            set_status "3" "No CDX files found, skipping"
        fi
    fi

    set_status "4" "Scanning with Grype"
    grype --add-cpes-if-none "sbom:$TMP_PATH/merged.spdx.json" -o json > "$TMP_PATH/vulns-spdx.grype.json"
    grype --add-cpes-if-none "sbom:$TMP_PATH/merged.cdx.json" -o json > "$TMP_PATH/vulns-cdx.grype.json"

    set_status "5" "Scanning with OSV (WIP)"
    osv-scanner --sbom="$TMP_PATH/merged.cdx.json" --format json --output "$TMP_PATH/vulns-cdx.osv.json" || true
    osv-scanner --sbom="$TMP_PATH/merged.cdx.json" --format sarif --output "$TMP_PATH/vulns-cdx.osv.sarif.json" || true

    if [[ -e "$YOCTO_CVE_INPUTS_PATH" ]]; then
        set_status "6" "Copy CVE-check result from Yocto"

        rm -Rf $YOCTO_CVE_TMP_PATH
        mkdir -p $YOCTO_CVE_TMP_PATH

        copy_yocto_cve_files $YOCTO_CVE_INPUTS_PATH $YOCTO_CVE_TMP_PATH

        set_status "6" "Found $(cd $YOCTO_CVE_TMP_PATH && find -- *.json | wc -l) CVE files issued by Yocto CVE check"
    else
        set_status "6" "No CVE check result found from Yocto"
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
            if [[ "$file" == *.spdx.json ]]; then
                cp "$file" "$destination/${SPDX_FILE_COUNTER}_$(basename "$file")"
                ((SPDX_FILE_COUNTER++))
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
