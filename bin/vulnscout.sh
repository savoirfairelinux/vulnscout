#!/bin/bash
#
# VulnScout script intended to be used in projects.
# Some features include running an interactive scan, generate report, CI/CD scan, etc.
# Use `vulnscout.sh --help` for more information.
# Exit 0: everything ok
# Exit 1: execution error (missing conf, docker issue)
# Exit 2: only in ci mode, used when report failed to met user conditions
#
# Note: Keep this file indented with tabs, not spaces, or you break the help message.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.


set -euo pipefail # Enable error checking

# Configuration are changed automatically by bin/release_tag.sh
DOCKER_IMAGE="gitlab.savoirfairelinux.com:5050/pe/vulnscout:v0.4.1"
VULNSCOUT_VERSION="v0.4.1"
INTERACTIVE_MODE="true"
FAIL_CONDITION=""
QUIET_MODE="false"
VERBOSE_MODE="false"


function main() {
	local container_id="" actual_semver="" latest_semver=""
	if [ $# -eq 0 ]; then
		echo "No arguments provided. Use --help for more information."
		exit 1
	fi

	actual_semver="$(echo "${VULNSCOUT_VERSION:1}" | grep -oE '^[0-9]+(\.[0-9]+){0,2}')"
	latest_semver="$(check_newer_version)"
	if [[ -n "$latest_semver" ]]; then
		if [[ "$(semver_cmp "$actual_semver" "$latest_semver")" == '<' ]]; then
			echo "Notice: A newer version of VulnScout is available: v$latest_semver (actual: $VULNSCOUT_VERSION)" >&2
			echo "To updade, run: $0 update" >&2
		fi
	else
		echo "Warning: Unable to reach Vulnscout repository using ssh on gerrit. Unable to check for newer version." >&2
	fi

	load_conf

	for arg in "$@"; do
		case "$arg" in
			--help | -h | help)
				help
				exit 0;
				;;
			-q | --quiet)
				QUIET_MODE="true"
				;;
			-vv | --verbose)
				VERBOSE_MODE="true"
				;;
			-v | --version)
				echo "$VULNSCOUT_VERSION"
				exit 0
				;;
			update | upgrade)
				update_vulnscout  # will exit
				;;
			scan)
				# action by default, nothing to do bu keep for compatibility
				;;
			ci)
				INTERACTIVE_MODE="false"
				;;
			*)
				if [[ "$FAIL_CONDITION" == "" && "$INTERACTIVE_MODE" == "false" ]]; then
					FAIL_CONDITION="$arg"
				else
					echo "Invalid command or flag '$arg'. Use --help for more information."
					exit 1
				fi
				;;
		esac
	done

	container_id="$(scan)"

	if [[ -n "${container_id}" ]]; then
		# shellcheck disable=SC2064 disable=SC2154
		trap "{ real_code=\"\$?\"; echo 'Exiting VulnScout, shutting down container'; docker rm -vf $container_id > /dev/null 2>&1 || exit \"\$real_code\"; }" EXIT
		trap "{ echo ''; echo 'Stopped with Ctrl+C, save and quit'; exit 130; }" SIGINT
	fi

	# loop until the container is stopped
	echo "Container started. Press Ctrl+C to stop the scan."
	if [[ "$INTERACTIVE_MODE" == "true" ]]; then
		echo "You can access the scan results at http://localhost:${FLASK_RUN_PORT-7275}"
	fi
	sleep 1
	if [[ "$QUIET_MODE" != "true" ]]; then
		docker logs -f "$container_id"
	fi

	local container_exit_code=0
	container_exit_code="$(docker wait "$container_id")"
	echo "Container stopped (exit code: ${container_exit_code}). Exiting VulnScout."
	exit "$container_exit_code"
}


#######################################
# Print help message
#######################################
function help() {
	cat <<-EOF
		VulnScout - A security scanning tool for projects

		Usage:
		    vulnscout.sh [command] [options]

		Commands:
		    scan            Run a security scan on the project (interactive) [default]
		    ci [condition]  Run a security scan in CI/CD pipeline
		                    fail with exit code 2 if a vulnerability fulfill the [condition]
		    update          Update VulnScout to the latest version
		    help            Display this help message

		Options:
		    -h --help       Display this help message
		    -v --version    Display the version of VulnScout
		    -q --quiet      Hide docker logs, keeping only a few line
		    -vv --verbose   Print event more logs than by default

		Copyright (C) 2024 Savoir-faire Linux, Inc.
	EOF
}


#######################################
# Run docker image with configuration passed as arguments
# Outputs:
#   write container id to stdout
#######################################
function scan() {
	local docker_args=""
	docker_args+=" -e IGNORE_PARSING_ERRORS=${IGNORE_PARSING_ERRORS-false}"
	if [[ -n "${FLASK_RUN_HOST-}" ]]; then docker_args+=" -e FLASK_RUN_HOST=${FLASK_RUN_HOST}"; fi
	docker_args+=" -e FLASK_RUN_PORT=${FLASK_RUN_PORT-7275}"
	docker_args+=" -p ${FLASK_RUN_PORT-7275}:${FLASK_RUN_PORT-7275}"
	docker_args+=" -e INTERACTIVE_MODE=${INTERACTIVE_MODE}"
	docker_args+=" -e VERBOSE_MODE=${VERBOSE_MODE}"

	if [[ -n "${PRODUCT_NAME-}" ]]; then docker_args+=" -e PRODUCT_NAME=${PRODUCT_NAME}"; fi
	if [[ -n "${PRODUCT_VERSION-}" ]]; then docker_args+=" -e PRODUCT_VERSION=${PRODUCT_VERSION}"; fi
	if [[ -n "${COMPANY_NAME-}" ]]; then docker_args+=" -e COMPANY_NAME=${COMPANY_NAME}"; fi
	if [[ -n "${CONTACT_EMAIL-}" ]]; then docker_args+=" -e CONTACT_EMAIL=${CONTACT_EMAIL}"; fi
	if [[ -n "${DOCUMENT_URL-}" ]]; then docker_args+=" -e DOCUMENT_URL=${DOCUMENT_URL}"; fi

	if [[ -n "${SPDX_SOURCES-}" ]]; then
		for source in "${SPDX_SOURCES[@]}"; do
			docker_args+=" -v $(pwd)$(clean_path "$source"):/scan/inputs/spdx$(clean_path "$source"):ro"
		done
	fi

	if [[ -n "${CDX_SOURCES-}" ]]; then
		for source in "${CDX_SOURCES[@]}"; do
			docker_args+=" -v $(pwd)$(clean_path "$source"):/scan/inputs/cdx$(clean_path "$source"):ro"
		done
	fi

	if [[ -n "${YOCTO_CVE_SOURCES-}" ]]; then
		for source in "${YOCTO_CVE_SOURCES[@]}"; do
			docker_args+=" -v $(pwd)$(clean_path "$source"):/scan/inputs/yocto_cve_check$(clean_path "$source"):ro"
		done
	fi

	if [[ -n "${OUTPUT_FOLDER-}" ]]; then
		docker_args+=" -v $(pwd)$(clean_path "$OUTPUT_FOLDER"):/scan/outputs"
	else
		echo "Warning: Started without OUTPUT_FOLDER which means the script will not save your change between runs" >&2
	fi

	if [[ -n "${CACHE_FOLDER-}" ]]; then
		docker_args+=" -v $(pwd)$(clean_path "$CACHE_FOLDER"):/cache/vulnscout"
	else
		echo "Warning: Started without CACHE_FOLDER which means the script will take much more time to start (+ 5-10 minutes)" >&2
	fi

	if [[ -d ".vulnscout/templates" ]]; then
		docker_args+=" -v $(pwd)$(clean_path "/.vulnscout/templates"):/scan/templates:ro"
	fi

	# shellcheck disable=SC2086 # docker args is a string with series of argument, so requires to be unquoted
	container_id="$(
		docker run -d ${docker_args} \
		-e GENERATE_DOCUMENTS="${GENERATE_DOCUMENTS-}" \
		-e FAIL_CONDITION="${FAIL_CONDITION-}" \
		"${DOCKER_IMAGE}"
	)"
	echo "${container_id}"
}


#######################################
# Ensure path is safe to use for binding
# Arguments:
#   unsafe path
# Outputs:
#   safe path starting with / in stdout, without any . or .. references
#######################################
function clean_path() {
	local path="$1"
	echo "/${path}" | sed 's|/../||g' | sed 's|/./||g' | sed 's|//\+|/|g'
}


#######################################
# Load conf files from .vulnscout folder
# Outputs:
#   source files so conf variables are loaded
#######################################
function load_conf() {
	if [[ -d ".vulnscout" ]]; then
		for file in .vulnscout/*; do
			if [[ -f "$file" ]]; then
				# shellcheck source=/dev/null
				source "$file"
			fi
		done
	else
		echo "No configuration file found. Please create a .vulnscout folder with configuration files."
		exit 1
	fi
}


#######################################
# Compare two semver versions
# Source: https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
# Arguments:
#   version A "*.*.*"
#   version B "*.*.*"
# Outputs:
#   = if equal, > if version A is greater, < if version B is greater (to stdout)
#######################################
semver_cmp () {
    if [[ "$1" == "$2" ]]; then echo '='; return 0; fi
    local IFS=.
    # shellcheck disable=SC2206
    local i ver1=($1) ver2=($2)

    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0 # fill empty fields in ver1 with zeros
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0 # fill empty fields in ver2 with zeros
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
			echo '>'
            return 0
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
			echo '<'
            return 0
        fi
    done
    echo '='
}


#######################################
# Find the latest stable version of VulnScout, using git ls-remote
# Outputs:
#   write most recent version found to stdout
#######################################
function check_newer_version() {
	local versions="" greatest_version="" verA="" cmp_result=""
	versions="$(git ls-remote --refs -t --sort=-v:refname ssh://g1.sfl.io/sfl/vulnscout)"
	versions="$(echo "$versions" | grep -Eo 'v[0-9]+(\.[0-9]+){0,2}([-+\.][a-zA-Z0-9]+)*')"

	for version in $versions; do
		# parse to get only the numbers
		verA="$(echo "${version:1}" | grep -oE '^[0-9]+(\.[0-9]+){0,2}')"

		# if this version is not a stable release, skip
		if [[ "${version}" != "v${verA}" ]]; then
			continue # this version
		fi
		# if this is the first stable version found, skip comparaison
		if [[ -z "$greatest_version" ]]; then
			greatest_version="$verA"
			continue
		fi
		cmp_result="$(semver_cmp "$verA" "$greatest_version")"

		# if version A is greater than greatest_version
		if [[ "$cmp_result" == '>' ]]; then
			greatest_version="$verA"
		fi
	done
	echo "$greatest_version"
}


#######################################
# Try some well known location where vulnscout.sh (this script) could be found
# Because sometime, bash script can just be run from pipe or curl
# It's not always possible to know where the script is located
# Outputs:
#   write full path of what we guessed to stdout
# Exit with 0 if a path was found, 1 otherwise
#######################################
function find_vulnscout_sh_path() {
	local script_path=""

	if [[ -f "${BASH_SOURCE[0]}" ]]; then
		script_path="$(realpath "${BASH_SOURCE[0]}")"
		echo "$script_path"
		return 0
	fi

	if [[ -f "$(realpath "$0")" ]]; then
		script_path="$(realpath "$0")"
		echo "$script_path"
		return 0
	fi

	# check if script is in the current folder
	if [[ -f "vulnscout.sh" ]]; then
		script_path="$(pwd)/vulnscout.sh"
		echo "$script_path"
		return 0
	fi

	# check if script is in the bin folder
	if [[ -f "bin/vulnscout.sh" ]]; then
		script_path="$(pwd)/bin/vulnscout.sh"
		echo "$script_path"
		return 0
	fi

	# check if script is in the parent folder
	if [[ -f "../vulnscout.sh" ]]; then
		script_path="$(pwd)/../vulnscout.sh"
		echo "$script_path"
		return 0
	fi

	# check if script is in the parent bin folder
	if [[ -f "../bin/vulnscout.sh" ]]; then
		script_path="$(pwd)/../bin/vulnscout.sh"
		echo "$script_path"
		return 0
	fi

	echo "Unable to find vulnscout.sh script. Please run this script from the project root folder."
	exit 1
}


#######################################
# Update vulnscout.sh to latest version, using git
#######################################
function update_vulnscout() {
	echo "Updating VulnScout to the latest version..."
	local script_path=""
	local tmp_folder=""

	script_path="$(find_vulnscout_sh_path)"
	tmp_folder="$(mktemp -d)"

	echo "Found vulnscout.sh at: $script_path"

	git clone ssh://g1.sfl.io/sfl/vulnscout "$tmp_folder"
	if [[ ! -f "$tmp_folder/bin/vulnscout.sh" ]]; then
		echo "Error: Unable to find vulnscout.sh in the repository."
		rm -rf "$tmp_folder"
		exit 1
	fi

	rm "$script_path"
	cp -f "$tmp_folder/bin/vulnscout.sh" "$script_path"
	rm -rf "$tmp_folder"

	echo "VulnScout updated to the latest version."
	exit 0
	# running `rm` before `cp` is needed to ensure inode change, preventing bash to try to read in the new file accidentally at wrong line number.
	# Ensure we exit now and this function was not called as sub-script or sub-process, or this exit will not stop the full script.
	# Failure to do so will result in the script to continue running the old version of the script, or bash to complain about script deleted.
}

main "$@"
