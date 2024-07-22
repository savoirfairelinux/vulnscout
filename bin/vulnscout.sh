#!/bin/bash
#
# VulnScout script intended to be used in projects.
# Some features include running an interactive scan, generate report, CI/CD scan, etc.
# Use `vulnscout.sh --help` for more information.
#
# Note: Keep this file indented with tabs, not spaces, or you break the help message.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.


set -euo pipefail # Enable error checking

# Configuration are changed automatically by bin/release_tag.sh
DOCKER_IMAGE="gitlab.savoirfairelinux.com:5050/pe/vulnscout:v0.3.0"
VULNSCOUT_VERSION="v0.3.0"


function main() {
	local container_id="" actual_semver="" latest_semver=""
	if [ $# -eq 0 ]; then
		echo "No arguments provided. Use --help for more information."
		exit 1
	fi

	if [ "$1" == "--help" ]; then
		help
		exit 0
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

	case "$1" in
		scan)
			container_id="$(scan)"
			;;
		report)
			echo "report command not implemented yet."
			exit 1
			;;
		ci)
			echo "ci command not implemented yet."
			exit 1
			;;
		update | upgrade)
			echo "update command not implemented yet."
			exit 1
			;;
		--version)
			echo "$VULNSCOUT_VERSION"
			exit 0
			;;
		*)
			echo "Invalid command. Use --help for more information."
			exit 1
			;;
	esac

	if [[ -n "${container_id}" ]]; then
		# shellcheck disable=SC2064
		trap "{ echo 'Exiting VulnScout, shutting down container'; docker rm -vf $container_id > /dev/null; }" EXIT
		trap "{ echo ''; echo 'Stopped with Ctrl+C, save and quit'; exit 0; }" SIGINT
	fi

	# loop until the container is stopped
	echo "Container started. Press Ctrl+C to stop the scan."
	echo "You can access the scan results at http://localhost:${FLASK_RUN_PORT-7275}"
	sleep 1
	while [[ -n "$(docker ps --filter "id=${container_id}" -q)" ]]; do
		sleep 3
	done

	echo "Container stopped. Exiting VulnScout."
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
			scan        Run a security scan on the project (interactive)
			report      Generate a report from the scan results
			ci          Run a security scan in CI/CD pipeline
			update      Update VulnScout to the latest version
			help        Display this help message

		Options:
			--help      Display this help message, or specific help for a command
			--version   Display the version of VulnScout

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

	if [[ -n "${PRODUCT_NAME-}" ]]; then docker_args+=" -e PRODUCT_NAME=${PRODUCT_NAME}"; fi
	if [[ -n "${PRODUCT_VERSION-}" ]]; then docker_args+=" -e PRODUCT_VERSION=${PRODUCT_VERSION}"; fi
	if [[ -n "${COMPANY_NAME-}" ]]; then docker_args+=" -e COMPANY_NAME=${COMPANY_NAME}"; fi
	if [[ -n "${CONTACT_EMAIL-}" ]]; then docker_args+=" -e CONTACT_EMAIL=${CONTACT_EMAIL}"; fi
	if [[ -n "${DOCUMENT_URL-}" ]]; then docker_args+=" -e DOCUMENT_URL=${DOCUMENT_URL}"; fi
	if [[ -n "${GENERATE_DOCUMENTS-}" ]]; then docker_args+=" -e GENERATE_DOCUMENTS=${GENERATE_DOCUMENTS}"; fi

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
		echo "Warning: You runned without OUTPUT_FOLDER which mean the script will not save your change between runs" >&2
	fi

	# shellcheck disable=SC2086 # docker args is a string with series of argument, so requires to be unquoted
	container_id="$(docker run --rm -d ${docker_args} "${DOCKER_IMAGE}")"
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

main "$@"
