#!/bin/bash
BASE_DIR=$PWD/../../
VULNSCOUT_DIR=.vulnscout/test_ci/state
OUPUT_CI_FILES=("time_estimates.csv" "time_estimates.json" "openvex.json" "sbom.cdx.json" "sbom.spdx.json" "summary.adoc" "sbom.spdx3.json")
OUPUT_CI_FILES_SORT=($(printf '%s\n' "${OUPUT_CI_FILES[@]}" | sort))

cd $BASE_DIR
# Launching VulnScout CI script with a fail condition that must be triggered
./vulnscout.sh --name test_ci --sbom $(pwd)/.vulnscout/example-spdx3/input/core-image-minimal-qemux86-64.rootfs.spdx.json \
	--cve-check $(pwd)/.vulnscout/example-spdx3/input/core-image-minimal-qemux86-64.rootfs.json \
	--fail_condition "cvss >= 8.0 or (cvss >= 7.0 and epss >= 50%)"
if [ $? -eq 2 ]; then
	echo "**Vulnscout condition fail correctly triggered**"
else
	echo "**VulnScout condition fail should have been triggered**"
	exit 1
fi
# Launching VulnScout CI script with fail condition that must not be triggered
./vulnscout.sh --name test_ci --sbom $(pwd)/.vulnscout/example-spdx3/input/core-image-minimal-qemux86-64.rootfs.spdx.json \
	--cve-check $(pwd)/.vulnscout/example-spdx3/input/core-image-minimal-qemux86-64.rootfs.json \
	--fail_condition "cvss >= 11.0"
if [ $? -eq 0 ]; then
	echo "**Checking output files**"
	check_output_files=( $(find $VULNSCOUT_DIR -type f | cut -d'/' -f4) )
	output_files_sort=($(printf '%s\n' "${check_output_files[@]}" | sort))
	if [ "${output_files_sort[*]}" == "${OUPUT_CI_FILES_SORT[*]}" ]; then
		echo "**Output files correctly created**"
	else
		echo "**Ouput files incorrect:**"
		echo "**${check_output_files[@]}**"
		exit 1
	fi
else
	echo "**VulnScout condition fail should not have been triggered**"
	exit 1
fi