#!/bin/bash
BASE_DIR=$PWD/../../

cd $BASE_DIR
# Launching VulnScout CI script with a fail condition that must be triggered
./vulnscout.sh --name test_ci --spdx $(pwd)/.vulnscout/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
	--cve-check $(pwd)/.vulnscout/example/spdx3/core-image-minimal-qemux86-64.rootfs.json \
	--fail_condition "cvss >= 8.0 or (cvss >= 7.0 and epss >= 50%)"
if [ $? -eq 2 ]; then
	echo "**Vulnscout condition fail correctly triggered**"
else
	echo "**VulnScout condition fail should have been triggered**"
	exit 1
fi
# Launching VulnScout CI script with fail condition that must not be triggered
./vulnscout.sh --name test_ci --spdx $(pwd)/.vulnscout/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
	--cve-check $(pwd)/.vulnscout/example/spdx3/core-image-minimal-qemux86-64.rootfs.json \
	--fail_condition "cvss >= 11.0"
if [ $? -eq 0 ]; then
	echo "**Checking output files**"
else
	echo "**VulnScout condition fail should not have been triggered**"
	exit 1
fi
# Launching VulnScout CI script with an archive of SPDX2
./vulnscout.sh --name test_ci --spdx $(pwd)/.vulnscout/example/spdx2/example.rootfs.spdx.tar.zst \
	--cve-check $(pwd)/.vulnscout/example/spdx2/example.rootfs.json \
	--fail_condition "cvss >= 9.0"
if [ $? -eq 2 ]; then
	echo "**Vulnscout condition fail correctly triggered**"
else
	echo "**VulnScout condition fail should have been triggered**"
	exit 1
fi
