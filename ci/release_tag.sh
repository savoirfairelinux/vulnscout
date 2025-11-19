#!/bin/bash
#
# Prepare, commit and push a new release tag
# Pushing a tag will then run a CI pipeline to build and deploy docker image
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

version=$1

# Check if the version is a valid semantic version
if ! echo "$version" | grep -qE '^v[0-9]+(\.[0-9]+){0,2}([-+\.][a-zA-Z0-9]+)*$'; then
    echo "Invalid version: $version - expected semver: v*.*.* [[-+.]option]*"
    exit 1
fi

semversion=$(echo "${version:1}" | grep -oE '^[0-9]+(\.[0-9]+){0,2}')
VULNSCOUT_GIT_URI="git@github.com:savoirfairelinux/vulnscout.git"


# Write the version to files
sed -i "s/\"version\": \".*\",/\"version\": \"${version}\",/i" frontend/package.json
sed -Ei "3s/^[0-9]+(\.[0-9]+){0,2}/${semversion}/" README.adoc
sed -Ei "3s/^[0-9]+(\.[0-9]+){0,2}/${semversion}/" WRITING_TEMPLATES.adoc
sed -Ei "3s/^v[0-9]+(\.[0-9]+){0,2}/v${semversion}/" WRITING_CI_CONDITIONS.adoc
sed -i "s/LABEL org.opencontainers.image.version=\".*\"/LABEL org.opencontainers.image.version=\"${version}\"/i" Dockerfile
sed -i "s/^VULNSCOUT_VERSION=\".*\"$/VULNSCOUT_VERSION=\"${version}\"/i" bin/vulnscout.sh

# Check if nvd.db exists and compress it
find .vulnscout/cache -maxdepth 1 -type f -name "nvd.db.*.xz" -exec rm -f {} +
mkdir -p .vulnscout/cache
nvd_db_path=".vulnscout/cache/nvd.db"
cqfd init
cqfd -b build_nvd
if [ -f "$nvd_db_path" ]; then
    echo "Found nvd.db, compressing with xz..."

    # xz compresses file in place, so we need to copy it then compress
    cp "$nvd_db_path" "${nvd_db_path}.tmp"
    xz "${nvd_db_path}.tmp"
    mv "${nvd_db_path}.tmp.xz" "${nvd_db_path}.${version}.xz"
    echo "nvd.db compressed to ${nvd_db_path}.${version}.xz"
    
    # Add the compressed file to git
    git add -f "${nvd_db_path}.${version}.xz"
else
    echo "nvd.db not found at $nvd_db_path, skipping compression"
fi

# Commit the changes
git add frontend/package.json
git add README.adoc
git add WRITING_TEMPLATES.adoc
git add WRITING_CI_CONDITIONS.adoc
git add Dockerfile
git add bin/vulnscout.sh


# Is there anything to commit?
if ! git diff --quiet HEAD --; then

    # Ask if the user want to commit or amend the last commit
    read -rp "Do you want to commit the changes or amend the last commit? [(c)ommit / (a)mend] " answer
    if [[ "$answer" = "commit" || "$answer" == "c" || "$answer" == "C" ]]; then

        # New commit with pre-filled message using commit.template
        old_config_template="$(git config --get commit.template || true)"
        git config --local commit.template ".gitmessage.$version"
        echo "release: publish $version" > ".gitmessage.$version"

        fail_commit=false
        if ! git commit; then
            fail_commit=true
        fi

        # clean commit.template config
        rm -f ".gitmessage.$version"
        if [[ -n "$old_config_template" ]]; then
            git config --local commit.template "$old_config_template"
        else
            git config --local --unset commit.template
        fi

        if [[ "$fail_commit" = true ]]; then
            echo "Commit failed, aborting release"
            exit 1
        fi

    elif [[ "$answer" = "amend" || "$answer" == "a" || "$answer" == "A" ]]; then
        git commit --amend
    else
        echo "Invalid answer: $answer - expected '(c)ommit' or '(a)mend'"
        exit 1
    fi


    # if file are unstagged, git review will fail. Stash them and re-apply them after
    if ! git diff --quiet HEAD --; then
        git add .
        git stash
        trap 'git stash pop' EXIT
    fi

else
    echo "No changes to commit, moving to tag step"
fi


# Tag the release
read -rp "What message do you want for release tag? [Release $version] " tag_msg
if [ -z "$tag_msg" ]; then
    tag_msg="Release $version"
fi
git tag -am "$tag_msg" "$version"


# Push the tag
git push $VULNSCOUT_GIT_URI tag "$version"

echo "Version $version published with success, check CI pipeline for deployment of Docker image."
