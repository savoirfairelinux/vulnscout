#!/bin/bash
#
# Prepare, commit and push a new release tag
# Pushing a tag will then run a Jenkins pipeline to build and deploy docker image
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.

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



# Write the version to files
sed -i "s/\"version\": \".*\",/\"version\": \"${version}\",/i" frontend/package.json
sed -Ei "3s/^[0-9]+(\.[0-9]+){0,2}/${semversion}/" README.adoc
sed -i "s/LABEL org.opencontainers.image.version=\".*\"/LABEL org.opencontainers.image.version=\"${version}\"/i" Dockerfile

# Commit the changes
git add frontend/package.json
git add README.adoc
git add Dockerfile



# Ask if the user want to commit or amend the last commit
read -rp "Do you want to commit the changes or amend the last commit? [(c)ommit / (a)mend] " answer
if [[ "$answer" = "commit" || "$answer" == "c" || "$answer" == "C" ]]; then

    # New commit with pre-filled message using commit.template
    old_config_template="$(git config --get commit.template || true)"
    git config --local commit.template ".gitmessage.$version"
    echo "release: publish $version" > ".gitmessage.$version"

    git commit

    # clean commit.template config
    if [[ -n "$old_config_template" ]]; then
        git config --local commit.template "$old_config_template"
    else
        git config --local --unset commit.template
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


# Publish the commit
git review

# Tag the release
read -rp "What message do you want for release tag? [Release $version] " tag_msg
if [ -z "$tag_msg" ]; then
    tag_msg="Release $version"
fi
git tag -am "$tag_msg" "$version"


# Push the tag
git push gerrit tag "$version"

echo "Version $version published with success, check Jenkins pipeline for deployment of Docker image."
