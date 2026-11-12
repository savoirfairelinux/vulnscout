# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Repository identifiers derived from SBOM URLs and PURLs."""

import pytest

from src.helpers.repository_urls import normalize_repository, scorecard_supported


@pytest.mark.parametrize("value,expected", [
    ("https://github.com/curl/curl", "github.com/curl/curl"),
    ("https://www.github.com/curl/curl.git", "github.com/curl/curl"),
    ("https://github.com/scop/bash-completion/releases/download/2.16.0/bash-completion-2.16.0.tar.xz",
     "github.com/scop/bash-completion"),
    ("https://codeload.github.com/libexpat/libexpat/tar.gz/R_2_6_4", "github.com/libexpat/libexpat"),
    ("https://raw.githubusercontent.com/microsoft/TypeScript/main/README.md", "github.com/microsoft/TypeScript"),
    ("git+https://github.com/zephyrproject-rtos/acpica@8d24867bc9c9d81c81eeac59391cda59333affd4",
     "github.com/zephyrproject-rtos/acpica"),
    ("git://github.com/madler/zlib.git;protocol=https;branch=master", "github.com/madler/zlib"),
    ("git@github.com:openssl/openssl.git", "github.com/openssl/openssl"),
    ("https://gitlab.com/fdroid/fdroidclient", "gitlab.com/fdroid/fdroidclient"),
    ("https://gitlab.com/group/sub/project/-/archive/v1.0/project-v1.0.tar.gz", "gitlab.com/group/sub/project"),
    ("https://gitlab.com/group/project/repository/archive.tar.gz?ref=v1", "gitlab.com/group/project"),
    ("https://bitbucket.org/owner/repo/get/v1.tar.gz", "bitbucket.org/owner/repo"),
    ("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
     "git.kernel.org/pub/scm/linux/kernel/git/stable/linux"),
    ("git://git.busybox.net/busybox;branch=1_36_stable", "git.busybox.net/busybox"),
    ("pkg:github/zephyrproject-rtos/hal_adi@489885cdfa668870f95b00ded1cc56ac52cdf5c4",
     "github.com/zephyrproject-rtos/hal_adi"),
    ("pkg:gitlab/fdroid/fdroidclient@1.0", "gitlab.com/fdroid/fdroidclient"),
    ("pkg:golang/github.com/gorilla/mux@v1.8.0", "github.com/gorilla/mux"),
    ("pkg:golang/github.com/owner/repo/v2@v2.0.0", "github.com/owner/repo"),
])
def test_repository_urls_and_purls_are_normalised(value, expected):
    assert normalize_repository(value) == expected


@pytest.mark.parametrize("value", [
    None, 42, "", "NOASSERTION", "NONE",
    "https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz",
    "http://savannah.nongnu.org/projects/acl/",
    "https://github.com/curl",
    "https://github.com/../etc",
    "https://github.com/owner/.hidden",
    "ftp://github.com/curl/curl",
    "file:///home/user/repo.git",
    "https://[::1/repo.git",
    "pkg:npm/react@18.2.0",
    "pkg:golang/golang.org/x/net@v0.1.0",
    "pkg:github/onlyname",
    "pkg:not a purl",
    "https://example.org/" + "a" * 300 + ".git",
])
def test_non_repository_values_are_rejected(value):
    assert normalize_repository(value) is None


def test_other_hosts_need_explicit_git_unless_assumed():
    url = "https://sourceware.org/git/glibc"
    assert normalize_repository(url) is None
    assert normalize_repository(url, assume_git=True) == "sourceware.org/git/glibc"


@pytest.mark.parametrize("repository,supported", [
    ("github.com/curl/curl", True),
    ("gitlab.com/fdroid/fdroidclient", True),
    ("gitlab.com/group/sub/project", False),
    ("bitbucket.org/owner/repo", False),
    ("git.kernel.org/pub/scm/linux", False),
])
def test_scorecard_only_covers_github_and_gitlab_projects(repository, supported):
    assert scorecard_supported(repository) is supported
