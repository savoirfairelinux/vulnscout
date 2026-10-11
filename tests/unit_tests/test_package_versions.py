# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest

from src.helpers.package_versions import git_revision_from_url, is_source_revision, package_version_info
from src.models.package import Package


REVISION = "c43f34b93797e81fd0257c30004dcd0ae332ae51"


@pytest.mark.parametrize("value,expected", [
    (REVISION, True), ("A" * 40, True), ("a" * 64, True),
    ("deadbeef", False), ("4.1.1", False), ("a" * 39, False), ("a" * 41, False),
    ("z" * 40, False), ("", False),
])
def test_only_full_hexadecimal_revisions_are_classified(value, expected):
    assert is_source_revision(value) is expected


def test_release_identifiers_do_not_replace_the_reported_commit():
    purl = "pkg:github/Mbed-TLS/mbedtls@v4.1.1"
    cpe = "cpe:2.3:a:trustedfirmware:mbed_tls:4.1.1:*:*:*:*:*:*:*"
    info = package_version_info(REVISION, [purl], [cpe])
    assert info["release_version"] == "4.1.1"
    assert info["source_revision"] == REVISION
    assert not info["version_conflict"]
    assert not info["revision_conflict"]
    assert info["version_evidence"] == [
        {"version": REVISION, "source": "sbom", "identifier": REVISION},
        {"version": "v4.1.1", "source": "purl", "identifier": purl},
        {"version": "4.1.1", "source": "cpe", "identifier": cpe},
    ]


@pytest.mark.parametrize("version,release,revision", [
    ("4.1.1", "4.1.1", None), (REVISION, None, REVISION),
    ("deadbeef", "deadbeef", None), ("", None, None), (None, None, None),
    ("NOASSERTION", None, None), ("NONE", None, None), ("*", None, None), ("-", None, None),
])
def test_missing_versions_hash_only_and_normal_packages(version, release, revision):
    info = package_version_info(version, [], [])
    assert info["release_version"] == release
    assert info["source_revision"] == revision
    assert not info["version_conflict"]


def test_two_commits_advertising_the_same_release_stay_distinct_and_roundtrip():
    first = Package("mbedtls", REVISION, purl=["pkg:github/Mbed-TLS/mbedtls@v4.1.1"])
    second = Package("mbedtls", "b" * 40, purl=["pkg:github/Mbed-TLS/mbedtls@v4.1.1"])
    assert first.version_info["release_version"] == second.version_info["release_version"] == "4.1.1"
    assert first.string_id != second.string_id
    assert first != second
    assert not first.merge(second)
    data = first.to_dict()
    assert data["version"] == REVISION
    assert data["id"] == f"mbedtls@{REVISION}"
    assert data["release_version"] == "4.1.1"
    restored = Package.from_dict(data)
    assert restored.string_id == first.string_id
    assert restored.version_info == first.version_info


def test_conflicting_release_identifiers_are_explicit():
    purls = ["pkg:generic/lib@1.0", "pkg:generic/lib@2.0"]
    info = package_version_info(REVISION, purls, [])
    assert info["release_version"] is None
    assert info["source_revision"] == REVISION
    assert info["version_conflict"]
    assert {item["version"] for item in info["version_evidence"]} == {REVISION, "1.0", "2.0"}


def test_conflicts_with_the_reported_release_are_not_hidden():
    info = package_version_info("1.0", ["pkg:generic/lib@2.0"], [])
    assert info["version_conflict"]
    assert info["release_version"] is None


def test_conflicting_revisions_are_explicit():
    info = package_version_info(REVISION, [f"pkg:generic/lib@{'b' * 40}"], [])
    assert info["revision_conflict"]
    assert info["source_revision"] is None


def test_release_and_revision_can_be_supplied_in_different_fields():
    info = package_version_info("1.0", [f"pkg:github/org/lib@{REVISION}"], [])
    assert info["release_version"] == "1.0"
    assert info["source_revision"] == REVISION


def test_cpe_case_normalization_does_not_alias_distinct_purl_tags():
    info = package_version_info(REVISION, ["pkg:generic/fatfs@R0.16"], [
        "cpe:2.3:a:elm-chan:fatfs:r0.16:*:*:*:*:*:*:*",
    ])
    assert info["release_version"] == "R0.16"
    assert not info["version_conflict"]
    info = package_version_info(REVISION, ["pkg:generic/lib@Release", "pkg:generic/lib@release"], [])
    assert info["version_conflict"]


def test_non_numeric_tag_aliases_are_not_guessed():
    info = package_version_info(REVISION, ["pkg:generic/hostap@hostap_2_11"], [
        "cpe:2.3:a:w1.fi:hostapd:2.11:*:*:*:*:*:*:*",
    ])
    assert info["release_version"] is None
    assert info["version_conflict"]


@pytest.mark.parametrize("cpe,version", [
    ("cpe:2.3:a:vendor:lib:1.2:*:*:*:*:*:*:*", "1.2"),
    (r"cpe:2.3:a:ven\:dor:lib:1.2\:beta:*:*:*:*:*:*:*", "1.2:beta"),
    ("cpe:/a:vendor:lib:1.2%3Abeta", "1.2:beta"),
    ("cpe:2.3:a:vendor:lib:*:*:*:*:*:*:*:*", None),
    ("cpe:2.3:a:vendor:lib:-:*:*:*:*:*:*:*", None),
    ("cpe:2.3:a:vendor:lib:1.*:*:*:*:*:*:*:*", None),
    ("cpe:2.3:a:vendor:lib:1.?0:*:*:*:*:*:*:*", None),
    ("cpe:/a:vendor:lib:1.*", None),
])
def test_cpe_only_versions_and_wildcards(cpe, version):
    info = package_version_info(REVISION, [], [cpe])
    assert info["release_version"] == version
    assert info["source_revision"] == REVISION


def test_invalid_identifiers_are_reported_without_inventing_versions(caplog):
    info = package_version_info(REVISION, ["not-a-purl", "pkg:generic/lib"], ["invalid-cpe"])
    assert info["release_version"] is None
    assert info["source_revision"] == REVISION
    assert "invalid PURL" in caplog.text
    assert "invalid CPE" in caplog.text


def test_duplicate_evidence_does_not_create_conflicts():
    info = package_version_info("1.0", ["pkg:generic/lib@1.0"] * 2, [])
    assert len(info["version_evidence"]) == 2
    assert info["release_version"] == "1.0"
    assert not info["version_conflict"]


def test_merging_identifiers_refreshes_display_metadata_without_changing_identity():
    package = Package("lib", REVISION, purl=["pkg:generic/lib@1.0"])
    assert package.version_info["release_version"] == "1.0"
    assert package.merge(Package("lib", REVISION, purl=["pkg:generic/lib@2.0"]))
    assert package.string_id == f"lib@{REVISION}"
    assert package.version_info["version_conflict"]
    assert package.version_info["release_version"] is None


@pytest.mark.parametrize("url,expected", [
    (f"git+https://example.org/repo.git@{REVISION}", REVISION),
    (f"git+ssh://git@example.org/repo.git@{REVISION.upper()}", REVISION),
    (f"git://example.org/repo.git@{'a' * 64}?path=src", 'a' * 64),
    (f"git+http://example.org/repo@{REVISION}#src", REVISION),
    (f"https://example.org/archive@{REVISION}", None),
    (f"https://example.org/{REVISION}.tar.gz", None),
    ("git+https://example.org/repo.git@deadbeef", None),
    ("git+https://example.org/repo.git@v1.0", None),
    (f"git+https://example.org/repo.git@{REVISION}a", None),
    ("NOASSERTION", None),
])
def test_only_explicitly_revision_pinned_git_urls_are_parsed(url, expected):
    assert git_revision_from_url(url) == expected


def test_source_urls_supply_revision_evidence_without_changing_identity():
    url = f"git+https://sourceware.org/git/glibc.git@{REVISION}"
    package = Package("libc6", "2.41+git", source_urls=[url, url, "NOASSERTION"])
    assert package.string_id == "libc6@2.41"
    assert package.source_urls == [url]
    assert package.version_info["release_version"] == "2.41"
    assert package.version_info["source_revision"] == REVISION
    assert package.version_info["version_evidence"][-1] == {
        "source": "download", "version": REVISION, "identifier": url,
    }
    assert Package.from_dict(package.to_dict()).version_info == package.version_info
    package.merge(Package("libc6", "2.41", source_urls=[f"git+https://example.org/helper@{'b' * 40}"]))
    assert package.version_info["source_revision"] is None
    assert package.version_info["revision_conflict"]
