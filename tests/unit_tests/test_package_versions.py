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


@pytest.mark.parametrize("reported,purl_version,cpe_version", [
    ("2.43", "2.43+git", "2.43"),
    ("2.43+git", "2.43", "2.43"),
    ("2.43", "2.43", "2.43+git"),
    ("v2.43+git", "v2.43+git", "2.43"),
    (REVISION, "2.43+git", "2.43"),
])
def test_git_suffix_matches_release_identifiers_without_changing_evidence(reported, purl_version, cpe_version):
    purl = f"pkg:generic/glibc@{purl_version}"
    cpe = f"cpe:2.3:a:gnu:glibc:{cpe_version}:*:*:*:*:*:*:*"
    info = package_version_info(reported, [purl], [cpe])
    assert info["release_version"] == "2.43"
    assert not info["version_conflict"]
    assert info["version_evidence"] == [
        {"version": reported, "source": "sbom", "identifier": reported},
        {"version": purl_version, "source": "purl", "identifier": purl},
        {"version": cpe_version, "source": "cpe", "identifier": cpe},
    ]


@pytest.mark.parametrize("reported", ["2.43+git", "v2.43+git", "V2.43+git"])
def test_git_suffix_alone_identifies_the_base_release(reported):
    info = package_version_info(reported, [], [])
    assert info["release_version"] == "2.43"
    assert not info["version_conflict"]
    assert info["version_evidence"][0]["version"] == reported


@pytest.mark.parametrize("other", [
    "2.44+git", "2.43-rc1+git", "2.43+github", "2.43+git1", "2.43+vendor", "2.43+git-custom",
])
def test_git_suffix_normalization_preserves_real_release_conflicts(other):
    info = package_version_info("2.43", [f"pkg:generic/glibc@{other}"], [])
    assert info["release_version"] is None
    assert info["version_conflict"]


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:a:gnu:glibc:2.43:rc1:*:*:*:*:*:*",
    "cpe:/a:gnu:glibc:2.43:rc1",
])
def test_git_suffix_does_not_hide_concrete_cpe_updates(cpe):
    info = package_version_info("2.43+git", ["pkg:generic/glibc@2.43+git"], [cpe])
    assert info["release_version"] is None
    assert info["version_conflict"]


def test_git_suffix_metadata_does_not_change_package_identity_or_identifiers():
    purl = "pkg:generic/glibc@2.43%2Bgit"
    package = Package("glibc", "2.43+git", purl=[purl])
    assert package.string_id == "glibc@2.43"
    assert package.purl == [purl]
    assert package.version_info["release_version"] == "2.43"
    assert not package.version_info["version_conflict"]
    data = package.to_dict()
    assert data["version"] == "2.43"
    assert {"version": "2.43+git", "source": "purl", "identifier": purl} in data["version_evidence"]
    assert Package.from_dict(data).version_info == package.version_info


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


@pytest.mark.parametrize("reported", [REVISION, "hostap_2_11", "2.11"])
def test_hostap_upstream_tags_match_release_identifiers_without_changing_evidence(reported):
    purl = "pkg:generic/hostap@hostap_2_11?vcs_url=git://w1.fi/hostap.git"
    cpe = "cpe:2.3:a:w1.fi:hostapd:2.11:*:*:*:*:*:*:*"
    info = package_version_info(reported, [purl], [cpe])
    assert info["release_version"] == "2.11"
    assert not info["version_conflict"]
    assert {"version": "hostap_2_11", "source": "purl", "identifier": purl} in info["version_evidence"]
    assert info["version_evidence"][0]["version"] == reported


@pytest.mark.parametrize("purl", [
    "pkg:generic/hostap@hostap_2_11?vcs_url=git://example.org/hostap.git",
    "pkg:generic/other@hostap_2_11?vcs_url=git://w1.fi/hostap.git",
    "pkg:generic/other/hostap@hostap_2_11?vcs_url=git://w1.fi/hostap.git",
    "pkg:generic/hostap@release_2_11?vcs_url=git://w1.fi/hostap.git",
])
def test_hostap_aliases_are_not_applied_to_other_repositories_packages_or_tags(purl):
    info = package_version_info(REVISION, [purl], ["cpe:2.3:a:w1.fi:hostapd:2.11:*:*:*:*:*:*:*"])
    assert info["release_version"] is None
    assert info["version_conflict"]


def test_hostap_tag_normalization_does_not_hide_mismatched_releases():
    purl = "pkg:generic/hostap@hostap_2_10?vcs_url=git://w1.fi/hostap.git"
    info = package_version_info(REVISION, [purl], ["cpe:2.3:a:w1.fi:hostapd:2.11:*:*:*:*:*:*:*"])
    assert info["release_version"] is None
    assert info["version_conflict"]


@pytest.mark.parametrize("reported", [REVISION, "TF-Mv2.3.1", "2.3.1"])
def test_trusted_firmware_m_tags_match_release_identifiers_without_changing_evidence(reported):
    purl = ("pkg:generic/trusted-firmware-m@TF-Mv2.3.1"
            "?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m")
    cpe = "cpe:2.3:o:arm:trusted_firmware-m:2.3.1:-:*:*:*:*:*:*"
    info = package_version_info(reported, [purl], [cpe])
    assert info["release_version"] == "2.3.1"
    assert not info["version_conflict"]
    assert {"version": "TF-Mv2.3.1", "source": "purl", "identifier": purl} in info["version_evidence"]
    assert info["version_evidence"][0]["version"] == reported


@pytest.mark.parametrize("purl", [
    "pkg:generic/trusted-firmware-m@TF-Mv2.3.1",
    ("pkg:generic/trusted-firmware-m@TF-Mv2.3.1"
     "?vcs_url=git%2Bhttps://example.org/TF-M/trusted-firmware-m"),
    ("pkg:generic/other@TF-Mv2.3.1"
     "?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m"),
    ("pkg:generic/other/trusted-firmware-m@TF-Mv2.3.1"
     "?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m"),
    ("pkg:generic/trusted-firmware-m@TF-Mv2.3.1-custom"
     "?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m"),
])
def test_trusted_firmware_m_aliases_require_the_exact_upstream_package_repository_and_tag(purl):
    info = package_version_info(REVISION, [purl], [
        "cpe:2.3:o:arm:trusted_firmware-m:2.3.1:-:*:*:*:*:*:*",
    ])
    assert info["release_version"] is None
    assert info["version_conflict"]


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:o:arm:trusted_firmware-m:2.3.2:-:*:*:*:*:*:*",
    "cpe:2.3:o:arm:trusted_firmware-m:2.3.1:rc1:*:*:*:*:*:*",
])
def test_trusted_firmware_m_normalization_preserves_real_release_conflicts(cpe):
    purl = ("pkg:generic/trusted-firmware-m@TF-Mv2.3.1"
            "?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m")
    info = package_version_info(REVISION, [purl], [cpe])
    assert info["release_version"] is None
    assert info["version_conflict"]


@pytest.mark.parametrize("cpe", [
    "cpe:2.3:o:zephyrproject:zephyr:4.5.0:rc2:*:*:*:*:*:*",
    "cpe:/o:zephyrproject:zephyr:4.5.0:rc2",
])
def test_cpe_update_is_part_of_the_release_version(cpe):
    info = package_version_info("4.5.0-rc2", [], [cpe])
    assert info["release_version"] == "4.5.0-rc2"
    assert not info["version_conflict"]
    assert {"version": "4.5.0-rc2", "source": "cpe", "identifier": cpe} in info["version_evidence"]
    assert package_version_info(REVISION, [], [cpe])["release_version"] == "4.5.0-rc2"


@pytest.mark.parametrize("reported", ["4.5.0", "4.5.0-rc1", "4.5.0-rc3"])
def test_cpe_update_normalization_preserves_real_release_conflicts(reported):
    info = package_version_info(reported, [], ["cpe:2.3:o:zephyrproject:zephyr:4.5.0:rc2:*:*:*:*:*:*"])
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
    ("cpe:2.3:a:vendor:lib:1.2:sp1:*:*:*:*:*:*", "1.2-sp1"),
    (r"cpe:2.3:a:vendor:lib:1.2:rc\:2:*:*:*:*:*:*", "1.2-rc:2"),
    ("cpe:/a:vendor:lib:1.2:sp1", "1.2-sp1"),
    ("cpe:/a:vendor:lib:1.2:rc%3A2", "1.2-rc:2"),
    ("cpe:2.3:a:vendor:lib:1.2:rc*:*:*:*:*:*:*", None),
    ("cpe:2.3:a:vendor:lib:1.2:rc?:*:*:*:*:*:*", None),
    ("cpe:/a:vendor:lib:1.2:rc*", None),
    ("cpe:/a:vendor:lib:-:rc2", None),
    ("cpe:/a:vendor:lib::rc2", None),
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
