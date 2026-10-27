# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Separate reported release versions from source revisions without changing identity."""

import logging
import re
from typing import Literal, TypedDict
from urllib.parse import unquote

from packageurl import PackageURL

logger = logging.getLogger(__name__)


class VersionEvidence(TypedDict):
    version: str
    source: Literal["sbom", "purl", "cpe", "download"]
    identifier: str


class PackageVersionInfo(TypedDict):
    release_version: str | None
    source_revision: str | None
    version_evidence: list[VersionEvidence]
    version_conflict: bool
    revision_conflict: bool


def is_source_revision(value: str) -> bool:
    """Recognize full SHA-1/SHA-256 revisions, not ambiguous short hexadecimal versions."""
    return re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value) is not None


def git_revision_from_url(value: str) -> str | None:
    """Extract an explicitly pinned Git revision, never an archive or file checksum."""
    match = re.fullmatch(
        r"(?:git\+(?:https?|ssh|git|file)|git)://[^?#]+@"
        r"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?:[?#].*)?",
        value.strip(),
    )
    return match.group(1).lower() if match else None


def _release_key(value: str) -> str:
    return re.sub(r"^[vV](?=\d)", "", value.removesuffix("+git"))


def _purl_release_key(purl: PackageURL) -> str:
    version = purl.version or ""
    # Hostap's upstream repository uses hostap_2_11 tags for the 2.11 release.
    if (purl.type == "generic" and not purl.namespace and purl.name == "hostap"
            and (purl.qualifiers or {}).get("vcs_url") == "git://w1.fi/hostap.git"):
        match = re.fullmatch(r"hostap_(\d+(?:_\d+)+)", version)
        if match:
            return match.group(1).replace("_", ".")
    if (purl.type == "generic" and not purl.namespace and purl.name == "trusted-firmware-m"
            and (purl.qualifiers or {}).get("vcs_url")
            == "git+https://review.trustedfirmware.org/TF-M/trusted-firmware-m"):
        match = re.fullmatch(r"TF-Mv(\d+\.\d+\.\d+)", version)
        if match:
            return match.group(1)
    return _release_key(version)


def _cpe_version(identifier: str) -> str | None:
    # An escaped colon belongs to its component, not to the CPE delimiter.
    parts = re.findall(r"(?:\\.|[^:\\])*(?::|$)", identifier)
    fields = [part[:-1] if part.endswith(":") else part for part in parts[:-1]]
    if "".join(parts) == identifier and identifier.startswith("cpe:2.3:") and len(fields) == 13:
        version = fields[5]
        if not version or version == "-" or any(token in {"*", "?"} for token in re.findall(r"\\.|.", version)):
            return None
        update = fields[6]
        if update not in {"", "*", "-"}:
            if any(token in {"*", "?"} for token in re.findall(r"\\.|.", update)):
                return None
            version += "-" + update
        return re.sub(r"\\(.)", r"\1", version)
    if "".join(parts) == identifier and identifier.startswith("cpe:/") and 5 <= len(fields) <= 8:
        if fields[4] in {"", "-"} or "*" in fields[4] or "?" in fields[4]:
            return None
        version = unquote(fields[4])
        update = fields[5] if len(fields) > 5 else ""
        if update not in {"", "*", "-"}:
            if "*" in update or "?" in update:
                return None
            version += "-" + unquote(update)
        return version
    logger.warning("Cannot extract a version from invalid CPE: %s", identifier)
    return None


def package_version_info(version: str | None, purls: list[str], cpes: list[str],
                         source_urls: list[str] | None = None,
                         source_revisions: list[str] | None = None) -> PackageVersionInfo:
    """Derive display metadata using only explicit, persisted SBOM identifiers.

    Git-style ``v`` prefixes on numeric versions and trailing ``+git`` markers are
    ignored for release comparison. CPE values are case-insensitive and concrete
    CPE updates are part of the release. Hostap and Trusted Firmware-M numeric
    tags are normalized only when their PURL identifies the upstream repository.
    Other tag aliases and commit-to-release lookups are not inferred. Original
    identifier and tag spellings remain in the evidence.
    """
    evidence: list[VersionEvidence] = []
    tag_aliases: dict[str, str] = {}

    def add(value: str | None, source: Literal["sbom", "purl", "cpe", "download"], identifier: str) -> None:
        if value is None:
            return
        value = value.strip()
        if value and value.upper() not in {"*", "-", "NOASSERTION", "NONE"}:
            item: VersionEvidence = {"version": value, "source": source, "identifier": identifier}
            if item not in evidence:
                evidence.append(item)

    add(version, "sbom", version or "")
    for revision in source_revisions or []:
        add(revision, "sbom", revision)
    for purl in purls:
        try:
            parsed = PackageURL.from_string(purl)
        except ValueError:
            logger.warning("Cannot extract a version from invalid PURL: %s", purl)
            continue
        add(parsed.version, "purl", purl)
        if parsed.version:
            key = _purl_release_key(parsed)
            if key != _release_key(parsed.version):
                tag_aliases[parsed.version] = key
    for cpe in cpes:
        add(_cpe_version(cpe), "cpe", cpe)
    for url in source_urls or []:
        add(git_revision_from_url(url), "download", url)

    releases = [item for item in evidence if not is_source_revision(item["version"])]
    release_keys = {
        tag_aliases.get(item["version"], _release_key(item["version"]))
        for item in releases if item["source"] != "cpe"
    }
    for item in releases:
        if item["source"] == "cpe":
            key = _release_key(item["version"])
            if not any(existing.casefold() == key.casefold() for existing in release_keys):
                release_keys.add(key)
    revisions = {item["version"].lower() for item in evidence if is_source_revision(item["version"])}
    return {
        "release_version": next(iter(release_keys)) if len(release_keys) == 1 else None,
        "source_revision": next(iter(revisions)) if len(revisions) == 1 else None,
        "version_evidence": evidence,
        "version_conflict": len(release_keys) > 1,
        "revision_conflict": len(revisions) > 1,
    }
