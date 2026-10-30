# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Portable recorded-file metadata, not a reconstruction of the build graph."""

import json

EVIDENCE_PREFIX = "VulnScout recorded file evidence v1:\n"
INVENTORY_UNKNOWN_COMMENT = "VulnScout: file inventory not recorded."
SPDX2_INVENTORY_PREFIX = "VulnScout recorded inventory v1:\n"
SPDX2_ASSOCIATION_COMMENT = "VulnScout: recorded file association (not package file analysis)."
SPDX2_FIELDS = {
    "fileTypes", "checksums", "licenseConcluded", "licenseInfoInFiles",
    "licenseComments", "copyrightText", "fileContributors", "attributionTexts", "noticeText",
}
SPDX3_FIELDS = {
    "verifiedUsing", "software_primaryPurpose", "software_contentIdentifier",
    "software_copyrightText", "software_attributionText",
    "software_fileKind", "software_additionalPurpose", "contentType",
}
HASH_ALGORITHMS = {
    "SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512",
    "SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
    "MD5": "md5", "ADLER32": "adler32", "BLAKE2b-256": "blake2b256",
    "BLAKE2b-384": "blake2b384", "BLAKE2b-512": "blake2b512", "BLAKE3": "blake3",
}


def spdx2_annotation_inventory(document: dict) -> tuple[list[dict], list[dict]]:
    files: list[dict] = []
    relationships: list[dict] = []
    for annotation in document.get("annotations", []):
        if not isinstance(annotation, dict):
            continue
        comment = annotation.get("comment")
        if not isinstance(comment, str) or not comment.startswith(SPDX2_INVENTORY_PREFIX):
            continue
        try:
            inventory = json.loads(comment[len(SPDX2_INVENTORY_PREFIX):])
        except ValueError:
            continue
        if not isinstance(inventory, dict):
            continue
        for field, destination in (("files", files), ("relationships", relationships)):
            values = inventory.get(field)
            if isinstance(values, list):
                destination.extend(value for value in values if isinstance(value, dict))
    return files, relationships


def recorded_evidence(properties: dict) -> dict | None:
    comment = properties.get("comment")
    if not isinstance(comment, str) or not comment.startswith(EVIDENCE_PREFIX):
        return None
    try:
        payload = json.loads(comment[len(EVIDENCE_PREFIX):])
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("builds"), list):
        return None
    return payload


def file_metadata(record: dict, spdx3: bool) -> dict:
    """Translate only recorded metadata; never hash paths or copy file contents."""
    properties = record["properties"]
    previous = recorded_evidence(properties)
    portable = {key: value for key, value in properties.items() if key in SPDX2_FIELDS | SPDX3_FIELDS}
    if previous and isinstance(previous.get("properties"), dict):
        portable = {
            **{key: value for key, value in previous["properties"].items() if key in SPDX2_FIELDS | SPDX3_FIELDS},
            **portable,
        }
    result = {key: value for key, value in portable.items() if key in (SPDX3_FIELDS if spdx3 else SPDX2_FIELDS)}
    if spdx3 and "verifiedUsing" not in result:
        hashes = [
            {"type": "Hash", "algorithm": HASH_ALGORITHMS[item["algorithm"]], "hashValue": item["checksumValue"]}
            for item in portable.get("checksums", [])
            if isinstance(item, dict) and item.get("algorithm") in HASH_ALGORITHMS
            and isinstance(item.get("checksumValue"), str)
        ]
        if hashes:
            result["verifiedUsing"] = hashes
    elif not spdx3 and "checksums" not in result:
        algorithms = {value: key for key, value in HASH_ALGORITHMS.items()}
        hashes = [
            {"algorithm": algorithms[item["algorithm"]], "checksumValue": item["hashValue"]}
            for item in portable.get("verifiedUsing", [])
            if isinstance(item, dict) and item.get("algorithm") in algorithms
            and isinstance(item.get("hashValue"), str)
        ]
        if hashes:
            result["checksums"] = hashes
    comment = previous.get("original_comment") if previous else properties.get("comment")
    result["comment"] = EVIDENCE_PREFIX + json.dumps({
        "properties": portable, "builds": record["builds"], "original_comment": comment,
        "scope": "recorded file evidence only; full build graph and completeness not exported",
    }, sort_keys=True)
    return result
