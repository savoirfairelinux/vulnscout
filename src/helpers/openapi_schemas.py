# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""OpenAPI 3.0 schemas for VulnScout's serialized API contracts.

Objects remain extensible because scoped routes add computed annotations.
Package string IDs and vulnerability identifiers are not database UUIDs.
"""

from typing import Any

from .stride_model import MAX_ROWS, RATINGS, STRIDE_CATEGORIES, SYSTEM_KEYS


def _ref(name: str) -> dict[str, Any]:
    return {"$ref": f"#/components/schemas/{name}"}


def _object(properties: dict[str, Any], required: tuple[str, ...] = (), **extra: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, **extra}
    if required:
        schema["required"] = list(required)
    return schema


def _array(items: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"type": "array", "items": items, **extra}


def _map(values: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": values, **extra}


_STRING = {"type": "string"}
_TEXT = {"type": "string", "nullable": True}
_UUID = {"type": "string", "format": "uuid"}
_NULL_UUID = {**_UUID, "nullable": True}
_DATE = {"type": "string", "format": "date-time", "nullable": True}
_BOOL = {"type": "boolean"}
_INT = {"type": "integer"}
_COUNT = {"type": "integer", "minimum": 0}
_NUMBER = {"type": "number", "nullable": True}
_STRINGS = _array(_STRING)
_UUIDS = _array(_UUID)
_PACKAGE_ID = {
    "type": "string",
    "description": "Package string ID: name@version, optionally followed by ::supplier; not a UUID.",
    "example": "openssl@3.0.16",
}
_VULN_ID = {
    "type": "string",
    "description": "Vulnerability identifier (for example CVE, GHSA or an imported advisory ID); not a UUID.",
    "example": "CVE-2025-0001",
}
_PACKAGES = _array(_PACKAGE_ID)
_VULNS = _array(_VULN_ID)
_OPENVEX_STATUSES = ["under_investigation", "not_affected", "affected", "fixed"]
_STATUSES = _OPENVEX_STATUSES + [
    "in_triage", "false_positive", "exploitable", "resolved", "resolved_with_pedigree",
]
_JUSTIFICATIONS = [
    "component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]
_CDX_JUSTIFICATIONS = [
    "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
    "requires_environment", "protected_by_compiler", "protected_at_runtime",
    "protected_at_perimeter", "protected_by_mitigating_control",
]
_VEX_FIELDS = {
    "status": {"type": "string", "enum": _STATUSES},
    "status_notes": _STRING,
    "justification": {"type": "string", "enum": ["", *_JUSTIFICATIONS, *_CDX_JUSTIFICATIONS]},
    "impact_statement": _STRING,
    "responses": _STRINGS,
    "workaround": _STRING,
}
_CONTEXT_FIELDS = {
    name: _TEXT for name in (
        "variant_description", "codebase_path", "environment", "threat_model", "risks", "other_info",
    )
}
# Variant context fields stored as plain text; the threat model and risks are rendered from STRIDE.
_CONTEXT_TEXT_FIELDS = {
    name: _TEXT for name in ("variant_description", "codebase_path", "environment", "other_info")
}
_CODEBASE_SOURCE = {"type": "string", "enum": ["paths", "references"]}
_STRIDE_ROWS = {"maxItems": MAX_ROWS}
_RATING = {"type": "string", "enum": [*RATINGS, None], "nullable": True}
_EFFORT_KEYS = ("optimistic", "likely", "pessimistic")
_SCAN_PACKAGE_FIELDS = {
    "package_id": _UUID, "package_name": _STRING, "package_version": _STRING,
    "package_supplier": _TEXT, "sources": _STRINGS,
}


SCHEMAS: dict[str, Any] = {
    "SourceFile": _object({
        "spdx_id": _STRING, "path": _STRING, "document_id": _UUID, "document_name": _STRING,
        "scan_id": _UUID, "variant_id": _UUID, "variant_name": _STRING,
        "properties": _object({}),
        "builds": _array(_object({
            "spdx_id": _STRING, "document_name": _STRING, "build_type": _TEXT,
            "parameters": _array(_object({})), "outputs": _STRINGS,
        })),
    }, ("spdx_id", "path", "document_id", "document_name", "properties", "builds")),
    "Project": _object({
        "id": _UUID, "name": _STRING,
        "variants": _array(_object({"id": _UUID, "name": _STRING}, ("id", "name"))),
    }, ("id", "name")),
    "Variant": _object({
        "id": _UUID, "name": _STRING, "project_id": _UUID,
    }, ("id", "name", "project_id")),
    "Package": _object({
        "id": _PACKAGE_ID, "package_id": _NULL_UUID, "name": _TEXT, "version": _TEXT,
        "cpe": _STRINGS, "purl": _STRINGS, "licences": _STRING, "supplier": _TEXT,
        "source_urls": _STRINGS, "source_revisions": _STRINGS, "component_types": _STRINGS,
        "source_file_count": {**_COUNT, "nullable": True},
        "compiled_source_file_count": _COUNT, "compiled_sources_complete": _BOOL,
        "source_files": _array(_ref("SourceFile"), nullable=True),
        "release_version": _TEXT, "source_revision": _TEXT,
        "version_conflict": _BOOL, "revision_conflict": _BOOL,
        "version_evidence": _array(_object({
            "version": _STRING, "identifier": _STRING,
            "source": {"type": "string", "enum": ["sbom", "purl", "cpe", "download"]},
        }, ("version", "identifier", "source"))),
        "variants": _STRINGS, "sources": _STRINGS, "sbom_documents": _STRINGS,
        "outdated": _BOOL, "variant_id": _UUID, "finding_ids": _UUIDS,
        "vulnerability_ids": _VULNS,
    }, ("id", "name", "version")),
    "PackageCollection": {
        "description": "Default list, or format=dict keyed by name@version (historical rows append @variant UUID).",
        "anyOf": [_array(_ref("Package")), _map(_ref("Package"))],
    },
    "CVSS": _object({
        "id": _UUID, "variant_id": _NULL_UUID, "version": _STRING,
        "vector_string": _STRING, "author": _TEXT, "origin": _STRING,
        "base_score": {"type": "number"}, "exploitability_score": {"type": "number"},
        "impact_score": {"type": "number"}, "severity": _STRING,
        "attack_vector": {
            "type": "string", "nullable": True,
            "enum": ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", None],
        },
    }, ("version", "base_score"), description=(
        "CVSS score. Compact Explorer rows retain only version, base_score and attack_vector; "
        "stored metrics may include id and variant_id."
    )),
    "Effort": _object({
        name: {"type": "string", "nullable": True, "example": "PT8H",
               "description": "ISO 8601 duration, or null when unset."}
        for name in _EFFORT_KEYS
    }, _EFFORT_KEYS),
    "EffortInput": _object({
        name: {"anyOf": [{"type": "integer"}, {"type": "string", "example": "PT8H"}]}
        for name in _EFFORT_KEYS
    }, _EFFORT_KEYS, description="Whole hours or ISO 8601 durations; optimistic <= likely <= pessimistic."),
    "VulnerabilityText": _object({
        "title": _STRING, "content": _STRING, "packages": _STRINGS,
    }, ("title", "content")),
    "Vulnerability": _object({
        "id": _VULN_ID, "found_by": _STRINGS, "datasource": _STRING, "namespace": _STRING,
        "aliases": _STRINGS, "related_vulnerabilities": _STRINGS,
        "urls": _STRINGS, "description": _TEXT, "cpes": _STRINGS,
        "fix": _object({
            "versions_impacted": _STRINGS, "versions_fixing": _STRINGS, "state": _STRING,
        }),
        "euvd": _object({
            "id": _TEXT, "known_exploited": _BOOL, "sources": _STRINGS,
            "date_added": _TEXT, "url": _TEXT,
        }),
        "severity": _object({
            "severity": _STRING, "min_score": _NUMBER, "max_score": _NUMBER,
            "cvss": _array(_ref("CVSS")),
        }),
        "epss": _object({"score": _NUMBER, "percentile": _NUMBER}),
        "effort": _ref("Effort"), "advisories": _STRINGS,
        "packages": _PACKAGES, "packages_current": _PACKAGES,
        "packages_current_by_variant": _map(_PACKAGES),
        "published": _TEXT, "data_fetched_at": _DATE, "data_updated_at": _DATE,
        "nvd_fetched_at": _DATE, "ghsa_fetched_at": _DATE, "euvd_fetched_at": _DATE,
        "first_scan_date": _DATE, "texts": _array(_ref("VulnerabilityText")),
        "variants": _STRINGS, "details_loaded": _BOOL,
    }, ("id", "severity", "effort", "packages")),
    "VulnerabilityCollection": {
        "description": "List (including compact Explorer rows) or format=dict keyed by vulnerability identifier.",
        "anyOf": [_array(_ref("Vulnerability")), _map(_ref("Vulnerability"))],
    },
    "AssessmentTarget": _object({
        "variant_id": _UUID, "package": _PACKAGE_ID, "project_id": _UUID, "outdated": _BOOL,
    }, ("variant_id", "package"), description=(
        "One actual target pair. packages and variant_ids are projections of this sparse set, "
        "not an implicit Cartesian product."
    )),
    "Assessment": _object({
        "id": _UUID, "source": _STRING, "origin": _STRING, "vuln_id": _VULN_ID,
        "packages": _PACKAGES, "variant_id": _NULL_UUID, "variant_ids": _UUIDS,
        "targets": _array(_ref("AssessmentTarget")),
        "timestamp": _DATE, "last_update": _STRING,
        **{name: _STRING for name in ("status", "status_notes", "justification", "impact_statement", "workaround")},
        "responses": _STRINGS, "outdated": _BOOL, "context_outdated": _BOOL,
        "assessment_fingerprint": _STRING, "project_id": _NULL_UUID, "has_review": _BOOL,
        "vuln_texts": _array(_ref("VulnerabilityText")),
        "reviews": _array(_ref("AssessmentReviewRecord")),
        "target_reviews": _array(_object({
            "variant_id": _UUID, "package": _PACKAGE_ID, "has_review": _BOOL, "is_stale": _BOOL,
        }, ("variant_id", "package", "has_review", "is_stale"))),
    }, ("id", "vuln_id", "packages", "targets", "variant_ids", "variant_id", "status")),
    "AssessmentCollection": {
        "anyOf": [
            _array(_ref("Assessment")), _map(_ref("Assessment")),
            _array(_ref("CompactAssessment")),
        ],
        "description": "List, format=dict keyed by assessment UUID, or format=compact positional rows.",
    },
    "CompactAssessment": _array(
        _TEXT, minItems=6, maxItems=6,
        description=(
            "Positional row [assessment UUID, vulnerability ID, package string ID or null, "
            "variant UUID or null, timestamp or null, status]. OpenAPI 3.0 cannot type individual tuple positions."
        ),
    ),
    "AssessmentReviewRecord": _object({
        "id": _UUID, "assessment_id": _UUID, "variant_id": _UUID, "package": _PACKAGE_ID,
        **{name: _STRING for name in ("status", "status_notes", "justification", "impact_statement", "workaround")},
        "responses": _STRINGS, "rationale": _STRING, "timestamp": _DATE,
        "verdict": {"type": "string", "enum": ["agrees", "differs"]}, "is_stale": _BOOL,
    }, ("id", "assessment_id", "variant_id", "package", "status", "rationale", "verdict", "is_stale")),
    "AssessmentReviewResult": _object({
        "review": _ref("AssessmentReviewRecord"), "status": {"type": "string", "enum": ["success"]},
    }, ("review",), description="GET returns review; PUT additionally returns status=success."),
    "AssessmentReviewList": _object({
        "reviews": _array(_ref("AssessmentReviewRecord")),
    }, ("reviews",)),
    "CustomAssessmentPage": _array(
        _ref("Assessment"),
        description="Paginated with limit/offset, but the response is a bare array, not a page envelope.",
    ),
    "ReviewMap": _map(_array(_ref("AssessmentReviewRecord")),
                      description="Assessment UUID -> reviews, one review per actual target."),
    "AssessmentCreate": _object({
        **_VEX_FIELDS, "vuln_id": _VULN_ID, "packages": _array(_PACKAGE_ID, minItems=1),
        "variant_id": _UUID, "variant_ids": _array(_UUID, minItems=1),
        "targets": _array(_ref("AssessmentTarget"), minItems=1),
        "timestamp": _STRING, "ai_generated": _BOOL,
    }, ("status",), anyOf=[
        {"required": ["targets"]},
        {"required": ["packages", "variant_ids"]},
        {"required": ["packages", "variant_id"]},
    ], description=(
        "Explicit targets preserve sparse pairs. Otherwise packages are crossed with the selected variants. "
        "vuln_id defaults to the path identifier. not_affected requires justification."
    )),
    "AssessmentUpdate": _object({
        **_VEX_FIELDS, "timestamp": _STRING, "update_timestamp": _BOOL,
        "allowed_variant_ids": _array(_UUID, minItems=1),
    }, description="Partial content update; targeting is changed through reconcile."),
    "AssessmentBatch": _object({
        "assessments": _array(_object({
            **_VEX_FIELDS, "vuln_id": _VULN_ID, "packages": _array(_PACKAGE_ID, minItems=1),
            "variant_id": _UUID, "variant_ids": _array(_UUID, minItems=1), "timestamp": _STRING,
        }, ("vuln_id", "status", "packages"), anyOf=[
            {"required": ["variant_id"]}, {"required": ["variant_ids"]},
        ])),
    }, ("assessments",)),
    "AssessmentReconcile": _object({
        **_VEX_FIELDS, "vuln_id": _VULN_ID, "packages": _array(_PACKAGE_ID, minItems=1),
        "variant_ids": _array(_UUID, minItems=1), "targets": _array(_ref("AssessmentTarget")),
        "update_timestamp": _BOOL, "timestamp": _STRING,
    }, ("vuln_id", "status"), anyOf=[
        {"required": ["targets"]}, {"required": ["packages", "variant_ids"]},
    ], description="targets may be empty to remove all targets and delete the assessment."),
    "AssessmentWriteResult": _object({
        "status": _STRING, "assessment": _ref("Assessment"), "assessments": _array(_ref("Assessment")),
        "count": _COUNT, "vuln_count": _COUNT,
    }, ("status",)),
    "AssessmentReconcileResult": _object({
        "status": _STRING, "updated": _array(_ref("Assessment")),
        "created": _array(_ref("Assessment")), "deleted": _UUIDS,
    }, ("status", "updated", "created", "deleted")),
    "ReviewWrite": _object({
        **_VEX_FIELDS, "status": {"type": "string", "enum": _OPENVEX_STATUSES},
        "justification": {"type": "string", "nullable": True, "enum": [*_JUSTIFICATIONS, None]},
        "variant_id": _UUID, "finding_id": _UUID, "package": _PACKAGE_ID,
        "expected_assessment_fingerprint": {"type": "string", "minLength": 1},
        "rationale": {"type": "string", "minLength": 1},
    }, ("variant_id", "status", "rationale", "expected_assessment_fingerprint"),
        anyOf=[{"required": ["finding_id"]}, {"required": ["package"]}],
        description="A review targets one existing custom assessment target; not_affected requires justification."),
    "VulnerabilityUpdate": _object({
        "variant_id": _UUID, "effort": _ref("EffortInput"), "cvss": _ref("CVSSInput"),
    }),
    "CVSSInput": _object({
        "version": _STRING, "vector_string": _STRING, "base_score": {"type": "number"},
        "author": _STRING, "origin": _STRING,
        "exploitability_score": {"type": "number"}, "impact_score": {"type": "number"},
    }, ("version", "vector_string", "base_score")),
    "VulnerabilityBatchUpdate": _object({
        "vulnerabilities": _array(_object({
            "id": _VULN_ID, "variant_id": _UUID,
            "effort": _ref("EffortInput"), "cvss": _ref("CVSSInput"),
        }, ("id",))),
    }, ("vulnerabilities",)),
    "VulnerabilityBatchResult": _object({
        "status": _STRING, "vulnerabilities": _array(_ref("Vulnerability")), "count": _COUNT,
        "errors": _array(_ref("Error")), "error_count": _COUNT,
    }, ("status", "vulnerabilities", "count")),
    "Scan": _object({
        "id": _UUID, "description": _TEXT, "timestamp": _DATE,
        "variant_id": _UUID, "variant_name": _TEXT, "project_name": _TEXT,
        "scan_type": {"type": "string", "enum": ["sbom", "tool"]},
        "scan_source": _TEXT, "run_id": _TEXT,
        "variant": _object({
            "id": _UUID, "name": _STRING,
            "project": _object({"id": _UUID, "name": _STRING}, ("id", "name")),
        }),
        "is_first": _BOOL, "previous_scan_id": _NULL_UUID,
        **{key: {**_COUNT, "nullable": True} for key in (
            "finding_count", "package_count", "vuln_count", "assessment_count",
            "findings_added", "findings_removed", "findings_upgraded", "findings_unchanged",
            "packages_added", "packages_removed", "packages_upgraded", "packages_unchanged",
            "vulns_added", "vulns_removed", "vulns_unchanged",
            "assessments_added", "assessments_removed", "assessments_unchanged",
            "newly_detected_findings", "newly_detected_vulns",
        )},
    }, ("id", "description", "timestamp")),
    "ScanCollection": _array(_ref("Scan")),
    "ScanPackage": _object(_SCAN_PACKAGE_FIELDS, ("package_name", "package_version")),
    "ScanFinding": _object({
        **_SCAN_PACKAGE_FIELDS, "finding_id": _UUID, "vulnerability_id": _VULN_ID, "origin": _STRING,
    }, ("vulnerability_id", "package_name", "package_version")),
    "ScanAssessment": _object({
        **_SCAN_PACKAGE_FIELDS, "vulnerability_id": _VULN_ID, "status": _STRING,
        "simplified_status": _STRING, "justification": _STRING,
        "impact_statement": _STRING, "status_notes": _STRING,
        "targets": _array(_object({
            "package_name": _STRING, "package_version": _STRING, "package_supplier": _TEXT,
        }, ("package_name", "package_version"))),
    }, ("vulnerability_id", "status")),
    "ScanResult": _object({
        "scan_id": _UUID, "scan_type": _STRING,
        "packages": _array(_ref("ScanPackage")), "findings": _array(_ref("ScanFinding")),
        "vulnerabilities": _array(_object({
            "vulnerability_id": _VULN_ID, "sources": _STRINGS,
        }, ("vulnerability_id", "sources"))),
        "assessments": _array(_ref("ScanAssessment")),
        **{key: _COUNT for key in ("package_count", "finding_count", "vuln_count", "assessment_count")},
    }, ("scan_id", "scan_type", "packages", "findings", "vulnerabilities", "assessments")),
    "ScanDiff": _object({
        "scan_id": _UUID, "scan_type": _STRING, "previous_scan_id": _NULL_UUID, "is_first": _BOOL,
        **{key: _COUNT for key in ("finding_count", "package_count", "vuln_count", "assessment_count")},
        **{f"findings_{key}": _array(_ref("ScanFinding")) for key in ("added", "removed", "unchanged")},
        **{f"packages_{key}": _array(_ref("ScanPackage")) for key in ("added", "removed", "unchanged")},
        **{f"vulns_{key}": _VULNS for key in ("added", "removed", "unchanged")},
        **{f"assessments_{key}": _array(_ref("ScanAssessment")) for key in ("added", "removed", "unchanged")},
        "packages_upgraded": _array(_object({
            "package_name": _STRING, "old_version": _STRING, "new_version": _STRING,
            "old_package_id": _UUID, "new_package_id": _UUID,
        }, ("package_name", "old_version", "new_version"))),
        "findings_upgraded": _array(_object({
            "vulnerability_id": _VULN_ID, "package_name": _STRING,
            "old_version": _STRING, "new_version": _STRING,
        }, ("vulnerability_id", "package_name", "old_version", "new_version"))),
        "newly_detected_findings": {**_COUNT, "nullable": True},
        "newly_detected_vulns": {**_COUNT, "nullable": True},
        "newly_detected_findings_list": _array(_ref("ScanFinding"), nullable=True),
        "newly_detected_vulns_list": {**_VULNS, "nullable": True},
        "newly_detected_assessments_list": _array(_ref("ScanAssessment"), nullable=True),
        "all_findings": _array(_ref("ScanFinding"), nullable=True),
        "all_vulns": {**_VULNS, "nullable": True},
    }, ("scan_id", "scan_type", "previous_scan_id", "is_first")),
    "Document": _object({
        "id": _STRING, "extension": _STRING, "is_template": _BOOL,
        "is_asset": _BOOL, "category": _STRINGS,
    }, ("id", "extension", "category")),
    "Operation": _object({
        "op_id": _STRING,
        "kind": {"type": "string", "enum": ["scan", "refresh", "upload", "export", "enrichment"]},
        "source": _STRING, "label": _STRING,
        "lane": {"type": "string", "enum": ["pipeline", "export", "upload"]},
        "scope": _object({
            "variant_id": _UUID, "variant_name": _STRING, "project_id": _UUID,
        }, nullable=True),
        "status": {"type": "string", "enum": ["queued", "running", "done", "error", "cancelled"]},
        "progress": _object({"current": _INT, "total": _INT, "message": _STRING}),
        "logs": _STRINGS, "error": _TEXT, "queue_id": _TEXT,
        "position": {**_INT, "nullable": True}, "options": _ref("JsonObject"),
        "cancellable": _BOOL, "created_at": _DATE, "started_at": _DATE, "finished_at": _DATE,
        "result": _object({}, nullable=True, description="Operation-kind-specific completion data."),
    }, ("op_id", "kind", "source", "label", "lane", "status", "progress", "logs", "cancellable")),
    "OperationSnapshot": _object({"operations": _array(_ref("Operation"))}, ("operations",)),
    "QueueAccepted": _object({
        "queue_id": _STRING, "operations": _array(_ref("Operation")),
    }, ("queue_id", "operations")),
    "OperationOptions": _object({
        "mode": {"type": "string", "enum": ["local", "api"], "default": "local"},
        "exclude_kernel": _BOOL, "exclude_native": _BOOL,
        "native_package_exceptions": _STRINGS,
    }),
    "OperationBatch": _object({
        "jobs": _array({"anyOf": [
            _object({
                "kind": {"type": "string", "enum": ["scan"]},
                "source": {"type": "string", "enum": ["grype", "nvd", "osv", "scc"]},
                "variant_ids": _array(_UUID, minItems=1), "options": _ref("OperationOptions"),
            }, ("kind", "source", "variant_ids")),
            _object({
                "kind": {"type": "string", "enum": ["refresh"]},
                "source": {"type": "string", "enum": ["nvd", "epss", "ghsa", "euvd"]},
                "ids": _array(_VULN_ID, minItems=1),
                "variant_ids": _array(_UUID, minItems=1, maxItems=100, uniqueItems=True),
                "exclude_ids": _VULNS, "options": _ref("OperationOptions"),
            }, ("kind", "source"), oneOf=[
                {"required": ["ids"], "not": {"required": ["variant_ids"]}},
                {"required": ["variant_ids"], "not": {"required": ["ids"]}},
            ]),
        ]}, minItems=1, maxItems=100),
    }, ("jobs",), description="At most 100 expanded operations; duplicate operation IDs are rejected."),
    "ContextFile": _object({
        "id": _UUID, "original_name": _STRING, "description": _TEXT,
    }, ("id", "original_name", "description")),
    "ProjectContext": _object({
        "project_id": _UUID, "description": _TEXT,
    }, ("project_id", "description")),
    "ContextSystem": _object({key: _TEXT for key in SYSTEM_KEYS}),
    "StrideModel": _object({
        "components": _array(_object({
            "id": {"type": "string", "pattern": r"^C[1-9]\d*$"}, "name": _STRING,
            "description": _TEXT, "trust_zone": _TEXT,
        }, ("id", "name")), **_STRIDE_ROWS),
        "interactions": _array(_object({
            "id": {"type": "string", "pattern": r"^I[1-9]\d*$"}, "name": _TEXT,
            "source_id": _STRING, "destination_id": _STRING,
            "interface": _TEXT, "data": _TEXT, "trust_boundary": _TEXT,
        }, ("id", "source_id", "destination_id")), **_STRIDE_ROWS),
        "threats": _array(_object({
            "id": {"type": "string", "pattern": r"^T[1-9]\d*$"},
            "category": {"type": "string", "enum": list(STRIDE_CATEGORIES)},
            "description": _TEXT,
            "target_ids": _array(_STRING, minItems=1, description="Component or interaction IDs."),
        }, ("id", "category", "target_ids")), **_STRIDE_ROWS),
        "risks": _array(_object({
            "threat_id": _STRING,
            "likelihood": _RATING, "impact": _RATING,
            "mitigation": _TEXT, "residual": _TEXT,
        }, ("threat_id",)), **_STRIDE_ROWS),
    }, description="Structured STRIDE model; rows reference earlier rows by ID."),
    "VariantContextEditor": _object({
        "codebase_source": _CODEBASE_SOURCE, "codebase_path": _TEXT,
        "system": _ref("ContextSystem"), "stride": _ref("StrideModel"),
        "files": _array(_ref("ContextFile")), "updated_at": _DATE,
    }, ("codebase_source", "codebase_path", "system", "stride", "files", "updated_at"),
        description="Stored editor values, independent of the selected codebase source."),
    "VariantContext": _object({
        "variant_id": _UUID, **_CONTEXT_FIELDS, "updated_at": _DATE,
        "files": _array(_ref("ContextFile")), "editor": _ref("VariantContextEditor"),
    }, ("variant_id", "files", "editor"),
        description="Top-level fields are what agents see: threat_model and risks are rendered from STRIDE."),
    "MergedContext": _object({
        "project_id": _UUID, "description": _TEXT, "variant_id": _UUID,
        **_CONTEXT_FIELDS, "files": _array(_ref("ContextFile")),
    }, ("project_id", "variant_id", "description", "files")),
    "ScanConfiguration": _object({
        "exclude_native": _BOOL,
        "native_package_exceptions": _array({"type": "string", "maxLength": 255, "example": "gcc-native"}),
    }, ("exclude_native", "native_package_exceptions")),
    "ProjectScanConfiguration": _object({
        "exclude_native": _BOOL, "native_package_exceptions": _STRINGS, "native_packages": _STRINGS,
    }, ("exclude_native", "native_package_exceptions")),
    "ConfigUpdate": _object({
        "product_name": _TEXT, "author_name": _TEXT, "client_name": _TEXT,
        "contact_email": _TEXT, "grype_memlimit": _TEXT,
    }, additionalProperties=False),
    "ServerVersion": _object({"version": _STRING}, ("version",)),
    "ScanStatus": _object({
        "status": {"type": "string", "enum": ["running", "done"]},
        "maxsteps": _INT, "step": _INT, "message": _STRING,
    }, ("status", "maxsteps", "step", "message")),
    "NvdKeyStatus": _object({
        "has_key": _BOOL, "masked_key": _STRING,
        "status": {"type": "string", "enum": ["ok"]}, "warning": _STRING,
    }, ("has_key", "masked_key")),
    "NvdKeyUpdate": _object({
        "api_key": {"type": "string", "description": "Empty string removes the configured key."},
    }, ("api_key",)),
    "NameRequest": _object({
        "name": {"type": "string", "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9_@-]{0,63}$"},
    }, ("name",)),
    "Message": _object({"message": _STRING}, ("message",)),
    "DeletionSummary": {
        "anyOf": [
            _ref("Message"),
            _object({
                "status": _STRING,
                "deleted": {"anyOf": [_STRING, _UUIDS]},
            }, ("status", "deleted")),
            _object({
                "deleted": {"type": "boolean", "enum": [True]}, "scan_id": _UUID,
                "orphaned_findings_removed": _COUNT,
            }, ("deleted", "scan_id", "orphaned_findings_removed")),
        ],
    },
    "ImportSummary": {
        "anyOf": [
            _object({
                "status": _STRING, "imported": _COUNT, "skipped": _COUNT,
                "errors": _array(_ref("Error")),
            }, ("status", "imported", "skipped", "errors")),
            _object({
                "status": _STRING,
                **{key: _COUNT for key in (
                    "assessments_imported", "assessments_skipped", "ai_assessments_imported",
                    "ai_assessments_skipped", "cvss_imported", "time_estimates_imported",
                )},
                "errors": _array(_ref("Error")),
            }, ("status", "assessments_imported", "cvss_imported", "time_estimates_imported", "errors")),
            _object({
                "imported_count": _COUNT, "skipped_count": _COUNT, "scan_id": _NULL_UUID,
                "format": _TEXT, "is_first": {**_BOOL, "nullable": True},
                "scans": _array(_object({
                    "scan_id": _UUID, "format": _STRING, "is_first": _BOOL,
                    **{key: _COUNT for key in (
                        "package_count", "finding_count", "vulnerability_count", "assessment_count",
                    )},
                })),
                **{key: _COUNT for key in (
                    "package_count", "finding_count", "vulnerability_count", "assessment_count",
                )},
            }, ("imported_count", "skipped_count", "scans")),
        ],
    },
    "DocumentExportRequest": _object({
        "project_id": _UUID, "variant_ids": _array(_UUID, minItems=1),
        "mode": {"type": "string", "enum": ["consolidated", "per_variant"]}, "async": _BOOL,
        "documents": _array(_object({
            "name": {"type": "string", "minLength": 1},
            "extension": {"type": "string", "minLength": 1},
        }, ("name", "extension")), minItems=1, maxItems=100),
    }, ("project_id", "mode", "documents"),
        description="SBOM documents require per_variant mode and cannot be mixed with reports."),
    "AgentUsage": _object({
        "cost": _NUMBER, "input_tokens": {**_INT, "nullable": True},
        "output_tokens": {**_INT, "nullable": True},
    }, ("cost", "input_tokens", "output_tokens")),
    "AgentMessageRequest": _object({
        "message": {"type": "string", "minLength": 1, "maxLength": 8000},
        "model": {"type": "string", "minLength": 1, "maxLength": 100},
        "context": _object({
            "page": {"type": "string", "enum": [
                "metrics", "packages", "vulnerabilities", "scans", "review",
                "exports", "settings", "ai", "unknown",
            ]},
            **{name: {"type": "string", "maxLength": 100} for name in (
                "projectId", "variantId", "baseVariantId", "compareOperation", "multiOperation",
            )},
            "variantIds": _STRINGS, "view": _ref("JsonObject"),
        }, ("page",), nullable=True),
    }, ("message",)),
    "AgentReply": _object({
        "reply": _STRING, "model": _STRING, "usage": _ref("AgentUsage"),
    }, ("reply", "model", "usage")),
    "AgentConversation": _object({
        "messages": _array(_object({
            "role": {"type": "string", "enum": ["user", "assistant"]}, "content": _STRING,
        }, ("role", "content"))),
        "usage": _ref("AgentUsage"),
    }, ("messages", "usage")),
    "AgentStatus": _object({
        "authenticated": _BOOL, "login": _TEXT, "configured": _BOOL, "device_login": _BOOL,
        "token_connected": _BOOL, "provider": _TEXT, "config_error": _TEXT,
        "model": _STRING, "usage": _ref("AgentUsage"),
        "messages": _array(_object({
            "role": {"type": "string", "enum": ["user", "assistant"]}, "content": _STRING,
        }, ("role", "content"))),
    }, ("authenticated", "configured", "messages", "model", "usage")),
    "AgentProviderRequest": _object({
        "provider": {"type": "string", "enum": ["openai", "azure", "anthropic", "local"]},
        "model": {"type": "string", "maxLength": 100},
        "api_key": {"type": "string", "maxLength": 4096, "writeOnly": True},
        "base_url": _STRING,
    }, ("provider",), description=(
        "Hosted providers require an API key; local providers use an HTTP loopback endpoint."
    )),
    "AgentProviderStatus": _object({"provider": _TEXT, "model": _STRING}, ("provider", "model")),
    "AgentModels": _object({
        "models": _array(_object({"id": _STRING, "name": _STRING}, ("id", "name"))),
    }, ("models",)),
    "AgentModelRequest": _object({"model": {"type": "string", "maxLength": 100}}, ("model",)),
    "AgentModelStatus": _object({"model": _STRING}, ("model",)),
    "AgentDeviceLogin": _object({
        "user_code": _STRING, "verification_uri": {"type": "string", "format": "uri"}, "interval": _INT,
    }, ("user_code", "verification_uri", "interval")),
    "AgentAuthStatus": {
        "anyOf": [
            _object({"status": {"type": "string", "enum": ["pending"]}, "interval": _INT}, ("status", "interval")),
            _object({
                "status": {"type": "string", "enum": ["connected"]}, "authenticated": _BOOL, "login": _TEXT,
            }, ("status", "authenticated", "login")),
            _object({"authenticated": _BOOL, "cleanup_error": _TEXT}, ("authenticated", "cleanup_error")),
        ],
    },
    "SourceReferenceResult": {
        "anyOf": [
            _object({
                "file_id": _UUID, "original_name": _STRING,
                "files": _array(_object({"path": _STRING, "size": _COUNT}, ("path", "size"))),
                "total": _COUNT, "next_offset": {**_COUNT, "nullable": True},
            }, ("file_id", "original_name", "files", "total", "next_offset")),
            _object({
                "file_id": _UUID, "original_name": _STRING, "path": _STRING, "content": _STRING,
                "start_line": _INT, "end_line": _INT, "total_lines": _COUNT,
                "next_line": {**_INT, "nullable": True},
            }, ("file_id", "original_name", "path", "content", "start_line", "end_line", "total_lines", "next_line")),
            _object({
                "file_id": _UUID, "original_name": _STRING, "truncated": _BOOL,
                "searched_files": _COUNT, "skipped_binary_files": _COUNT,
                "matches": _array(_object({"path": _STRING, "line": _INT, "text": _STRING}, ("path", "line", "text"))),
            }, ("file_id", "original_name", "matches", "truncated", "searched_files", "skipped_binary_files")),
        ],
    },
    "ContextExportProject": _object({
        "project_name": _STRING, "project_description": _TEXT,
        "variants": _array(_object({
            "variant_name": _STRING, **_CONTEXT_TEXT_FIELDS, "codebase_source": _CODEBASE_SOURCE,
            "system": _ref("ContextSystem"), "stride_model": _ref("StrideModel"),
            "files": _array(
                _object({"original_name": _STRING, "description": _TEXT}, ("original_name", "description")),
                description="Uploaded codebase references by name; contents are not exported and import ignores it.",
            ),
        }, ("variant_name",))),
    }, ("project_name", "project_description", "variants")),
    "ContextExport": _object({
        "version": {"type": "string", "example": "2.0"},
        "exported_at": _DATE, "projects": _array(_ref("ContextExportProject")),
    }, ("version", "exported_at", "projects")),
    "ContextImportEntry": _object({"project_name": _TEXT, "variant_name": _TEXT, "reason": _STRING}),
    "ContextImportResult": _object({
        "imported": _array(_ref("ContextImportEntry")),
        "ignored": _array(_ref("ContextImportEntry")),
        "failed": _array(_ref("ContextImportEntry")),
    }, ("imported", "ignored", "failed")),
    "MatchConditionRequest": _object({
        "condition": {"type": "string", "minLength": 1, "maxLength": 1000},
        "items": _array(_object({"id": _STRING, "data": _ref("JsonObject")}, ("id", "data")), maxItems=50000),
    }, ("condition", "items")),
    "MatchConditionResult": _object({"matching_ids": _STRINGS}, ("matching_ids",)),
    "DescriptionSearchRequest": _object({
        "vulnerability_ids": _array(_VULN_ID, maxItems=100000),
        "terms": _array({"type": "string", "maxLength": 256}, maxItems=50),
    }, ("vulnerability_ids", "terms")),
    "DescriptionSearchResult": _object({
        "matches": _map(_VULNS, description="Normalized search term -> matching vulnerability identifiers."),
    }, ("matches",)),
    "CopyAssessmentsRequest": _object({
        "source_variant_id": _UUID, "target_variant_id": _UUID,
        "match_mode": {"type": "string", "enum": ["exact", "ignore_minor_version", "ignore_version"]},
        "version_precision": _INT,
        "copy_condition": {"type": "string", "enum": ["no_custom", "different_status", "different_value"]},
        "selections": _array(_object({
            "source_assessment_id": _UUID, "target_finding_id": _UUID,
        }, ("source_assessment_id", "target_finding_id"))),
    }, ("source_variant_id", "target_variant_id")),
    "CopyAssessmentDetails": _object({
        "simplified_status": _STRING, "status": _STRING, "justification": _TEXT,
        "status_notes": _TEXT, "impact_statement": _TEXT, "workaround": _TEXT, "responses": _STRINGS,
    }),
    "CopyCandidate": _object({
        "target_finding_id": _UUID, "target_package": _PACKAGE_ID,
        "already_has_custom": _BOOL, "selected": _BOOL,
    }, ("target_finding_id", "target_package", "already_has_custom", "selected")),
    "CopyAssessmentsResult": _object({
        "copied": _COUNT, "skipped": _COUNT, "message": _STRING,
    }, ("copied", "skipped", "message")),
    "DependencyGraph": {
        "anyOf": [
            _object({
                "documents": _array(_object({
                    "id": _UUID, "source_name": _STRING, "variant_id": _UUID, "variant_name": _STRING,
                    "dependencies_recorded": _BOOL,
                    "packages": _array(_object({
                        "id": _PACKAGE_ID, "name": _STRING, "version": _STRING,
                        "release_version": _TEXT, "source_revision": _TEXT,
                    }, ("id", "name", "version"))),
                    "edges": _array(_object({
                        "package_id": _PACKAGE_ID, "dependency_id": _PACKAGE_ID,
                    }, ("package_id", "dependency_id"))),
                }, ("id", "source_name", "variant_id", "variant_name", "packages", "edges"))),
            }, ("documents",)),
            _object({
                "counts": _map(_object({"in": _COUNT, "out": _COUNT}, ("in", "out"))),
                "unrecorded": _PACKAGES,
            }, ("counts", "unrecorded")),
        ],
    },
    "OutdatedCleanupSelection": _object({
        "candidate_ids": _object({
            "observations": _UUIDS, "assessments": _UUIDS,
            "package_pairs": _array(_object({
                "package_id": _UUID, "variant_id": _UUID,
            }, ("package_id", "variant_id"), additionalProperties=False)),
        }, ("observations", "assessments", "package_pairs"), additionalProperties=False),
    }, ("candidate_ids",)),
    "CleanupResult": {
        "anyOf": [
            _object({key: _COUNT for key in (
                "assessments_deleted", "assessment_targets_removed", "observations_deleted",
                "sbom_packages_deleted", "sbom_observations_deleted", "findings_deleted",
                "vulnerabilities_deleted", "packages_deleted",
            )}, ("assessments_deleted", "observations_deleted", "packages_deleted")),
            _object({"scans_deleted": _COUNT}, ("scans_deleted",)),
            _object({
                "vulnerabilities_deleted": _COUNT, "assessments_deleted": _COUNT, "findings_deleted": _COUNT,
            }, ("vulnerabilities_deleted", "assessments_deleted", "findings_deleted")),
        ],
    },
    "ReviewTimeEstimate": _object({
        "id": _UUID, "vuln_id": _VULN_ID, "variant_id": _NULL_UUID,
        **{key: _INT for key in _EFFORT_KEYS},
        **{f"{key}_iso": {"type": "string", "example": "PT8H"} for key in _EFFORT_KEYS},
        "vuln_texts": _array(_ref("VulnerabilityText")),
    }, ("id", "vuln_id", "variant_id", *_EFFORT_KEYS)),
    "ReviewCustomCVSS": _object({
        "id": _UUID, "vuln_id": _VULN_ID, "variant_id": _NULL_UUID,
        "version": _STRING, "vector_string": _STRING, "base_score": {"type": "number"},
        "author": _TEXT, "origin": _STRING, "vuln_texts": _array(_ref("VulnerabilityText")),
    }, ("id", "vuln_id", "variant_id", "version", "vector_string", "base_score")),
    "VariantActivePackages": _array(_object({
        "variant_id": _UUID, "active_packages": _PACKAGES,
        "findings": _array(_object({
            "finding_id": _UUID, "package": _PACKAGE_ID, "outdated": _BOOL,
        }, ("finding_id", "package", "outdated"))),
    }, ("variant_id", "active_packages", "findings"))),
    "VariantSnapshots": _array(_object({
        "variant_id": _UUID, "effort": _ref("Effort"), "custom_cvss": _array(_ref("CVSS")),
    }, ("variant_id", "effort", "custom_cvss"))),
    "CustomDataAssessment": _object({
        "vuln_id": _VULN_ID, "status": _STRING, "simplified_status": _STRING,
        "justification": _TEXT, "impact_statement": _TEXT, "status_notes": _TEXT, "workaround": _TEXT,
        "timestamp": _DATE, "packages": _PACKAGES, "variant": _TEXT, "variant_id": _NULL_UUID,
        "targets": _array(_object({
            "variant": _TEXT, "package": _PACKAGE_ID,
        }, ("variant", "package"))),
    }, ("vuln_id", "status", "packages"), description=(
        "Portable version-2 targets use variant names, not variant UUIDs, and preserve sparse package/variant pairs."
    )),
    "CustomDataDocument": _object({
        "version": {"type": "integer", "enum": [1, 2]},
        "exported_at": _DATE, "project_id": _UUID,
        "timestamp_policy": {"type": "string", "enum": ["original", "current"]},
        "assessments": _array(_ref("CustomDataAssessment")),
        "ai_assessments": _array(_ref("CustomDataAssessment")),
        "cvss": _array(_object({
            "vuln_id": _VULN_ID, "variant": _TEXT, "version": _STRING,
            "vector_string": _STRING, "base_score": {"type": "number"}, "author": _TEXT, "origin": _STRING,
        }, ("vuln_id", "version", "vector_string", "base_score"))),
        "time_estimates": _array(_object({
            "vuln_id": _VULN_ID, "variant": _TEXT,
            **{key: {"anyOf": [{"type": "integer"}, {"type": "string"}]} for key in _EFFORT_KEYS},
        }, ("vuln_id", *_EFFORT_KEYS))),
    }, ("version",), description=(
        "VulnScout custom-data export/import. Exports are version 2; legacy version 1 imports "
        "can use variant_id/variant fields instead of targets."
    )),
    "OpenVexDocument": _object({
        "@context": {"description": "OpenVEX JSON-LD context.", "example": "https://openvex.dev/ns/v0.2.0"},
        "@id": _STRING, "author": _STRING, "timestamp": _STRING, "version": _INT,
        "statements": _array(_object({
            "vulnerability": _object({"name": _VULN_ID, "@id": _STRING, "description": _STRING, "aliases": _STRINGS}),
            "products": _array(_object({"@id": _STRING, "identifiers": _map(_STRING)})),
            "status": {"type": "string", "enum": _OPENVEX_STATUSES},
            "justification": _STRING, "impact_statement": _STRING,
            "action_statement": _STRING, "timestamp": _STRING,
        }, description="Extensible OpenVEX statement; upstream extensions are preserved.")),
    }, ("@context", "statements"), description="OpenVEX JSON document, not an internal assessment serialization."),
}

SCHEMAS["Config"] = _object({
    "project": {**SCHEMAS["Project"], "nullable": True},
    "variant": {**SCHEMAS["Variant"], "nullable": True},
    **{key: _STRING for key in ("product_name", "author_name", "client_name", "contact_email", "grype_memlimit")},
}, ("project", "variant", "product_name", "author_name", "client_name", "contact_email", "grype_memlimit"))

_COPY_SOURCE = {
    "source_assessment_id": _UUID, "source_finding_id": _UUID,
    "vulnerability_id": _VULN_ID, "source_package": _PACKAGE_ID,
    "assessment_details": _ref("CopyAssessmentDetails"),
}
_COPY_SUMMARY = {"count": _COUNT, "skipped": _COUNT, "message": _STRING}
SCHEMAS["CopyAssessmentsPreview"] = {"anyOf": [
    _object({
        **_COPY_SUMMARY, "mode": {"type": "string", "enum": ["exact"]},
        "entries": _array(_object({**_COPY_SOURCE, **SCHEMAS["CopyCandidate"]["properties"]})),
    }, ("count", "skipped", "message", "mode", "entries")),
    _object({
        **_COPY_SUMMARY,
        "mode": {"type": "string", "enum": ["ignore_minor_version", "ignore_version"]},
        "groups": _array(_object({**_COPY_SOURCE, "candidates": _array(_ref("CopyCandidate"))})),
    }, ("count", "skipped", "message", "mode", "groups")),
]}

_CLEANUP_LABELS = {"package": _PACKAGE_ID, "project": _STRING, "variant": _STRING}
SCHEMAS["CleanupPreview"] = {"anyOf": [
    _object({
        "candidate_ids": SCHEMAS["OutdatedCleanupSelection"]["properties"]["candidate_ids"],
        "packages": _array(_object({
            **_CLEANUP_LABELS, "vulnerabilities": _VULNS,
            "linked_data": _object({
                "observations": _COUNT, "sbom_packages": _COUNT, "sbom_observations": _COUNT,
            }),
        })),
        "assessments": _array(_object({**_CLEANUP_LABELS, "vulnerability": _VULN_ID})),
    }, ("candidate_ids", "packages", "assessments")),
    _object({"scans": _array(_object({
        "id": _UUID, "description": _STRING, "timestamp": _DATE, "project": _STRING, "variant": _STRING,
    }, ("id", "description", "timestamp", "project", "variant")))}, ("scans",)),
    _object({
        "vulnerabilities": _array(_object({"id": _VULN_ID, "assessments": _COUNT}, ("id", "assessments"))),
    }, ("vulnerabilities",)),
]}

SCHEMAS.update({
    "AssessmentReview": _ref("AssessmentReviewRecord"),
    "OperationCancellation": _object({
        "status": {"type": "string", "enum": ["cancelling"]}, "op_id": _STRING,
    }, ("status", "op_id")),
    "QueueCancellation": _object({"cancelled": _COUNT}, ("cancelled",)),
    "OperationDismissal": _object({
        "status": {"type": "string", "enum": ["dismissed"]}, "op_id": _STRING,
    }, ("status", "op_id")),
    "ProjectContextUpdate": _object({"description": _TEXT}),
    "VariantContextUpdate": _object({
        **_CONTEXT_TEXT_FIELDS, "codebase_source": _CODEBASE_SOURCE,
        "system": _ref("ContextSystem"), "stride": _ref("StrideModel"),
    }, description=(
        "With stride, an editor save storing every field (codebase_source required; the STRIDE "
        "model must describe a threat model). Without stride, a full replacement of the text fields; "
        "threat_model and risks are read-only, and a new context uses codebase_source paths when "
        "codebase_path is given, otherwise references."
    )),
    "SbomUploadAccepted": _object({
        "op_id": _STRING, "scan_id": _UUID, "message": _STRING,
    }, ("op_id", "scan_id", "message")),
    "TemplateUploaded": _object({
        "id": _STRING, "category": _STRINGS, "message": _STRING,
    }, ("id", "category", "message")),
    "AssetUploaded": _object({"name": _STRING, "message": _STRING}, ("name", "message")),
    "ExportAccepted": _object({"op_id": _STRING}, ("op_id",)),
    "CleanupSelection": {"anyOf": [
        _ref("OutdatedCleanupSelection"),
        _object({"scan_ids": _UUIDS}, ("scan_ids",)),
        _object({"vulnerability_ids": _VULNS}, ("vulnerability_ids",)),
    ]},
})

_EXPORT_PACKAGE_FIELDS = {
    "package_name": _STRING, "package_version": _STRING, "supplier": _STRING, "sources": _STRINGS,
}
_EXPORT_UPGRADE_FIELDS = {
    "package_name": _STRING, "old_version": _STRING, "new_version": _STRING, "supplier": _STRING,
}
_EXPORT_FINDING = _object({
    **_EXPORT_PACKAGE_FIELDS, "vulnerability_id": _VULN_ID,
}, ("vulnerability_id", "package_name", "package_version"))
_EXPORT_ASSESSMENT = _object({
    **_EXPORT_PACKAGE_FIELDS, "vulnerability_id": _VULN_ID, "status": _STRING,
    "simplified_status": _STRING, "justification": _STRING,
    "impact_statement": _STRING, "status_notes": _STRING,
    "targets": _array(_object(_EXPORT_PACKAGE_FIELDS, ("package_name", "package_version"))),
}, ("vulnerability_id", "status"))
_EXPORT_META = {
    "export_version": {"type": "integer", "enum": [1]}, "scan_id": _UUID, "timestamp": _STRING,
    "scan_type": {"type": "string", "enum": ["import_sbom", "vulnerability_scan"]},
    "scan_source": _TEXT, "project_name": _TEXT, "variant_id": _UUID, "variant_name": _TEXT,
}
SCHEMAS["ScanExport"] = {"anyOf": [
    _object({
        **_EXPORT_META, "export_format": {"type": "string", "enum": ["scan-diff"]},
        "vulnerabilities": _VULNS, "findings": _array(_EXPORT_FINDING),
        "packages": _array(_object(_EXPORT_PACKAGE_FIELDS, ("package_name", "package_version"))),
        "assessments": _array(_EXPORT_ASSESSMENT),
        "newly_detected_vulns": _VULNS, "newly_detected_findings": _array(_EXPORT_FINDING),
        "newly_detected_assessments": _array(_EXPORT_ASSESSMENT),
        "diff": _object({
            **{f"vulns_{key}": _VULNS for key in ("added", "removed", "unchanged")},
            **{f"findings_{key}": _array(_EXPORT_FINDING) for key in ("added", "removed", "unchanged")},
            **{f"packages_{key}": _array(_object(_EXPORT_PACKAGE_FIELDS)) for key in ("added", "removed", "unchanged")},
            **{f"assessments_{key}": _array(_EXPORT_ASSESSMENT) for key in ("added", "removed", "unchanged")},
            "packages_upgraded": _array(_object(_EXPORT_UPGRADE_FIELDS)),
            "findings_upgraded": _array(_object({**_EXPORT_UPGRADE_FIELDS, "vulnerability_id": _VULN_ID})),
        }),
    }, (
        "export_version", "export_format", "scan_id", "scan_type", "timestamp",
        "variant_id", "vulnerabilities", "findings",
    )),
    _object({
        **_EXPORT_META, "export_format": {"type": "string", "enum": ["full-result"]},
        "packages": _array(_object(_EXPORT_PACKAGE_FIELDS, ("package_name", "package_version"))),
        "findings": _array(_EXPORT_FINDING),
        "vulnerabilities": _array(_object({
            "vulnerability_id": _VULN_ID, "sources": _STRINGS,
        }, ("vulnerability_id", "sources"))),
        "assessments": _array(_EXPORT_ASSESSMENT),
    }, ("export_version", "export_format", "scan_id", "scan_type", "timestamp", "variant_id",
        "packages", "findings", "vulnerabilities", "assessments")),
]}
_IMPORT_NONEMPTY_STRING = {"type": "string", "pattern": r"\S"}
_IMPORT_PACKAGE = _object({
    "package_name": _IMPORT_NONEMPTY_STRING, "package_version": _TEXT, "supplier": _TEXT,
}, ("package_name",))
_IMPORT_FINDING = _object({
    **_IMPORT_PACKAGE["properties"], "vulnerability_id": _IMPORT_NONEMPTY_STRING,
}, ("package_name", "vulnerability_id"))
_IMPORT_ASSESSMENT = _object({
    "vulnerability_id": _IMPORT_NONEMPTY_STRING, "status": _IMPORT_NONEMPTY_STRING,
    "package_name": _TEXT, "package_version": _TEXT, "supplier": _TEXT,
    "targets": _array(_IMPORT_PACKAGE, nullable=True),
    **{key: _TEXT for key in ("simplified_status", "status_notes", "justification", "impact_statement")},
}, ("vulnerability_id", "status"))
_SCAN_IMPORT_FIELDS = {
    "scan_id": _UUID, "scan_type": _EXPORT_META["scan_type"], "timestamp": _IMPORT_NONEMPTY_STRING,
    "project_name": _IMPORT_NONEMPTY_STRING, "variant_name": _IMPORT_NONEMPTY_STRING,
    "scan_source": _TEXT, "packages": _array(_IMPORT_PACKAGE, nullable=True),
    "findings": _array(_IMPORT_FINDING),
    "assessments": _array(_IMPORT_ASSESSMENT, nullable=True),
    "newly_detected_assessments": _array(_IMPORT_ASSESSMENT, nullable=True),
}
_SCAN_IMPORT_REQUIRED = ("scan_id", "scan_type", "timestamp", "project_name", "variant_name", "findings")
_SCAN_IMPORT_TYPES = [
    _object({
        "scan_type": {"type": "string", "enum": ["import_sbom"]}, "packages": _array(_IMPORT_PACKAGE),
    }, ("packages",)),
    _object({"scan_type": {"type": "string", "enum": ["vulnerability_scan"]}}),
]
SCHEMAS["ScanImportItem"] = _object({
    **_SCAN_IMPORT_FIELDS,
    "export_version": _EXPORT_META["export_version"],
    "export_format": {"type": "string", "enum": ["scan-diff", "full-result"]},
}, (*_SCAN_IMPORT_REQUIRED, "export_version", "export_format"), oneOf=_SCAN_IMPORT_TYPES,
    description="Versioned scan import; packages are required only for import_sbom scans.")
SCHEMAS["LegacyScanExport"] = _object(
    _SCAN_IMPORT_FIELDS, (*_SCAN_IMPORT_REQUIRED, "packages"), oneOf=_SCAN_IMPORT_TYPES,
    **{"not": {"anyOf": [{"required": ["export_version"]}, {"required": ["export_format"]}]}},
    description="Legacy full-result import with neither export_version nor export_format markers.",
)
_SCAN_IMPORT_ITEM = {"oneOf": [_ref("ScanImportItem"), _ref("LegacyScanExport")]}
SCHEMAS["ScanImport"] = {
    "anyOf": [_SCAN_IMPORT_ITEM, _array(_SCAN_IMPORT_ITEM, minItems=1, maxItems=200)],
    "description": "One scan export or a list; legacy unversioned full-result exports are also accepted.",
}

SCHEMAS.update({
    "CustomDataImport": {
        "allOf": [
            _ref("CustomDataDocument"),
            _object({"project_id": _UUID}, ("project_id",)),
        ],
    },
    "ReviewExport": {"anyOf": [_ref("OpenVexDocument"), _ref("CustomDataDocument")]},
    "AssessmentBatchResult": _object({
        "status": _STRING, "assessments": _array(_ref("Assessment")),
        "count": _COUNT, "vuln_count": _COUNT,
        "errors": _array(_ref("Error")), "error_count": _COUNT,
    }, ("status", "assessments", "count")),
    "NvdRefreshRequest": _object({
        "mode": {"type": "string", "enum": ["local", "api"], "default": "local"},
    }),
    "VulnerabilityRefreshResponse": _object({
        "vulnerabilities": _array(_ref("Vulnerability")),
    }, ("vulnerabilities",)),
    "ScanImportResult": SCHEMAS["ImportSummary"]["anyOf"][2],
})
