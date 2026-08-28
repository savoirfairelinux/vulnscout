# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan CRUD and list/diff/global-result route handlers.

Computation helpers live in sibling modules:
- ``_scan_queries``  — low-level DB batch queries
- ``_scan_diff``     — diff algorithms & list-view serialisation
"""

import re
import uuid as uuid_module
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timezone
from typing import NamedTuple, TypedDict, TypeVar, cast

from flask import Flask, jsonify, request as flask_request
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import RequestEntityTooLarge

from ..controllers.scans import ScanController
from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..models.observation import Observation
from ..models.assessment import Assessment
from ..models.assessment_target import AssessmentTarget
from ..models.finding import Finding
from ..models.package import Package, _normalize_supplier
from ..models.project import Project
from ..models.scan import Scan
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.variant import Variant
from ..models.vulnerability import Vulnerability
from ..extensions import db

from ._scan_queries import (
    _packages_by_scan_ids,
    _package_rows,
    _pkg_to_dict,
    _load_scan_with_findings,
    _obs_to_dict,
    _origin_for_scan,
    _assessments_detail_for_scan,
    ObsDict,
)
from ._scan_diff import (
    _classify_package_changes,
    _contributing_scans_at,
    _contributing_scans_before,
    _global_result_id_sets,
    _global_assessment_ids_for,
    _global_result_full,
    invalidate_scan_list_cache,
    serialize_list_with_diff_cached,
)


# ---------------------------------------------------------------------------
# Re-export for backward compatibility with external consumers
# (merger_ci, test_scan, scan_triggers, settings)
# ---------------------------------------------------------------------------
# These are accessed via ``from ..routes.scans import <name>``.
# After all call-sites are updated the re-exports can be removed.
from ._scan_queries import (  # noqa: F401  — re-exports
    _findings_by_scan_ids,
    _vulns_by_scan_ids,
    _variant_info,
    _TOOL_SOURCE_LABELS,
)
from ._scan_diff import (  # noqa: F401  — re-exports
    _classify_finding_changes,
    _prev_scan_map,
    _serialize_list_with_diff,
)

_STALE_CLEANUP_PREVIEW_ERROR = "Cleanup preview is no longer current. Review it again before deleting."


def _cleanup_candidates(body: object, key: str, validator: Callable[[object], bool]) -> object | None:
    """Return a validated cleanup candidate field, or reject malformed API input."""
    if not isinstance(body, dict) or key not in body or not validator(body[key]):
        return None
    return body[key]


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_outdated_candidates(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"observations", "assessments", "package_pairs"}
        and _is_string_list(value["observations"])
        and _is_string_list(value["assessments"])
        and isinstance(value["package_pairs"], list)
        and all(
            isinstance(pair, dict)
            and set(pair) == {"package_id", "variant_id"}
            and all(isinstance(item, str) for item in pair.values())
            for pair in value["package_pairs"]
        )
    )


# ---------------------------------------------------------------------------
# Scan export helpers — mirror the frontend strip/transform functions
# ---------------------------------------------------------------------------

def _extract_supplier_name(supplier: str) -> str:
    """Strip SPDX-style prefix and trailing email from a supplier string."""
    s = re.sub(r'^[^:]+:\s*', '', supplier)
    return re.sub(r'\s*\([^)]*\)$', '', s)


def _scan_meta(scan: Scan, variant_name: str | None = None, project_name: str | None = None) -> dict[str, object]:
    """Build scan metadata dict for export."""
    scan_type = scan.scan_type or "sbom"
    ts: str | datetime = scan.timestamp
    if isinstance(ts, datetime):
        ts = ts.isoformat()
    return {
        "export_version": 1,
        "scan_id": str(scan.id),
        "timestamp": ts,
        "scan_type": "vulnerability_scan" if scan_type == "tool" else "import_sbom",
        "scan_source": scan.scan_source or None,
        "project_name": project_name or None,
        "variant_id": str(scan.variant_id),
        "variant_name": variant_name or None,
    }


def _strip_finding(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "package_name": entry.get("package_name", ""),
        "package_version": entry.get("package_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_package(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "package_name": entry.get("package_name", ""),
        "package_version": entry.get("package_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_package_upgrade(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "package_name": entry.get("package_name", ""),
        "old_version": entry.get("old_version", ""),
        "new_version": entry.get("new_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_finding_upgrade(entry: dict) -> dict:
    supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
    result = {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "package_name": entry.get("package_name", ""),
        "old_version": entry.get("old_version", ""),
        "new_version": entry.get("new_version", ""),
    }
    if supplier:
        result["supplier"] = supplier
    return result


def _strip_assessment(entry: dict) -> dict:
    result = {
        "vulnerability_id": entry.get("vulnerability_id", ""),
        "status": entry.get("status", ""),
        "simplified_status": entry.get("simplified_status", ""),
        "justification": entry.get("justification", ""),
        "impact_statement": entry.get("impact_statement", ""),
        "status_notes": entry.get("status_notes", ""),
    }
    # Identify the finding the assessment belongs to. Without it an importer
    # can only guess, and would attach the assessment to every package sharing
    # the vulnerability — asserting things the source never said.
    package_name = entry.get("package_name", "")
    if package_name:
        result["package_name"] = package_name
        result["package_version"] = entry.get("package_version", "")
        supplier = _extract_supplier_name(entry.get("package_supplier", "") or "")
        if supplier:
            result["supplier"] = supplier
    return result


def _build_diff_export(
    scan: Scan,
    diff: dict,
    variant_name: str | None = None,
    project_name: str | None = None,
) -> dict[str, object]:
    """Build the export-ready dict from a scan and its diff response."""
    meta = _scan_meta(scan, variant_name, project_name)
    meta["export_format"] = "scan-diff"
    is_tool = (scan.scan_type or "sbom") == "tool"

    if is_tool:
        return {
            **meta,
            "vulnerabilities": diff.get("all_vulns") or diff.get("vulns_added", []),
            "findings": [
                _strip_finding(f)
                for f in (diff.get("all_findings") or diff.get("findings_added", []))
            ],
            "newly_detected_vulns": diff.get("newly_detected_vulns_list") or [],
            "newly_detected_findings": [
                _strip_finding(f)
                for f in (diff.get("newly_detected_findings_list") or [])
            ],
            "newly_detected_assessments": [
                _strip_assessment(a)
                for a in (diff.get("newly_detected_assessments_list") or [])
            ],
        }

    # SBOM scan
    base: dict = {
        **meta,
        "vulnerabilities": diff.get("all_vulns") or (diff.get("vulns_added", []) + diff.get("vulns_unchanged", [])),
        "findings": [
            _strip_finding(f)
            for f in (
                diff.get("all_findings")
                or (diff.get("findings_added", []) + diff.get("findings_unchanged", []))
            )
        ],
        "packages": [
            _strip_package(p)
            for p in (diff.get("packages_added", []) + diff.get("packages_unchanged", []))
        ],
        "assessments": [
            _strip_assessment(a)
            for a in (
                list(diff.get("assessments_added") or [])
                + list(diff.get("assessments_unchanged") or [])
            )
        ],
    }

    if not diff.get("is_first", True):
        base["diff"] = {
            "vulns_added": diff.get("vulns_added", []),
            "vulns_removed": diff.get("vulns_removed", []),
            "vulns_unchanged": diff.get("vulns_unchanged", []),
            "findings_added": [_strip_finding(f) for f in diff.get("findings_added", [])],
            "findings_removed": [_strip_finding(f) for f in diff.get("findings_removed", [])],
            "findings_upgraded": [_strip_finding_upgrade(f) for f in diff.get("findings_upgraded", [])],
            "findings_unchanged": [_strip_finding(f) for f in diff.get("findings_unchanged", [])],
            "packages_added": [_strip_package(p) for p in diff.get("packages_added", [])],
            "packages_removed": [_strip_package(p) for p in diff.get("packages_removed", [])],
            "packages_upgraded": [_strip_package_upgrade(p) for p in diff.get("packages_upgraded", [])],
            "packages_unchanged": [_strip_package(p) for p in diff.get("packages_unchanged", [])],
            "assessments_added": [_strip_assessment(a) for a in (diff.get("assessments_added") or [])],
            "assessments_removed": [_strip_assessment(a) for a in (diff.get("assessments_removed") or [])],
            "assessments_unchanged": [_strip_assessment(a) for a in (diff.get("assessments_unchanged") or [])],
        }

    return base


def _build_global_result_export(
    scan: Scan,
    result: dict,
    variant_name: str | None = None,
    project_name: str | None = None,
) -> dict[str, object]:
    """Build the export-ready dict from a scan and its global result."""
    meta = _scan_meta(scan, variant_name, project_name)
    meta["export_format"] = "full-result"
    return {
        **meta,
        "packages": [
            {
                "package_name": p.get("package_name", ""),
                "package_version": p.get("package_version", ""),
                **({"supplier": s} if (s := _extract_supplier_name(p.get("package_supplier", "") or "")) else {}),
                "sources": p.get("sources", []),
            }
            for p in result.get("packages", [])
        ],
        "findings": [
            {
                "vulnerability_id": f.get("vulnerability_id", ""),
                "package_name": f.get("package_name", ""),
                "package_version": f.get("package_version", ""),
                **({"supplier": s} if (s := _extract_supplier_name(f.get("package_supplier", "") or "")) else {}),
                "sources": f.get("sources", []),
            }
            for f in result.get("findings", [])
        ],
        "vulnerabilities": [
            {
                "vulnerability_id": v.get("vulnerability_id", ""),
                "sources": v.get("sources", []),
            }
            for v in result.get("vulnerabilities", [])
        ],
        "assessments": [_strip_assessment(a) for a in result.get("assessments", [])],
    }


def _sanitize_filename(name: str) -> str:
    """Sanitize a string for use in a filename."""
    s = re.sub(r'\s+', '_', name)
    s = re.sub(r'[<>:"/\\|?*]+', '', s)
    s = re.sub(r'_+', '_', s)
    return s.strip('_')


def _format_timestamp_for_filename(dt: datetime | str | None = None) -> str:
    """Format a datetime (or now) as YYYYMMDD_HHmmss for filenames."""
    if dt is None:
        d = datetime.now(timezone.utc)
    elif isinstance(dt, str):
        d = datetime.fromisoformat(dt)
    else:
        d = dt
    return d.strftime('%Y%m%d_%H%M%S')


# ---------------------------------------------------------------------------
# Scan import — validation
# ---------------------------------------------------------------------------
#
# Importing is a two-phase operation:
#
#   1. every export in the request is parsed and validated against the
#      destination database *without writing anything*, and
#   2. only once all of them are known to be importable are they persisted,
#      inside the single transaction the request handler commits.
#
# Splitting the phases keeps a bad entry halfway through a bulk import from
# doing any work at all, and lets validation errors name the offending entry.

#: ``source`` recorded on rows created by an import.
_IMPORT_SOURCE_LABEL = "Imported VulnScout scan"
#: The only ``export_version`` this importer understands.
_SUPPORTED_EXPORT_VERSION = 1
#: Upper bound on exports accepted in one request, mirroring MAX_EXPORT_SCANS.
_MAX_IMPORT_EXPORTS = 200
#: Batch size for ``IN`` lookups, kept well under SQLite's parameter limit.
_IMPORT_QUERY_CHUNK = 400

#: (name, version, supplier) identity of a package within an export.
PackageKey = tuple[str, str, str]
#: (package identity, vulnerability id) identity of a finding within an export.
FindingKey = tuple[PackageKey, str]

_T = TypeVar("_T")


class _ImportSummary(TypedDict):
    """What importing one export created, as reported back to the caller."""

    scan_id: str
    source_scan_id: str
    format: str                 # 'diff' | 'full'
    project_name: str
    variant_name: str
    package_count: int
    finding_count: int
    vulnerability_count: int
    assessment_count: int
    is_first: bool


class _ScanImport(NamedTuple):
    """One validated export, resolved against the destination database."""

    source_scan_id: uuid_module.UUID
    export_format: str          # 'scan-diff' | 'full-result'
    variant: Variant
    project_name: str
    variant_name: str
    scan_type: str              # 'sbom' | 'tool'
    scan_source: str | None
    timestamp: datetime
    package_keys: list[PackageKey]
    findings: list[FindingKey]
    assessments: list["_ImportAssessment"]


def _chunked(items: Sequence[_T], size: int) -> Iterator[Sequence[_T]]:
    """Yield *items* in slices of at most *size* elements."""
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _required_import_string(payload: dict, key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    return value.strip()


def _optional_import_string(payload: dict, key: str) -> str:
    """Return a string field that may be absent or null, defaulting to ''."""
    value = payload.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    return value


def _import_array(payload: dict, key: str, required: bool) -> list:
    value = payload.get(key)
    if value is None and not required:
        return []
    if not isinstance(value, list):
        raise ValueError(f"'{key}' must be an array")
    return value


def _import_destination(project_name: str, variant_name: str) -> Variant:
    project = db.session.execute(
        db.select(Project).where(Project.name == project_name)
    ).scalar_one_or_none()
    if project is None:
        raise LookupError(f"Project '{project_name}' was not found")
    variant = Variant.get_by_name_and_project(variant_name, project.id)
    if variant is None:
        raise LookupError(
            f"Variant '{variant_name}' was not found in project '{project_name}'"
        )
    return variant


def _import_scan_metadata(
    payload: dict,
) -> tuple[uuid_module.UUID, str, str | None, datetime]:
    """Validate and extract scan metadata from an import payload.

    The exported ``scan_id`` identifies the source scan. It is recorded on the
    destination Scan as ``source_scan_id`` so the same export cannot be
    imported twice, but it is never reused as the destination primary key.
    """
    scan_id_text = _required_import_string(payload, "scan_id")
    try:
        source_scan_id = uuid_module.UUID(scan_id_text)
    except ValueError as exc:
        raise ValueError("'scan_id' must be a UUID") from exc

    exported_scan_type = _required_import_string(payload, "scan_type")
    if exported_scan_type not in {"import_sbom", "vulnerability_scan"}:
        raise ValueError(
            "'scan_type' must be 'import_sbom' or 'vulnerability_scan'"
        )

    scan_type = "sbom" if exported_scan_type == "import_sbom" else "tool"
    scan_source = _optional_import_string(payload, "scan_source")

    timestamp_text = _required_import_string(payload, "timestamp")
    try:
        timestamp = datetime.fromisoformat(
            timestamp_text.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("'timestamp' must be an ISO 8601 datetime") from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return source_scan_id, scan_type, scan_source or None, timestamp


def _import_package_key(entry: object) -> PackageKey:
    """Return the package identity carried by a package or finding entry."""
    if not isinstance(entry, dict):
        raise ValueError("Package and finding entries must be JSON objects")
    return (
        _required_import_string(entry, "package_name"),
        _optional_import_string(entry, "package_version"),
        # Match the normalisation Package applies on write, so a lookup for an
        # already-known package finds it instead of inserting a duplicate.
        _normalize_supplier(_optional_import_string(entry, "supplier")),
    )


class _ImportAssessment(NamedTuple):
    """One assessment from an export, with the finding it belongs to."""

    vulnerability_id: str
    #: The assessed package, when the export records one.  Exports written
    #: before assessments carried their package leave this ``None``, and the
    #: assessment then applies to every finding for its vulnerability.
    package_key: PackageKey | None
    values: dict[str, str]


def _import_assessment_entry(entry: object) -> _ImportAssessment:
    if not isinstance(entry, dict):
        raise ValueError("Assessment entries must be JSON objects")
    package_key = _import_package_key(entry) if entry.get("package_name") else None
    return _ImportAssessment(
        vulnerability_id=_required_import_string(entry, "vulnerability_id").upper(),
        package_key=package_key,
        values={
            "status": _required_import_string(entry, "status"),
            "simplified_status": _optional_import_string(entry, "simplified_status"),
            "status_notes": _optional_import_string(entry, "status_notes"),
            "justification": _optional_import_string(entry, "justification"),
            "impact_statement": _optional_import_string(entry, "impact_statement"),
        },
    )


def _parse_scan_export(payload: object) -> _ScanImport:
    """Validate one export against the destination DB without writing to it."""
    if not isinstance(payload, dict):
        raise ValueError("Scan export must be a JSON object")

    # Exports predating the versioned format carry neither marker but are
    # recognisable by their full-result field set.
    is_legacy_full_result = (
        "export_version" not in payload
        and "export_format" not in payload
        and {
            "scan_id",
            "scan_type",
            "timestamp",
            "project_name",
            "variant_name",
            "packages",
            "findings",
        }.issubset(payload)
    )

    if (
        not is_legacy_full_result
        and payload.get("export_version") != _SUPPORTED_EXPORT_VERSION
    ):
        raise ValueError(
            f"'export_version' must be {_SUPPORTED_EXPORT_VERSION}"
        )

    export_format = (
        "full-result" if is_legacy_full_result else payload.get("export_format")
    )
    if export_format not in {"scan-diff", "full-result"}:
        raise ValueError("'export_format' must be 'scan-diff' or 'full-result'")

    project_name = _required_import_string(payload, "project_name")
    variant_name = _required_import_string(payload, "variant_name")
    variant = _import_destination(project_name, variant_name)

    source_scan_id, scan_type, scan_source, timestamp = _import_scan_metadata(payload)

    # Both export formats carry the scan's complete state in the top-level
    # ``packages`` / ``findings`` arrays.  A ``diff`` block, when present, is
    # derived from the source variant's history and is deliberately ignored:
    # the destination recomputes its own diff from its own timeline.
    findings_raw = _import_array(payload, "findings", required=True)
    packages_raw = _import_array(payload, "packages", required=(scan_type == "sbom"))

    package_keys: list[PackageKey] = []
    seen_packages: set[PackageKey] = set()
    for entry in packages_raw:
        key = _import_package_key(entry)
        if key not in seen_packages:
            seen_packages.add(key)
            package_keys.append(key)

    findings: list[FindingKey] = []
    seen_findings: set[FindingKey] = set()
    for entry in findings_raw:
        key = _import_package_key(entry)
        if key not in seen_packages:
            seen_packages.add(key)
            package_keys.append(key)
        pair = (key, _required_import_string(entry, "vulnerability_id").upper())
        if pair not in seen_findings:
            seen_findings.add(pair)
            findings.append(pair)

    # Full-result exports list assessments under ``assessments``; tool diff
    # exports list them under ``newly_detected_assessments``.
    assessments = [
        _import_assessment_entry(entry)
        for key in ("assessments", "newly_detected_assessments")
        for entry in _import_array(payload, key, required=False)
    ]
    known_vulns = {vulnerability_id for _key, vulnerability_id in findings}
    unmatched = sorted({a.vulnerability_id for a in assessments} - known_vulns)
    if unmatched:
        raise ValueError(
            "Assessments reference vulnerabilities with no matching finding: "
            + ", ".join(unmatched[:5])
            + (f" (+{len(unmatched) - 5} more)" if len(unmatched) > 5 else "")
        )

    return _ScanImport(
        source_scan_id=source_scan_id,
        export_format=export_format,
        variant=variant,
        project_name=project_name,
        variant_name=variant_name,
        scan_type=scan_type,
        scan_source=scan_source,
        timestamp=timestamp,
        package_keys=package_keys,
        findings=findings,
        assessments=assessments,
    )


# ---------------------------------------------------------------------------
# Scan import — persistence
# ---------------------------------------------------------------------------

def _resolve_import_packages(
    keys: Sequence[PackageKey],
) -> dict[PackageKey, Package]:
    """Map every package identity to a persisted Package, creating misses.

    Existing packages are fetched in a handful of batched queries rather than
    one round-trip per entry, which is what makes a large import finish.
    """
    if not keys:
        return {}

    names = sorted({name for name, _version, _supplier in keys})
    known: dict[PackageKey, Package] = {}
    for chunk in _chunked(names, _IMPORT_QUERY_CHUNK):
        for package in db.session.execute(
            db.select(Package).where(Package.name.in_(chunk))
        ).scalars().all():
            stored = (package.name or "", package.version or "", package.supplier or "")
            known.setdefault(stored, package)
            # Export reduces a supplier to its bare name, dropping any SPDX
            # prefix and contact address, so an export of "Organization: PNG
            # Group (png@example.com)" comes back as "PNG Group". Index that
            # form too, or re-importing would create a second row for a
            # package the destination already has.
            as_exported = (stored[0], stored[1], _extract_supplier_name(stored[2]))
            if as_exported != stored:
                known.setdefault(as_exported, package)

    created = False
    for key in keys:
        if key in known:
            continue
        name, version, supplier = key
        package = Package(
            name=name, version=version, cpe=[], purl=[],
            licences="", supplier=supplier,
        )
        db.session.add(package)
        known[key] = package
        created = True

    if created:
        db.session.flush()  # assign primary keys before findings reference them
    return {key: known[key] for key in keys}


def _ensure_import_vulnerabilities(vulnerability_ids: set[str]) -> None:
    """Create placeholder Vulnerability rows for ids not yet in the database."""
    if not vulnerability_ids:
        return
    ordered = sorted(vulnerability_ids)
    existing: set[str] = set()
    for chunk in _chunked(ordered, _IMPORT_QUERY_CHUNK):
        existing.update(db.session.execute(
            db.select(Vulnerability.id).where(Vulnerability.id.in_(chunk))
        ).scalars().all())

    missing = [vuln_id for vuln_id in ordered if vuln_id not in existing]
    for vulnerability_id in missing:
        db.session.add(Vulnerability(id=vulnerability_id))
    if missing:
        db.session.flush()


def _resolve_import_findings(
    pairs: Sequence[tuple[uuid_module.UUID, str]],
) -> dict[tuple[uuid_module.UUID, str], Finding]:
    """Map every (package, vulnerability) pair to a Finding, creating misses."""
    if not pairs:
        return {}

    package_ids = sorted({package_id for package_id, _vuln in pairs}, key=str)
    known: dict[tuple[uuid_module.UUID, str], Finding] = {}
    for chunk in _chunked(package_ids, _IMPORT_QUERY_CHUNK):
        for finding in db.session.execute(
            db.select(Finding).where(Finding.package_id.in_(chunk))
        ).scalars().all():
            known[(finding.package_id, finding.vulnerability_id)] = finding

    created = False
    for pair in pairs:
        if pair in known:
            continue
        package_id, vulnerability_id = pair
        finding = Finding(package_id=package_id, vulnerability_id=vulnerability_id)
        db.session.add(finding)
        known[pair] = finding
        created = True

    if created:
        db.session.flush()  # assign primary keys before observations reference them
    return {pair: known[pair] for pair in pairs}


def _assessment_identity(
    finding_id: uuid_module.UUID, entry: dict[str, str]
) -> tuple:
    return (
        finding_id,
        entry["status"],
        entry["simplified_status"],
        entry["status_notes"],
        entry["justification"],
        entry["impact_statement"],
    )


def _existing_assessment_identities(
    variant_id: uuid_module.UUID,
    finding_ids: Sequence[uuid_module.UUID],
) -> set[tuple]:
    """Return identities of assessments already attached to these findings.

    Joins through ``assessment_targets`` rather than the assessment's scalar
    ``finding_id``/``variant_id`` columns, so a genuine multi-target
    assessment (created with no scalar columns set) is still recognised as
    already covering one of its targets — the scalar columns would read as
    ``None`` for such a row and collapse every one of them into the same
    false identity.
    """
    identities: set[tuple] = set()
    for chunk in _chunked(finding_ids, _IMPORT_QUERY_CHUNK):
        rows = db.session.execute(
            db.select(
                AssessmentTarget.finding_id,
                Assessment.status,
                Assessment.simplified_status,
                Assessment.status_notes,
                Assessment.justification,
                Assessment.impact_statement,
            )
            .join(Assessment, Assessment.id == AssessmentTarget.assessment_id)
            .where(
                AssessmentTarget.variant_id == variant_id,
                AssessmentTarget.finding_id.in_(chunk),
            )
        ).all()
        for finding_id, status, simplified_status, status_notes, justification, impact_statement in rows:
            identities.add(_assessment_identity(finding_id, {
                "status": status or "",
                "simplified_status": simplified_status or "",
                "status_notes": status_notes or "",
                "justification": justification or "",
                "impact_statement": impact_statement or "",
            }))
    return identities


def _utc_key(value: datetime) -> str:
    """Normalise a timestamp to a UTC string that compares reliably.

    Comparing datetimes through the database would depend on how each backend
    stores time zones, so identity comparisons are made in Python instead.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _is_first_scan_of_its_kind(scan: Scan) -> bool:
    """Whether *scan* is the earliest of its type/source in its variant.

    Mirrors the previous-scan selection in ``_compute_diff_dict`` without
    paying for a full diff computation.
    """
    scan_type = scan.scan_type or "sbom"
    same_kind = [
        sibling for sibling in ScanController.get_by_variant(scan.variant_id)
        if (sibling.scan_type or "sbom") == scan_type
        and (sibling.scan_source == scan.scan_source if scan_type == "tool" else True)
    ]
    return bool(same_kind) and same_kind[0].id == scan.id


def _persist_scan_import(item: _ScanImport) -> _ImportSummary:
    """Persist one validated export and return a summary of what it created."""
    # The id in the export belongs to the source scan and is not reused: Scan.id
    # keeps its uuid4 default so the destination gets its own identity. The scan
    # is instead recognised on a later import by its variant, kind and timestamp.
    scan = Scan(
        description=(
            f"Imported scan from {item.project_name} / {item.variant_name}"
        ),
        scan_type=item.scan_type,
        scan_source=item.scan_source,
        timestamp=item.timestamp,
        variant_id=item.variant.id,
    )
    db.session.add(scan)
    db.session.flush()

    packages = _resolve_import_packages(item.package_keys)

    if item.scan_type == "sbom":
        # SBOM scans expose their package set through an SBOM document; tool
        # scans reach theirs through their findings and need none.
        document = SBOMDocument(
            path=f"imported-scan://{scan.id}",
            source_name=_IMPORT_SOURCE_LABEL,
            format="vulnscout_json",
            scan_id=scan.id,
        )
        db.session.add(document)
        db.session.flush()
        # Two export entries can resolve to one row (e.g. suppliers that
        # normalise to the same value), so link each package only once.
        for package_id in {package.id for package in packages.values()}:
            db.session.add(SBOMPackage(
                sbom_document_id=document.id,
                package_id=package_id,
            ))

    vulnerability_ids = {vulnerability_id for _key, vulnerability_id in item.findings}
    _ensure_import_vulnerabilities(vulnerability_ids)

    finding_pairs = [
        (packages[package_key].id, vulnerability_id)
        for package_key, vulnerability_id in item.findings
    ]
    findings = _resolve_import_findings(finding_pairs)

    findings_by_vulnerability: dict[str, list[Finding]] = {}
    findings_by_pair: dict[FindingKey, Finding] = {}
    observed: set[uuid_module.UUID] = set()
    for package_key, vulnerability_id in item.findings:
        finding = findings[(packages[package_key].id, vulnerability_id)]
        findings_by_pair[(package_key, vulnerability_id)] = finding
        if finding.id in observed:
            continue
        observed.add(finding.id)
        findings_by_vulnerability.setdefault(vulnerability_id, []).append(finding)
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))

    assessment_count = _persist_import_assessments(
        item, findings_by_vulnerability, findings_by_pair
    )

    db.session.flush()
    return _ImportSummary(
        scan_id=str(scan.id),
        source_scan_id=str(item.source_scan_id),
        format="diff" if item.export_format == "scan-diff" else "full",
        project_name=item.project_name,
        variant_name=item.variant_name,
        package_count=len(item.package_keys),
        finding_count=len(item.findings),
        vulnerability_count=len(vulnerability_ids),
        assessment_count=assessment_count,
        is_first=_is_first_scan_of_its_kind(scan),
    )


def _persist_import_assessments(
    item: _ScanImport,
    findings_by_vulnerability: dict[str, list[Finding]],
    findings_by_pair: dict[FindingKey, Finding],
) -> int:
    """Create the export's assessments, skipping ones already present.

    An assessment belongs to one (package, vulnerability) finding.  When the
    export names the package the assessment is attached to exactly that
    finding; only for older exports that omit it does it fall back to every
    finding sharing the vulnerability.  Re-importing a file — or importing two
    exports that share an assessment — must not duplicate it, so identical
    assessments already on the destination variant are left alone.
    """
    if not item.assessments:
        return 0

    # Every automatically-produced assessment records where it came from
    # (``sbom``, ``nvd``, ``grype``, …); an imported one must carry the
    # origin a natively-produced one of the same kind would have, so it
    # reads the same way on the destination as it did on the source.
    origin = item.scan_source if item.scan_type == "tool" else "sbom"

    finding_ids = sorted(
        {finding.id for findings in findings_by_vulnerability.values() for finding in findings},
        key=str,
    )
    seen = _existing_assessment_identities(item.variant.id, finding_ids)

    created = 0
    for entry in item.assessments:
        if entry.package_key is not None:
            finding = findings_by_pair.get((entry.package_key, entry.vulnerability_id))
            targets = [finding] if finding is not None else []
        else:
            targets = findings_by_vulnerability.get(entry.vulnerability_id, [])
        for target in targets:
            identity = _assessment_identity(target.id, entry.values)
            if identity in seen:
                continue
            seen.add(identity)
            Assessment.create(
                status=entry.values["status"],
                finding_id=target.id,
                variant_id=item.variant.id,
                source=_IMPORT_SOURCE_LABEL,
                origin=origin or "sbom",
                simplified_status=entry.values["simplified_status"],
                status_notes=entry.values["status_notes"],
                justification=entry.values["justification"],
                impact_statement=entry.values["impact_statement"],
                commit=False,
            )
            created += 1
    return created


def _import_scan_exports(exports: Sequence[object]) -> tuple[list[_ImportSummary], int]:
    """Validate exports and persist only scans absent from their destination."""
    parsed: list[_ScanImport] = []
    batch_keys: set[tuple[uuid_module.UUID, str, str | None, str]] = set()
    skipped_count = 0

    for index, export in enumerate(exports):
        try:
            item = _parse_scan_export(export)
        except (TypeError, ValueError, LookupError) as exc:
            raise type(exc)(_import_entry_error(index, len(exports), exc)) from exc

        location = f"'{item.project_name}' / '{item.variant_name}'"
        described = f"scan '{item.source_scan_id}' ({_utc_key(item.timestamp)})"

        # Guard against the same scan arriving twice in one request as well as
        # against one already present in the destination.
        batch_key = (
            item.variant.id, item.scan_type, item.scan_source,
            _utc_key(item.timestamp),
        )
        if batch_key in batch_keys:
            raise FileExistsError(_import_entry_error(
                index, len(exports),
                f"{described} appears more than once for {location} "
                f"in this import",
            ))
        batch_keys.add(batch_key)

        if _find_duplicate_scan(item) is not None:
            skipped_count += 1
            continue
        parsed.append(item)

    try:
        return ([_persist_scan_import(item) for item in parsed], skipped_count)
    except LookupError as exc:
        # Every destination lookup already succeeded during validation, so a
        # LookupError here is an internal fault. Re-raise it as one rather than
        # letting the route report it to the client as a missing destination.
        raise RuntimeError("Failed to persist a validated scan import") from exc


def _find_duplicate_scan(item: _ScanImport) -> Scan | None:
    """Return the destination scan *item* would duplicate, if there is one.

    A scan is identified by what it is rather than by a recorded provenance
    id: its variant, its kind (type plus tool source) and the instant it ran.
    Scan timestamps carry microsecond precision, so two distinct scans of the
    same kind in one variant never collide in practice, while a re-import of
    the same export always does.  Identifying it this way keeps the importer
    self-contained — no extra column, and no dependence on rows written by an
    earlier version — and it also catches an export whose scan the destination
    already has natively, which a provenance marker would miss.
    """
    target = _utc_key(item.timestamp)
    for sibling in ScanController.get_by_variant(item.variant.id):
        if (sibling.scan_type or "sbom") != item.scan_type:
            continue
        if (sibling.scan_source or None) != item.scan_source:
            continue
        if _utc_key(sibling.timestamp) == target:
            return sibling
    return None


def _import_entry_error(index: int, total: int, detail: object) -> str:
    """Prefix an error with its position, so bulk imports name the bad entry."""
    if total <= 1:
        return str(detail)
    return f"Export #{index + 1} of {total}: {detail}"


def _format_byte_size(num_bytes: float) -> str:
    """Render a byte count using the largest unit that keeps it >= 1."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if num_bytes < 1024 or unit == "GiB":
            return f"{num_bytes:g} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:g} GiB"


def init_app(app: Flask) -> None:

    @app.route('/api/scans/import', methods=['POST'])
    def import_scan() -> ResponseReturnValue:
        """Import VulnScout scan diff or full-result exports.

        Accepts a single export object or an array of them (as produced by
        ``GET /api/scans/export``).  The whole request is validated before any
        of it is written, and persisted in one transaction, so a rejected
        import leaves the database untouched.

        OpenAPI:
        response 201 JsonObject Import summary, with one entry per newly imported scan.
        response 400 Error Malformed or unsupported export payload.
        response 404 Error Destination project or variant not found.
        response 413 Error Request body exceeds the scan import size limit.
        """
        try:
            payload = flask_request.get_json(force=True, silent=True)
            if payload is None:
                raise ValueError(
                    "Request body must be valid JSON: a scan export object "
                    "or an array of them"
                )
            exports = payload if isinstance(payload, list) else [payload]
            if not exports:
                raise ValueError("Scan import array must not be empty")
            if len(exports) > _MAX_IMPORT_EXPORTS:
                raise ValueError(
                    f"Too many exports ({len(exports)}). "
                    f"Maximum is {_MAX_IMPORT_EXPORTS} per request."
                )
            results, skipped_count = _import_scan_exports(exports)
            db.session.commit()
        except RequestEntityTooLarge:
            db.session.rollback()
            limit = _format_byte_size(app.config["MAX_SCAN_IMPORT_CONTENT_LENGTH"])
            return jsonify({
                "error": f"Scan import exceeds the {limit} size limit",
            }), 413
        except FileExistsError as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 409
        except LookupError as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 404
        except (TypeError, ValueError) as exc:
            db.session.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to import scan export")
            return jsonify({"error": "Failed to import scan data"}), 500

        # New scans change every cached scan-history list and their diff badges.
        if results:
            invalidate_scan_list_cache()

        last = results[-1] if results else None
        return jsonify({
            "imported_count": len(results),
            "skipped_count": skipped_count,
            "scans": results,
            # Summary of the request as a whole; the singular fields describe
            # the last scan imported, for single-file imports the only one.
            "scan_id": last["scan_id"] if last else None,
            "format": last["format"] if last else None,
            "is_first": last["is_first"] if last else None,
            "package_count": sum(r["package_count"] for r in results),
            "finding_count": sum(r["finding_count"] for r in results),
            "vulnerability_count": sum(r["vulnerability_count"] for r in results),
            "assessment_count": sum(r["assessment_count"] for r in results),
        }), 201

    @app.route('/api/scans')
    def list_all_scans() -> ResponseReturnValue:
        """List every scan currently stored in the database.

        OpenAPI:
        response 200 JsonObject Scan collection.
        """
        scans = ScanController.get_all()
        result = serialize_list_with_diff_cached("all", scans)
        return jsonify(result)

    @app.route('/api/projects/<project_id>/scans')
    def list_scans_by_project(project_id: str) -> ResponseReturnValue:
        """List scans belonging to a specific project.

        OpenAPI:
        response 200 JsonObject Scan collection for the selected project.
        response 404 Error Project not found.
        """
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found"}), 404
        scans = ScanController.get_by_project(project_id)
        result = serialize_list_with_diff_cached(f"project:{project_id}", scans)
        return jsonify(result)

    @app.route('/api/variants/<variant_id>/scans')
    def list_scans_by_variant(variant_id: str) -> ResponseReturnValue:
        """List scans belonging to a specific variant.

        OpenAPI:
        response 200 JsonObject Scan collection for the selected variant.
        response 404 Error Variant not found.
        """
        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found"}), 404
        scans = ScanController.get_by_variant(variant_id)
        result = serialize_list_with_diff_cached(f"variant:{variant_id}", scans)
        return jsonify(result)

    @app.route('/api/scans/<scan_id>', methods=['PATCH'])
    def update_scan(scan_id: str) -> ResponseReturnValue:
        """Update the editable description of a scan.

        OpenAPI:
        body JsonObject optional JSON object containing a description field.
        response 200 JsonObject Updated scan payload.
        response 400 Error Invalid scan identifier or payload.
        response 404 Error Scan not found.
        """
        from flask import request as req
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400
        payload = req.get_json(silent=True)
        if not payload or "description" not in payload:
            return jsonify({"error": "Missing 'description' field"}), 400
        description = payload["description"]
        if not isinstance(description, str):
            return jsonify({"error": "'description' must be a string"}), 400
        scan = ScanController.get(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404
        updated = ScanController.update(scan, description)
        return jsonify(ScanController.serialize(updated))

    @app.route('/api/scans/<scan_id>', methods=['DELETE'])
    def delete_scan(scan_id: str) -> ResponseReturnValue:
        """Delete a scan and its observations.

        Findings that are no longer referenced by any observation are
        also removed (cascade cleaned).  The response includes the
        number of orphaned findings that were deleted.

        OpenAPI:
        response 200 JsonObject Deletion summary.
        response 400 Error Invalid scan identifier.
        response 404 Error Scan not found.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400
        scan = ScanController.get(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        # Collect finding IDs referenced by this scan's observations
        # *before* the cascade delete removes them.
        finding_ids = {obs.finding_id for obs in (scan.observations or [])}

        # Delete the scan (cascades to observations + sbom_documents)
        ScanController.delete(scan)

        # Clean up orphaned findings — those that no longer have any
        # observation linking them to a remaining scan.
        orphaned_count = 0
        if finding_ids:
            from sqlalchemy import exists as sa_exists
            for fid in finding_ids:
                has_obs = db.session.query(
                    sa_exists().where(Observation.finding_id == fid)
                ).scalar()
                if not has_obs:
                    finding = db.session.get(Finding, fid)
                    if finding:
                        db.session.delete(finding)
                        orphaned_count += 1
            if orphaned_count:
                db.session.commit()

        return jsonify({
            "deleted": True,
            "scan_id": scan_id,
            "orphaned_findings_removed": orphaned_count,
        })

    @app.route('/api/outdated-data', methods=['GET', 'DELETE'])
    def outdated_data() -> ResponseReturnValue:
        """Permanently remove package evidence and assessments marked outdated.

        Package evidence is removed only from variants where its package
        name/version is no longer active; globally shared rows are pruned only
        after their final reference disappears.

        OpenAPI:
        response 200 JsonObject Cleanup summary or deletion preview.
        response 500 Error Cleanup failed.
        """
        from ..helpers.outdated_cleanup import (
            delete_outdated_data as cleanup,
            outdated_data_preview,
        )

        if flask_request.method == 'GET':
            return jsonify(outdated_data_preview())
        candidate_ids = _cleanup_candidates(
            flask_request.get_json(silent=True), "candidate_ids", _is_outdated_candidates
        )
        if candidate_ids is None:
            return jsonify({"error": "candidate_ids must be a valid cleanup preview"}), 400
        try:
            return jsonify(cleanup(cast(dict[str, object], candidate_ids)))
        except ValueError:
            return jsonify({"error": _STALE_CLEANUP_PREVIEW_ERROR}), 409
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to delete outdated data")
            return jsonify({"error": "Failed to delete outdated data"}), 500

    @app.route('/api/empty-scans', methods=['GET', 'DELETE'])
    def empty_scans() -> ResponseReturnValue:
        """Preview or delete non-initial scans with no recorded changes."""
        from ..helpers.outdated_cleanup import delete_empty_scans, empty_scans_preview

        if flask_request.method == 'GET':
            return jsonify({"scans": empty_scans_preview()})
        scan_ids = _cleanup_candidates(flask_request.get_json(silent=True), "scan_ids", _is_string_list)
        if scan_ids is None:
            return jsonify({"error": "scan_ids must be a list of strings"}), 400
        try:
            return jsonify(delete_empty_scans(cast(list[str], scan_ids)))
        except ValueError:
            return jsonify({"error": _STALE_CLEANUP_PREVIEW_ERROR}), 409
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to delete empty scans")
            return jsonify({"error": "Failed to delete empty scans"}), 500

    @app.route('/api/orphaned-vulnerabilities', methods=['GET', 'DELETE'])
    def orphaned_vulnerabilities() -> ResponseReturnValue:
        """Preview or delete CVEs absent from every project and variant."""
        from ..helpers.outdated_cleanup import (
            delete_orphaned_vulnerabilities,
            orphaned_vulnerabilities_preview,
        )

        if flask_request.method == 'GET':
            return jsonify({"vulnerabilities": orphaned_vulnerabilities_preview()})
        vulnerability_ids = _cleanup_candidates(
            flask_request.get_json(silent=True), "vulnerability_ids", _is_string_list
        )
        if vulnerability_ids is None:
            return jsonify({"error": "vulnerability_ids must be a list of strings"}), 400
        try:
            return jsonify(delete_orphaned_vulnerabilities(cast(list[str], vulnerability_ids)))
        except ValueError:
            return jsonify({"error": _STALE_CLEANUP_PREVIEW_ERROR}), 409
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to delete orphaned vulnerabilities")
            return jsonify({"error": "Failed to delete orphaned vulnerabilities"}), 500

    @app.route('/api/scans/<scan_id>/diff')
    def get_scan_diff(scan_id: str) -> ResponseReturnValue:
        """Return the computed diff between a scan and its predecessor.

        OpenAPI:
        response 200 JsonObject Scan diff payload.
        response 400 Error Invalid scan identifier.
        response 404 Error Scan not found.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        diff = _compute_diff_dict(scan)

        scan_type = scan.scan_type or "sbom"
        prev_scan_id = diff["previous_scan_id"]

        newly_detected_findings_list = diff.get("newly_detected_findings_list")
        newly_detected_vulns_list = diff.get("newly_detected_vulns_list")

        return jsonify({
            "scan_id": str(scan.id),
            "scan_type": scan_type,
            "previous_scan_id": str(prev_scan_id) if prev_scan_id else None,
            "is_first": diff["is_first"],
            "finding_count": diff["finding_count"],
            "package_count": diff["package_count"],
            "vuln_count": diff["vuln_count"],
            "findings_added": diff["findings_added"],
            "findings_removed": diff["findings_removed"],
            "findings_upgraded": diff["findings_upgraded"],
            "findings_unchanged": diff["findings_unchanged"],
            "packages_added": diff["packages_added"],
            "packages_removed": diff["packages_removed"],
            "packages_upgraded": diff["packages_upgraded"],
            "packages_unchanged": diff["packages_unchanged"],
            "vulns_added": diff["vulns_added"],
            "vulns_removed": diff["vulns_removed"],
            "vulns_unchanged": diff["vulns_unchanged"],
            "assessment_count": diff["assessment_total"],
            "assessments_added": diff["assessments_added"],
            "assessments_removed": diff["assessments_removed"],
            "assessments_unchanged": diff["assessments_unchanged"],
            "newly_detected_findings": (
                len(newly_detected_findings_list)
                if newly_detected_findings_list is not None
                else None
            ),
            "newly_detected_vulns": (
                len(newly_detected_vulns_list)
                if newly_detected_vulns_list is not None
                else None
            ),
            "newly_detected_findings_list": newly_detected_findings_list,
            "newly_detected_vulns_list": newly_detected_vulns_list,
            "newly_detected_assessments_list": diff.get("newly_detected_assessments_list"),
            "all_findings": diff.get("all_findings"),
            "all_vulns": diff.get("all_vulns"),
        })

    # ------------------------------------------------------------------
    # Merge result — all active items (SBOM ∪ tool scan) with source info
    # ------------------------------------------------------------------

    @app.route('/api/scans/<scan_id>/global-result')
    def get_scan_global_result(scan_id: str) -> ResponseReturnValue:
        """Return every active finding, vulnerability, and package at the
        time of *scan_id* together with their source (SBOM document name /
        format or scan source label).

        Uses the shared ``_global_result_full`` helper so that the counts
        are consistent with the list view's *Scan Result* badges.

        OpenAPI:
        response 200 JsonObject Aggregated scan result.
        response 400 Error Invalid scan identifier.
        response 404 Error Scan not found.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        return jsonify(_global_result_full(scan, all_variant_scans))

    # ------------------------------------------------------------------
    # Export endpoints — server-side data transformation for downloads
    # ------------------------------------------------------------------

    def _compute_diff_dict(scan: Scan) -> dict:
        """Compute the diff dict for a scan (same logic as get_scan_diff)."""
        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        scan_type = scan.scan_type or "sbom"
        scan_source = scan.scan_source
        prev_scan_id = None
        same_type_scans = [
            s for s in all_variant_scans
            if (s.scan_type or "sbom") == scan_type
            and (s.scan_source == scan_source if scan_type == "tool" else True)
        ]
        for i, s in enumerate(same_type_scans):
            if s.id == scan.id and i > 0:
                prev_scan_id = same_type_scans[i - 1].id
                break

        is_tool_scan = scan_type == "tool"
        scan_origin = _origin_for_scan(scan)
        _prev_scan = _load_scan_with_findings(prev_scan_id) if prev_scan_id else None

        current_finding_ids = {obs.finding_id for obs in scan.observations}
        curr_vulns = {obs.finding.vulnerability_id for obs in scan.observations}

        if is_tool_scan:
            sbom_before, tools_before = _contributing_scans_before(scan, all_variant_scans)
            sbom_after, tools_after = _contributing_scans_at(scan, all_variant_scans)
            _global_before_f, _global_before_v, _ = _global_result_id_sets(
                sbom_before, tools_before, filter_tool_by_sbom_pkgs=True)
            _global_after_f, _global_after_v, _ = _global_result_id_sets(
                sbom_after, tools_after, filter_tool_by_sbom_pkgs=True)
            added_fids = _global_after_f - _global_before_f
            removed_fids = _global_before_f - _global_after_f
            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
            if _prev_scan:
                _prev_origin = _origin_for_scan(_prev_scan)
                findings_removed = [
                    _obs_to_dict(obs, _prev_origin)
                    for obs in _prev_scan.observations if obs.finding_id in removed_fids
                ]
            else:
                findings_removed = []
            vulns_added = sorted(_global_after_v - _global_before_v)
            vulns_removed = sorted(_global_before_v - _global_after_v)
        elif prev_scan_id is None:
            findings_added = [_obs_to_dict(obs, scan_origin) for obs in scan.observations]
            findings_removed = []
            vulns_added = sorted(curr_vulns)
            vulns_removed = []
        else:
            prev_finding_ids = {obs.finding_id for obs in _prev_scan.observations} if _prev_scan else set()
            prev_vulns = {obs.finding.vulnerability_id for obs in _prev_scan.observations} if _prev_scan else set()
            added_fids = current_finding_ids - prev_finding_ids
            removed_fids = prev_finding_ids - current_finding_ids
            findings_added = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in added_fids
            ]
            findings_removed = [
                _obs_to_dict(obs, scan_origin)
                for obs in _prev_scan.observations if obs.finding_id in removed_fids
            ] if _prev_scan else []
            vulns_added = sorted(curr_vulns - prev_vulns)
            vulns_removed = sorted(prev_vulns - curr_vulns)

        if is_tool_scan:
            curr_pkg_ids = set()
            packages_added = []
            packages_removed = []
            packages_upgraded = []
        else:
            scans_to_query = [scan.id] if prev_scan_id is None else [scan.id, prev_scan_id]
            pkg_sets = _packages_by_scan_ids(scans_to_query)
            curr_pkg_ids = pkg_sets.get(scan.id, set())
            prev_pkg_ids = pkg_sets.get(prev_scan_id, set()) if prev_scan_id else set()
            raw_added_pkg_ids = curr_pkg_ids - prev_pkg_ids
            raw_removed_pkg_ids = prev_pkg_ids - curr_pkg_ids
            all_relevant_pkg_ids = raw_added_pkg_ids | raw_removed_pkg_ids
            pkg_lookup = _package_rows(all_relevant_pkg_ids)
            truly_added_ids, truly_removed_ids, upgraded_pairs_list = _classify_package_changes(
                raw_added_pkg_ids, raw_removed_pkg_ids, pkg_lookup)
            packages_added = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_added_ids if pid in pkg_lookup]
            packages_removed = [_pkg_to_dict(pkg_lookup[pid]) for pid in truly_removed_ids if pid in pkg_lookup]
            packages_upgraded = [
                {"package_name": old_pkg.name or "unknown", "old_version": old_pkg.version or "",
                 "new_version": new_pkg.version or "", "old_package_id": str(old_pkg.id),
                 "new_package_id": str(new_pkg.id), "package_supplier": old_pkg.supplier or ""}
                for old_pkg, new_pkg in upgraded_pairs_list
            ]

        # Classify findings for SBOM with previous
        if not is_tool_scan and prev_scan_id is not None:
            _, latest_tool = _contributing_scans_at(scan, all_variant_scans)
            curr_sr_fids, curr_sr_vids, _ = _global_result_id_sets(
                scan, latest_tool, filter_tool_by_sbom_pkgs=True)
            prev_sr_fids, prev_sr_vids, _ = _global_result_id_sets(
                _prev_scan, latest_tool, filter_tool_by_sbom_pkgs=True)
            fid_obs_map = {}
            fid_info = {}
            for obs in scan.observations:
                fid_obs_map[obs.finding_id] = _obs_to_dict(obs, scan_origin)
                fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for obs in (_prev_scan.observations if _prev_scan else []):
                if obs.finding_id not in fid_obs_map:
                    fid_obs_map[obs.finding_id] = _obs_to_dict(obs, scan_origin)
                if obs.finding_id not in fid_info:
                    fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)
            for tool_scan_obj in latest_tool.values():
                tool_loaded = _load_scan_with_findings(tool_scan_obj.id)
                if not tool_loaded:
                    continue
                tool_origin = _origin_for_scan(tool_loaded)
                for obs in tool_loaded.observations:
                    if obs.finding_id not in fid_obs_map:
                        fid_obs_map[obs.finding_id] = _obs_to_dict(obs, tool_origin)
                    if obs.finding_id not in fid_info:
                        fid_info[obs.finding_id] = (obs.finding.package_id, obs.finding.vulnerability_id)

            sr_new_fids = curr_sr_fids - prev_sr_fids
            sr_gone_fids = prev_sr_fids - curr_sr_fids
            sr_unchanged_fids = prev_sr_fids & curr_sr_fids

            upgraded_old_ids_set = {old_pkg.id for old_pkg, _ in upgraded_pairs_list}  # noqa: F841
            upgraded_new_ids_set = {new_pkg.id for _, new_pkg in upgraded_pairs_list}
            upgraded_old_to_new = {old_pkg.id: (old_pkg, new_pkg) for old_pkg, new_pkg in upgraded_pairs_list}
            _rem_by_vuln: dict[str, list[tuple[uuid_module.UUID, uuid_module.UUID]]] = {}
            for fid in sr_gone_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_old_ids_set:
                    _rem_by_vuln.setdefault(info[1], []).append((fid, info[0]))
            sr_upgraded_fids_new = set()
            sr_upgraded_fids_gone = set()
            findings_upgraded_list = []
            for fid in sr_new_fids:
                info = fid_info.get(fid)
                if info and info[0] in upgraded_new_ids_set:
                    candidates = _rem_by_vuln.get(info[1], [])
                    if candidates:
                        old_fid, old_pkg_id = candidates.pop(0)
                        sr_upgraded_fids_new.add(fid)
                        sr_upgraded_fids_gone.add(old_fid)
                        old_pkg, new_pkg = upgraded_old_to_new[old_pkg_id]
                        obs_dict: ObsDict | None = fid_obs_map.get(fid)
                        findings_upgraded_list.append({
                            "vulnerability_id": info[1], "package_name": old_pkg.name or "unknown",
                            "old_version": old_pkg.version or "", "new_version": new_pkg.version or "",
                            "package_supplier": old_pkg.supplier or "",
                            "origin": obs_dict["origin"] if obs_dict else scan_origin,
                        })
            findings_added = [fid_obs_map[fid] for fid in sr_new_fids - sr_upgraded_fids_new if fid in fid_obs_map]
            findings_removed = [fid_obs_map[fid] for fid in sr_gone_fids - sr_upgraded_fids_gone if fid in fid_obs_map]
            findings_upgraded = findings_upgraded_list
            findings_unchanged = [fid_obs_map[fid] for fid in sr_unchanged_fids if fid in fid_obs_map]
            vulns_added = sorted(curr_sr_vids - prev_sr_vids)
            vulns_removed = sorted(prev_sr_vids - curr_sr_vids)
            vulns_unchanged = sorted(prev_sr_vids & curr_sr_vids)
            unchanged_pkg_ids = curr_pkg_ids & prev_pkg_ids
            for old_pkg, new_pkg in upgraded_pairs_list:
                unchanged_pkg_ids.discard(old_pkg.id)
                unchanged_pkg_ids.discard(new_pkg.id)
            if unchanged_pkg_ids:
                unchanged_pkg_lookup = _package_rows(unchanged_pkg_ids)
                packages_unchanged = [
                    _pkg_to_dict(unchanged_pkg_lookup[pid])
                    for pid in unchanged_pkg_ids if pid in unchanged_pkg_lookup
                ]
            else:
                packages_unchanged = []
        elif not is_tool_scan:
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []
        else:
            findings_upgraded = []
            findings_unchanged = []
            vulns_unchanged = []
            packages_unchanged = []

        # Newly detected (tool scans only)
        newly_detected_findings_list = None
        newly_detected_vulns_list = None
        newly_detected_assessments_list = None
        if is_tool_scan:
            _new_vids = _global_after_v - _global_before_v
            _new_fids = _global_after_f - _global_before_f
            newly_detected_vulns_list = sorted(_new_vids)
            newly_detected_findings_list = [
                _obs_to_dict(obs, scan_origin)
                for obs in scan.observations if obs.finding_id in _new_fids
            ]
            from ..models.assessment import Assessment as _Assessment
            _before_assess_ids = _global_assessment_ids_for(sbom_before, tools_before)
            _after_assess_ids = _global_assessment_ids_for(sbom_after, tools_after)
            _new_assess_ids = _after_assess_ids - _before_assess_ids
            if _new_assess_ids:
                from ..models.finding import Finding as _Finding
                from ..models.assessment_target import AssessmentTarget as _AssessmentTarget
                _assess_rows = db.session.execute(
                    db.select(_Assessment.id, _Finding.vulnerability_id, _Assessment.status,
                              _Assessment.simplified_status, _Assessment.justification,
                              _Assessment.impact_statement, _Assessment.status_notes)
                    .join(_AssessmentTarget, _AssessmentTarget.assessment_id == _Assessment.id)
                    .join(_Finding, _Finding.id == _AssessmentTarget.finding_id)
                    .where(_Assessment.id.in_(_new_assess_ids))
                ).all()
                # A multi-target assessment produces one row per target, so
                # dedupe by assessment id to keep the list one entry per
                # assessment (matching the scalar-column query it replaces).
                _seen_new_assess: set[uuid_module.UUID] = set()
                _new_assess_entries = []
                for aid, vid, status, simp, just, impact, notes in _assess_rows:
                    if aid in _seen_new_assess:
                        continue
                    _seen_new_assess.add(aid)
                    _new_assess_entries.append(
                        {"vulnerability_id": vid, "status": status or "under_investigation",
                         "simplified_status": simp or "Pending Assessment", "justification": just or "",
                         "impact_statement": impact or "", "status_notes": notes or ""}
                    )
                newly_detected_assessments_list = sorted(
                    _new_assess_entries, key=lambda a: a["vulnerability_id"]
                )
            else:
                newly_detected_assessments_list = []

        all_findings_list = None
        all_vulns_list = None
        if is_tool_scan:
            all_findings_list = [_obs_to_dict(obs, scan_origin) for obs in scan.observations]
            all_vulns_list = sorted(curr_vulns)

        _next_scan_ts = None
        for s in all_variant_scans:
            if s.timestamp > scan.timestamp:
                if _next_scan_ts is None or s.timestamp < _next_scan_ts:
                    _next_scan_ts = s.timestamp
        assess_detail = _assessments_detail_for_scan(scan, next_scan_ts=_next_scan_ts, prev_scan=_prev_scan)

        return {
            "previous_scan_id": prev_scan_id,
            "is_first": prev_scan_id is None,
            "finding_count": len(current_finding_ids),
            "package_count": len(curr_pkg_ids),
            "vuln_count": len(curr_vulns),
            "findings_added": findings_added,
            "findings_removed": findings_removed,
            "findings_upgraded": findings_upgraded,
            "findings_unchanged": findings_unchanged,
            "packages_added": packages_added,
            "packages_removed": packages_removed,
            "packages_upgraded": packages_upgraded,
            "packages_unchanged": packages_unchanged,
            "vulns_added": vulns_added,
            "vulns_removed": vulns_removed,
            "vulns_unchanged": vulns_unchanged,
            "assessment_total": assess_detail["total"],
            "assessments_added": assess_detail["added"],
            "assessments_removed": assess_detail["removed"],
            "assessments_unchanged": assess_detail["unchanged_list"],
            "newly_detected_findings_list": newly_detected_findings_list,
            "newly_detected_vulns_list": newly_detected_vulns_list,
            "newly_detected_assessments_list": newly_detected_assessments_list,
            "all_findings": all_findings_list,
            "all_vulns": all_vulns_list,
        }

    @app.route('/api/scans/<scan_id>/export-diff')
    def export_scan_diff(scan_id: str) -> ResponseReturnValue:
        """Export a single scan's diff as a cleaned JSON download.

        OpenAPI:
        response 200 JsonObject JSON download containing the scan diff.
        response 400 Error Invalid scan identifier.
        response 404 Error Scan not found.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        variant_map = _variant_info([scan.variant_id])
        vname, pname = variant_map.get(scan.variant_id, (None, None))

        diff = _compute_diff_dict(scan)
        export_data = _build_diff_export(scan, diff, vname, pname)

        proj = _sanitize_filename(pname or "project")
        variant = _sanitize_filename(vname or str(scan.variant_id))
        ts = _format_timestamp_for_filename(scan.timestamp)
        filename = f"scan_diff_{proj}_{variant}_{ts}.json"

        response = jsonify(export_data)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @app.route('/api/scans/<scan_id>/export-result')
    def export_scan_result(scan_id: str) -> ResponseReturnValue:
        """Export a single scan's global result as a cleaned JSON download.

        OpenAPI:
        response 200 JsonObject JSON download containing the global scan result.
        response 400 Error Invalid scan identifier.
        response 404 Error Scan not found.
        """
        try:
            scan_uuid = uuid_module.UUID(scan_id)
        except ValueError:
            return jsonify({"error": "Invalid scan id"}), 400

        scan = _load_scan_with_findings(scan_uuid)
        if scan is None:
            return jsonify({"error": "Scan not found"}), 404

        variant_map = _variant_info([scan.variant_id])
        vname, pname = variant_map.get(scan.variant_id, (None, None))

        all_variant_scans = ScanController.get_by_variant(scan.variant_id)
        result = _global_result_full(scan, all_variant_scans)
        export_data = _build_global_result_export(scan, result, vname, pname)

        proj = _sanitize_filename(pname or "project")
        variant = _sanitize_filename(vname or str(scan.variant_id))
        ts = _format_timestamp_for_filename(scan.timestamp)
        filename = f"scan_total_{proj}_{variant}_{ts}.json"

        response = jsonify(export_data)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @app.route('/api/scans/export')
    def export_all_scans() -> ResponseReturnValue:
        """Export all visible scans (optionally filtered by variant/project).

        Query params:
          - variant_id: filter to a single variant
          - project_id: filter to a single project
          - type: 'diff' or 'total' (default: 'diff')
        Returns a JSON array of export objects grouped per variant, with
        Content-Disposition for download.

                OpenAPI:
                query variant_id uuid optional Restrict export to a single variant.
                query project_id uuid optional Restrict export to a single project.
                query type string optional Export type: diff or total.
                response 200 JsonObject JSON export payload.
                response 400 Error Invalid filter or export type.
                response 404 Error Project not found.
        """
        export_type = flask_request.args.get("type", "diff")
        if export_type not in ("diff", "total"):
            return jsonify({"error": "type must be 'diff' or 'total'"}), 400

        variant_id = flask_request.args.get("variant_id")
        project_id = flask_request.args.get("project_id")

        if variant_id:
            try:
                uuid_module.UUID(variant_id)
            except ValueError:
                return jsonify({"error": "Invalid variant_id"}), 400
            scans = ScanController.get_by_variant(variant_id)
        elif project_id:
            try:
                uuid_module.UUID(project_id)
            except ValueError:
                return jsonify({"error": "Invalid project_id"}), 400
            project = ProjectController.get(project_id)
            if project is None:
                return jsonify({"error": "Project not found"}), 404
            scans = ScanController.get_by_project(project_id)
        else:
            scans = ScanController.get_all()

        if not scans:
            return jsonify([])

        MAX_EXPORT_SCANS = 200
        if len(scans) > MAX_EXPORT_SCANS:
            return jsonify({
                "error": f"Too many scans ({len(scans)}). "
                         f"Maximum is {MAX_EXPORT_SCANS}. "
                         "Filter by variant_id or project_id to reduce the set."
            }), 400

        # Group scans by (project_name, variant_id) to produce one file per group
        variant_ids = list({s.variant_id for s in scans})
        variant_map = _variant_info(variant_ids)

        groups: dict = {}
        for scan in scans:
            vname, pname = variant_map.get(scan.variant_id, (None, None))
            key = f"{pname or ''}::{scan.variant_id}"
            groups.setdefault(key, []).append((scan, vname, pname))

        all_exports = []
        for group_scans in groups.values():
            group_data = []
            for scan, vname, pname in group_scans:
                loaded = _load_scan_with_findings(scan.id)
                if not loaded:
                    continue
                if export_type == "diff":
                    diff = _compute_diff_dict(loaded)
                    group_data.append(_build_diff_export(loaded, diff, vname, pname))
                else:
                    all_variant_scans = ScanController.get_by_variant(scan.variant_id)
                    result = _global_result_full(loaded, all_variant_scans)
                    group_data.append(_build_global_result_export(loaded, result, vname, pname))
            all_exports.extend(group_data)

        ts = _format_timestamp_for_filename()
        filename = f"scans_{export_type}_{ts}.json"

        response = jsonify(all_exports)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
