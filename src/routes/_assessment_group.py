# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for assessment write endpoints."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from ..extensions import db, batch_session
from ..models import Assessment as DBAssessment, Finding, Package
from ..models.assessment import STATUS_TO_SIMPLIFIED


def resolve_package(pkg_string_id: str) -> "Package | None":
    """Look up an existing Package for 'name@version::supplier'.

    Returns ``None`` when no matching package exists. Writing an assessment must
    never create a package, so callers block the write when this returns
    ``None``. Matching is on name + version + supplier (with the same supplier
    normalization used by :meth:`Package.find_or_create`).
    """
    return Package.get_by_string_id(pkg_string_id)


def find_valid_finding(package_id: UUID, vuln_id: str, variant_id: UUID) -> "Finding | None":
    """Return the finding when it was actually observed for the variant.

    Assessment writes may target active or historical package versions, but
    they must never invent a package/vulnerability/variant relationship that
    was not produced by a scan.
    """
    from ..models.observation import Observation
    from ..models.scan import Scan

    return db.session.execute(
        db.select(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Finding.package_id == package_id,
            Finding.vulnerability_id == vuln_id.upper(),
            Scan.variant_id == variant_id,
        )
        .distinct()
    ).scalar_one_or_none()


def validate_assessment_findings(
    packages: list[Package], vuln_id: str, variant_id: UUID
) -> "tuple[dict[UUID, Finding], list[str]]":
    findings: dict[UUID, Finding] = {}
    invalid: list[str] = []
    for package in packages:
        finding = find_valid_finding(package.id, vuln_id, variant_id)
        if finding is None:
            invalid.append(package.string_id)
        else:
            findings[package.id] = finding
    return findings, invalid


def create_assessment_record(
    assessment: "DBAssessment",
    finding_id: UUID,
    variant_id: UUID | None,
    timestamp: datetime | None = None,
    origin: str = "custom",
) -> "DBAssessment":
    """Create a single DBAssessment row from a validated DTO.

    Shared between ``add_assessment`` (single) and ``add_assessments_batch``.
    """
    return DBAssessment.create(
        status=assessment.status or "",
        simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status or "", "Pending Assessment"),
        finding_id=finding_id,
        variant_id=variant_id,
        origin=origin,
        status_notes=assessment.status_notes,
        justification=assessment.justification,
        impact_statement=assessment.impact_statement,
        workaround=getattr(assessment, "workaround", None),
        responses=list(assessment.responses) if assessment.responses else [],
        commit=True,
        timestamp=timestamp,
    )


def payload_to_assessment(data: dict) -> "tuple[DBAssessment | dict[str, str], int]":
    """
    Take an object in input and try to convert it to an Assessment DTO.
    Return either (Assessment, 200) or (error_dict, http_code).
    """
    if "packages" not in data or not isinstance(data["packages"], list) or len(data["packages"]) < 1:
        return {"error": "Invalid request data"}, 400

    assessment = DBAssessment.new_dto(data["vuln_id"], data["packages"])

    if "status" not in data or not isinstance(data["status"], str):
        return {"error": "Invalid request data"}, 400

    if assessment.set_status(data["status"]) is False:
        return {"error": "Invalid status"}, 400

    if "status_notes" in data and isinstance(data["status_notes"], str):
        assessment.set_status_notes(data["status_notes"], False)

    if "justification" in data and isinstance(data["justification"], str):
        if not assessment.set_justification(data["justification"]):
            return {"error": "Invalid justification"}, 400
    elif assessment.is_justification_required():
        return {"error": "Justification required"}, 400

    if "impact_statement" in data and isinstance(data["impact_statement"], str):
        assessment.set_not_affected_reason(data["impact_statement"], False)

    if "workaround" in data and isinstance(data["workaround"], str):
        assessment.set_workaround(data["workaround"])

    if "timestamp" in data and isinstance(data["timestamp"], str):
        try:
            assessment.timestamp = datetime.fromisoformat(data["timestamp"])
        except (ValueError, TypeError):
            pass
    if "responses" in data and isinstance(data["responses"], list):
        for response in data["responses"]:
            assessment.add_response(response)
    return assessment, 200


@dataclass(frozen=True)
class ReconcileRequest:
    """A validated request to bring one assessment group to a desired state."""

    vuln_id: str
    existing_ids: list[UUID]
    packages: list[str]
    variant_ids: list[UUID]
    dto: "DBAssessment"
    update_timestamp: bool
    timestamp: "datetime | None"
    # Whether the payload carried a ``responses`` key. Without this flag an
    # edit that simply omits ``responses`` would wipe the VEX responses stored
    # on the existing rows.
    has_responses: bool = False


def parse_reconcile_payload(
    data: dict[str, Any],
) -> "tuple[ReconcileRequest | None, dict[str, str] | None]":
    """Validate a group-reconcile payload.

    Returns ``(request, None)`` when the payload is well formed, otherwise
    ``(None, error_dict)``. Performs no database access.
    """
    vuln_id = data.get("vuln_id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None, {"error": "vuln_id is required"}

    packages = data.get("packages")
    if (not isinstance(packages, list) or not packages
            or not all(isinstance(p, str) and p for p in packages)):
        return None, {"error": "packages must be a non-empty list of package ids"}

    raw_variants = data.get("variant_ids")
    if not isinstance(raw_variants, list) or not raw_variants:
        return None, {"error": "variant_ids must be a non-empty list"}
    variant_ids: list[UUID] = []
    for raw in raw_variants:
        try:
            variant_ids.append(UUID(str(raw)))
        except (ValueError, AttributeError, TypeError):
            return None, {"error": f"Invalid variant_id: {raw}"}

    raw_existing = data.get("existing_ids", [])
    if not isinstance(raw_existing, list):
        return None, {"error": "existing_ids must be a list"}
    existing_ids: list[UUID] = []
    for raw in raw_existing:
        try:
            existing_ids.append(UUID(str(raw)))
        except (ValueError, AttributeError, TypeError):
            return None, {"error": f"Invalid assessment id: {raw}"}

    dto, code = payload_to_assessment({**data, "vuln_id": vuln_id, "packages": packages})
    if code != 200 or not isinstance(dto, DBAssessment):
        message = dto.get("error", "Invalid assessment content") if isinstance(dto, dict) else "Invalid content"
        return None, {"error": message}

    update_timestamp = data.get("update_timestamp", True)
    if not isinstance(update_timestamp, bool):
        return None, {"error": "update_timestamp must be a boolean"}

    timestamp: "datetime | None" = None
    raw_ts = data.get("timestamp")
    if isinstance(raw_ts, str) and raw_ts:
        try:
            timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            return None, {"error": "Invalid timestamp"}

    return ReconcileRequest(
        vuln_id=vuln_id,
        existing_ids=existing_ids,
        packages=packages,
        variant_ids=variant_ids,
        dto=dto,
        update_timestamp=update_timestamp,
        timestamp=timestamp,
        has_responses=isinstance(data.get("responses"), list),
    ), None


def load_group_rows(
    existing_ids: list[UUID], vuln_id: str
) -> "tuple[list[DBAssessment], dict[str, str] | None]":
    """Load the group's current rows, rejecting ids that belong to another CVE.

    Without this guard a client could pass arbitrary assessment ids and have
    them deleted by the reconcile below.
    """
    rows: list[DBAssessment] = []
    for assessment_id in existing_ids:
        row = DBAssessment.get_by_id(assessment_id)
        if row is None:
            return [], {"error": f"Assessment not found: {assessment_id}"}
        finding = row.finding
        if finding is None or (finding.vulnerability_id or "").upper() != vuln_id.upper():
            return [], {"error": f"Assessment {assessment_id} does not belong to {vuln_id}"}
        if row.variant_id is None or finding.package is None:
            # Such a legacy row cannot be keyed by (package, variant), so it
            # could neither be updated nor deleted: refuse rather than leaving
            # it silently desynced from the rest of the group.
            return [], {
                "error": f"Assessment {assessment_id} is not bound to a variant and package"
                         " and cannot be reconciled"
            }
        rows.append(row)
    return rows, None


def validate_deletions(
    rows: "list[DBAssessment]", targets: "dict[tuple[str, UUID], Finding]"
) -> "dict[str, str] | None":
    """Refuse the whole request when it would delete a pending AI row.

    Mirrors ``delete_assessment``: AI rows are approved or rejected through
    their own endpoints, never removed as a side effect of a group edit.
    """
    for key, row in index_group_rows(rows).items():
        if key not in targets and row.origin == "ai":
            return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}
    return None


def index_group_rows(rows: "list[DBAssessment]") -> "dict[tuple[str, UUID], DBAssessment]":
    """Index the group's rows by their (package, variant) key."""
    indexed: dict[tuple[str, UUID], DBAssessment] = {}
    for row in rows:
        finding = row.finding
        if finding is None or finding.package is None or row.variant_id is None:
            continue
        indexed[(finding.package.string_id, row.variant_id)] = row
    return indexed


def resolve_targets(
    req: ReconcileRequest,
) -> "tuple[dict[tuple[str, UUID], Finding], dict[str, str] | None]":
    """Resolve every (package, variant) combo to a Finding.

    Every combo is checked before any write happens, so one bad combo cancels
    the whole action — the same rule ``add_assessments_batch`` applies.
    """
    packages: list[Package] = []
    missing: list[str] = []
    for pkg_string_id in req.packages:
        package = resolve_package(pkg_string_id)
        if package is None:
            missing.append(pkg_string_id)
        else:
            packages.append(package)
    if missing:
        return {}, {
            "error": "Package not found: " + ", ".join(missing)
            + ". Assessments can only be written for existing packages."
        }

    resolved: dict[tuple[str, UUID], Finding] = {}
    invalid: list[str] = []
    for variant_id in req.variant_ids:
        findings, bad = validate_assessment_findings(packages, req.vuln_id, variant_id)
        invalid.extend(f"{sid} (variant {variant_id})" for sid in bad)
        for package in packages:
            finding = findings.get(package.id)
            if finding is not None:
                resolved[(package.string_id, variant_id)] = finding
    if invalid:
        return {}, {
            "error": "Invalid package version for vulnerability and variant: " + ", ".join(invalid)
        }
    return resolved, None


def apply_reconcile(
    req: ReconcileRequest,
    rows: "list[DBAssessment]",
    targets: "dict[tuple[str, UUID], Finding]",
) -> "dict[str, Any]":
    """Bring the group to the desired state inside a single transaction.

    ``batch_session`` defers every per-row commit to one commit at the end and
    rolls back on any exception, so a failure part-way leaves the group
    untouched.
    """
    shared_ts = req.timestamp or datetime.now(timezone.utc)

    existing_by_key = index_group_rows(rows)

    updated: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []
    deleted: list[str] = []
    became_custom = False
    deleted_non_custom = False

    with batch_session():
        for key, row in existing_by_key.items():
            if key in targets:
                # Editing a pending AI row must not silently approve it.
                new_origin = "ai" if row.origin == "ai" else "custom"
                if (row.origin or "") != "custom" and new_origin == "custom":
                    became_custom = True
                row.update(
                    status=req.dto.status,
                    origin=new_origin,
                    simplified_status=STATUS_TO_SIMPLIFIED.get(
                        req.dto.status or "", "Pending Assessment"
                    ),
                    status_notes=req.dto.status_notes or "",
                    justification=req.dto.justification or "",
                    impact_statement=req.dto.impact_statement or "",
                    workaround=getattr(req.dto, "workaround", None) or "",
                    # ``None`` means "leave as is": an edit that did not send
                    # responses must not wipe imported VEX response data.
                    responses=list(req.dto.responses or []) if req.has_responses else None,
                    timestamp=shared_ts if req.update_timestamp else None,
                    update_timestamp=req.update_timestamp,
                )
                updated.append(row.to_dict())
            else:
                if (row.origin or "") != "custom":
                    deleted_non_custom = True
                deleted.append(str(row.id))
                row.delete()

        for key, finding in targets.items():
            if key in existing_by_key:
                continue
            new_row = create_assessment_record(
                req.dto,
                finding.id,
                key[1],
                # A new row always needs a first-observation timestamp; callers
                # keeping the group's timestamp pass it as ``req.timestamp`` so
                # the new sibling joins the same group instead of splitting it.
                timestamp=shared_ts,
            )
            created.append(new_row.to_dict())

    return {
        "updated": updated,
        "created": created,
        "deleted": deleted,
        "became_custom": became_custom,
        "deleted_non_custom": deleted_non_custom,
    }
