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
    responses: "list[str] | None" = None,
) -> "DBAssessment":
    """Create a single DBAssessment row from a validated DTO.

    Shared between ``add_assessment`` (single) and ``add_assessments_batch``.
    ``responses`` overrides the DTO's own responses; group reconcile uses it so
    a new member inherits the responses the rest of the group already carries.
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
        responses=(
            list(responses) if responses is not None
            else (list(assessment.responses) if assessment.responses else [])
        ),
        commit=True,
        timestamp=timestamp,
    )


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
    from .assessments import payload_to_assessment

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


def validate_deletions(
    rows: "list[DBAssessment]", targets: "dict[tuple[str, UUID], Finding]"
) -> "dict[str, str] | None":
    """Refuse the edit when it would drop a target from a pending AI assessment.

    Mirrors ``delete_assessment``: AI assessments are approved or rejected
    through their own endpoints, never edited piecemeal by removing one of
    their targets.
    """
    if not rows or rows[0].origin != "ai":
        return None
    if set(index_group_rows(rows)) - set(targets):
        return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}
    return None


def index_group_rows(rows: "list[DBAssessment]") -> "dict[tuple[str, UUID], Any]":
    """Index the group's current targets by their (package, variant) key.

    A group is now one assessment — ``rows`` holds zero or one of them — and
    its targets live on ``target_rows`` rather than one row per package.
    """
    if not rows:
        return {}
    indexed: dict[tuple[str, UUID], Any] = {}
    for target in rows[0].target_rows:
        finding = target.finding
        if finding is None or finding.package is None:
            continue
        indexed[(finding.package.string_id, target.variant_id)] = target
    return indexed


def resolve_targets(
    req: ReconcileRequest,
    existing_by_key: "dict[tuple[str, UUID], Any] | None" = None,
) -> "tuple[dict[tuple[str, UUID], Finding], dict[str, str] | None]":
    """Resolve the (package, variant) combos this edit should end up covering.

    A selected package is not necessarily observed in every selected variant:
    the selection is a cross-product, but the scan data is sparse. Such an empty
    cell is not an error, it simply produces no row — rejecting the whole
    request for it would make an otherwise valid group uneditable, which is what
    the per-row loop this endpoint replaced never did.

    What is still refused before any write happens: an unknown package, and a
    package that is observed for this vulnerability in *none* of the selected
    variants, which means the selection itself is wrong.
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
    covered: set[str] = set()
    for variant_id in req.variant_ids:
        findings, _absent = validate_assessment_findings(packages, req.vuln_id, variant_id)
        for package in packages:
            finding = findings.get(package.id)
            if finding is not None:
                resolved[(package.string_id, variant_id)] = finding
                covered.add(package.string_id)

    # A target that already exists for a still-selected combo stays a target
    # even if the finding lookup above missed it, otherwise the reconcile
    # would read it as deselected and drop a target the user only meant to edit.
    selected_packages = {package.string_id for package in packages}
    selected_variants = set(req.variant_ids)
    for key, target_row in (existing_by_key or {}).items():
        if key in resolved or key[0] not in selected_packages or key[1] not in selected_variants:
            continue
        if target_row.finding is not None:
            resolved[key] = target_row.finding
            covered.add(key[0])

    unobserved = sorted(selected_packages - covered)
    if unobserved:
        return {}, {
            "error": "Invalid package version for vulnerability and variant: " + ", ".join(unobserved)
        }
    return resolved, None


def apply_reconcile(
    req: ReconcileRequest,
    rows: "list[DBAssessment]",
    targets: "dict[tuple[str, UUID], Finding]",
) -> "dict[str, Any]":
    """Bring the group — one assessment — to the desired target set and content.

    A group is now a single assessment, so there is nothing to loop over: its
    target set is diffed against the request and applied as added or removed
    ``AssessmentTarget`` rows, and its content fields are updated once.
    Removing the last target leaves the assessment unreachable, so it is
    deleted along with it rather than kept around empty.
    """
    if not rows:
        return {
            "updated": [], "created": [], "deleted": [],
            "became_custom": False, "deleted_non_custom": False,
        }

    assessment = rows[0]
    shared_ts = req.timestamp or datetime.now(timezone.utc)
    existing_by_key = index_group_rows(rows)
    deleted_non_custom = False

    with batch_session():
        for key, target_row in existing_by_key.items():
            if key in targets:
                continue
            if (assessment.origin or "") != "custom":
                deleted_non_custom = True
            assessment.target_rows.remove(target_row)

        for key, finding in targets.items():
            if key in existing_by_key:
                continue
            assessment.add_target(key[1], finding.id)

        if not assessment.target_rows:
            deleted_id = str(assessment.id)
            assessment.delete()
            return {
                "updated": [], "created": [], "deleted": [deleted_id],
                "became_custom": False, "deleted_non_custom": deleted_non_custom,
            }

        # Editing a pending AI assessment must not silently approve it.
        new_origin = "ai" if assessment.origin == "ai" else "custom"
        became_custom = (assessment.origin or "") != "custom" and new_origin == "custom"
        assessment.update(
            status=req.dto.status,
            origin=new_origin,
            simplified_status=STATUS_TO_SIMPLIFIED.get(
                req.dto.status or "", "Pending Assessment"
            ),
            status_notes=req.dto.status_notes or "",
            justification=req.dto.justification or "",
            impact_statement=req.dto.impact_statement or "",
            workaround=getattr(req.dto, "workaround", None) or "",
            # ``None`` means "leave as is": an edit that did not send responses
            # must not wipe imported VEX response data.
            responses=list(req.dto.responses or []) if req.has_responses else None,
            timestamp=shared_ts if req.update_timestamp else None,
            update_timestamp=req.update_timestamp,
        )

    return {
        "updated": [assessment.to_dict()],
        "created": [],
        "deleted": [],
        "became_custom": became_custom,
        "deleted_non_custom": deleted_non_custom,
    }

