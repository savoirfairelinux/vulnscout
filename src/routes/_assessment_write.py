# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for assessment write endpoints."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from ..extensions import batch_session
from ..models import Assessment as DBAssessment, Finding, Package, Variant
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
    return Finding.get_observed_by_variant(package_id, vuln_id, variant_id)


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
    targets: "list[tuple[UUID, UUID]]",
    timestamp: datetime | None = None,
    origin: str = "custom",
    responses: "list[str] | None" = None,
) -> "DBAssessment":
    """Create a single DBAssessment row from a validated DTO and target set.

    ``targets`` is every ``(variant_id, finding_id)`` pair this write action
    resolved. Shared between ``add_assessment`` and ``add_assessments_batch``
    — every package x variant combo resolved for one user action becomes
    targets on ONE row, never one row per combo. ``responses`` overrides the
    DTO's own responses; reconcile uses it so an edit that adds a target
    inherits the responses the rest of the assessment already carries.
    """
    return DBAssessment.create(
        status=assessment.status or "",
        simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status or "", "Pending Assessment"),
        targets=targets,
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
    """A validated request to bring one assessment to a desired state."""

    vuln_id: str
    packages: list[str]
    variant_ids: list[UUID]
    target_pairs: "list[tuple[str, UUID]] | None"
    dto: "DBAssessment"
    update_timestamp: bool
    timestamp: "datetime | None"
    # Whether the payload carried a ``responses`` key. Without this flag an
    # edit that simply omits ``responses`` would wipe the VEX responses stored
    # on the existing row.
    has_responses: bool = False


def parse_reconcile_payload(
    data: dict[str, Any],
) -> "tuple[ReconcileRequest | None, dict[str, str] | None]":
    """Validate a reconcile payload.

    Returns ``(request, None)`` when the payload is well formed, otherwise
    ``(None, error_dict)``. Performs no database access.
    """
    from .assessments import payload_to_assessment

    vuln_id = data.get("vuln_id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None, {"error": "vuln_id is required"}

    target_pairs: "list[tuple[str, UUID]] | None" = None
    raw_targets = data.get("targets")
    if raw_targets is not None:
        if not isinstance(raw_targets, list):
            return None, {"error": "targets must be a list"}
        target_pairs = []
        for target in raw_targets:
            if not isinstance(target, dict):
                return None, {"error": "Invalid target"}
            package = target.get("package")
            if not isinstance(package, str) or not package:
                return None, {"error": "Target package is required"}
            try:
                target_variant_id = UUID(str(target.get("variant_id")))
            except (ValueError, AttributeError, TypeError):
                return None, {"error": f"Invalid variant_id: {target.get('variant_id')}"}
            pair = (package, target_variant_id)
            if pair not in target_pairs:
                target_pairs.append(pair)

    packages = data.get("packages")
    raw_variants = data.get("variant_ids")
    if target_pairs is not None:
        packages = list(dict.fromkeys(package for package, _variant in target_pairs))
        variant_ids = list(dict.fromkeys(variant for _package, variant in target_pairs))
    else:
        if (not isinstance(packages, list) or not packages
                or not all(isinstance(p, str) and p for p in packages)):
            return None, {"error": "packages must be a non-empty list of package ids"}
        if not isinstance(raw_variants, list) or not raw_variants:
            return None, {"error": "variant_ids must be a non-empty list"}
        variant_ids = []
        for raw in raw_variants:
            try:
                variant_ids.append(UUID(str(raw)))
            except (ValueError, AttributeError, TypeError):
                return None, {"error": f"Invalid variant_id: {raw}"}

    dto, code = payload_to_assessment(
        {**data, "vuln_id": vuln_id, "packages": packages},
        allow_empty_packages=target_pairs is not None,
    )
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
        packages=packages,
        variant_ids=variant_ids,
        target_pairs=target_pairs,
        dto=dto,
        update_timestamp=update_timestamp,
        timestamp=timestamp,
        has_responses=isinstance(data.get("responses"), list),
    ), None


def validate_deletions(
    assessment: "DBAssessment | None", targets: "dict[tuple[str, UUID], Finding]"
) -> "dict[str, str] | None":
    """Refuse the edit when it would drop a target from a pending AI assessment.

    Mirrors ``delete_assessment``: AI assessments are approved or rejected
    through their own endpoints, never edited piecemeal by removing one of
    their targets.
    """
    if assessment is None or assessment.origin != "ai":
        return None
    if set(index_targets(assessment)) - set(targets):
        return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}
    return None


def index_targets(assessment: "DBAssessment | None") -> "dict[tuple[str, UUID], Any]":
    """Index the assessment's current targets by their (package, variant) key."""
    if assessment is None:
        return {}
    indexed: dict[tuple[str, UUID], Any] = {}
    for target in assessment.target_rows:
        finding = target.finding
        if finding is None or finding.package is None:
            continue
        indexed[(finding.package.string_id, target.variant_id)] = target
    return indexed


def resolve_target_set(
    packages: list[Package], vuln_id: str, variant_ids: list[UUID],
    expected_project_id: UUID | None = None,
) -> "tuple[dict[tuple[str, UUID], Finding], list[str]]":
    """Cross *packages* with *variant_ids*, keeping only observed combos.

    Returns ``(resolved, unobserved)``: ``resolved`` maps
    ``(package.string_id, variant_id) -> Finding`` for every combo a scan
    actually recorded; ``unobserved`` lists the packages that had zero valid
    combo across *every* selected variant — the caller's cue to reject the
    whole request, since the selection itself is wrong in that case.

    A selected package not being observed in every selected variant is not
    itself an error: the selection is a cross-product, but scan data is
    sparse, so a missing cell simply produces no target.
    """
    variants = []
    missing_variants = []
    for variant_id in variant_ids:
        variant = Variant.get_by_id(variant_id)
        if variant is None:
            missing_variants.append(str(variant_id))
        else:
            variants.append(variant)
    if missing_variants:
        raise ValueError("Variant not found: " + ", ".join(missing_variants))

    project_ids = {variant.project_id for variant in variants}
    if expected_project_id is not None:
        project_ids.add(expected_project_id)
    if len(project_ids) > 1:
        raise ValueError("Assessment targets belong to different projects")

    resolved: dict[tuple[str, UUID], Finding] = {}
    covered: set[str] = set()
    for variant_id in variant_ids:
        findings, _absent = validate_assessment_findings(packages, vuln_id, variant_id)
        for package in packages:
            finding = findings.get(package.id)
            if finding is not None:
                resolved[(package.string_id, variant_id)] = finding
                covered.add(package.string_id)

    selected_packages = {package.string_id for package in packages}
    unobserved = sorted(selected_packages - covered)
    return resolved, unobserved


def resolve_targets(
    req: ReconcileRequest,
    existing_by_key: "dict[tuple[str, UUID], Any] | None" = None,
) -> "tuple[dict[tuple[str, UUID], Finding], dict[str, str] | None]":
    """Resolve the (package, variant) combos this edit should end up covering.

    A selected package is not necessarily observed in every selected variant:
    the selection is a cross-product, but the scan data is sparse. Such an empty
    cell is not an error, it simply produces no row — rejecting the whole
    request for it would make an otherwise valid assessment uneditable, which
    is what the per-row loop this endpoint replaced never did.

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

    if req.target_pairs is not None:
        package_by_id = {package.string_id: package for package in packages}
        variants: dict[UUID, Variant] = {}
        missing_variants: list[str] = []
        for variant_id in req.variant_ids:
            variant = Variant.get_by_id(variant_id)
            if variant is None:
                missing_variants.append(str(variant_id))
            else:
                variants[variant_id] = variant
        if missing_variants:
            return {}, {"error": "Variant not found: " + ", ".join(missing_variants)}

        project_ids = {variant.project_id for variant in variants.values()}
        if existing_by_key:
            existing_variant = Variant.get_by_id(next(iter(existing_by_key))[1])
            if existing_variant is not None:
                project_ids.add(existing_variant.project_id)
        if len(project_ids) > 1:
            return {}, {"error": "Assessment targets belong to different projects"}

        resolved_pairs: dict[tuple[str, UUID], Finding] = {}
        invalid_pairs: list[str] = []
        for package_id, variant_id in req.target_pairs:
            key = (package_id, variant_id)
            existing = (existing_by_key or {}).get(key)
            if existing is not None and existing.finding is not None:
                resolved_pairs[key] = existing.finding
                continue
            package = package_by_id[package_id]
            finding = find_valid_finding(package.id, req.vuln_id, variant_id)
            if finding is None:
                invalid_pairs.append(f"{package_id} in {variant_id}")
            else:
                resolved_pairs[key] = finding
        if invalid_pairs:
            return {}, {
                "error": "Invalid package version for vulnerability and variant: "
                + ", ".join(invalid_pairs)
            }
        return resolved_pairs, None

    expected_project_id: UUID | None = None
    if existing_by_key:
        existing_variant = Variant.get_by_id(next(iter(existing_by_key))[1])
        if existing_variant is not None:
            expected_project_id = existing_variant.project_id
    try:
        resolved, unobserved_initial = resolve_target_set(
            packages, req.vuln_id, req.variant_ids,
            expected_project_id=expected_project_id,
        )
    except ValueError as exc:
        return {}, {"error": str(exc)}
    selected_packages = {package.string_id for package in packages}
    covered = selected_packages - set(unobserved_initial)

    # A target that already exists for a still-selected combo stays a target
    # even if the finding lookup above missed it, otherwise the reconcile
    # would read it as deselected and drop a target the user only meant to edit.
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
    assessment: "DBAssessment | None",
    targets: "dict[tuple[str, UUID], Finding]",
) -> "dict[str, Any]":
    """Bring *assessment* to the desired target set and content.

    Its target set is diffed against the request and applied as added or
    removed ``AssessmentTarget`` rows, and its content fields are updated
    once. Removing the last target leaves the assessment unreachable, so it
    is deleted along with it rather than kept around empty.
    """
    if assessment is None:
        return {
            "updated": [], "created": [], "deleted": [],
            "became_custom": False, "deleted_non_custom": False,
        }

    shared_ts = req.timestamp or datetime.now(timezone.utc)
    existing_by_key = index_targets(assessment)
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
