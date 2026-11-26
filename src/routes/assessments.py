# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import gzip
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal, cast, overload
from uuid import UUID

from ..models import Assessment as DBAssessment, Package, Finding
from ..models.assessment import APPROVAL_CONTENT_FIELDS, APPROVAL_EDIT_FIELDS
from ..models.assessment_target import AssessmentTarget, GroupInvariantError
from ..models.assessment_review import AssessmentReview, fingerprint_assessment
from ..extensions import db, batch_session, hold_write_lock, write_lock
from ..models.variant import Variant as DBVariant
from ..models.variant_context import VariantContext
from ..helpers.assessment_risk_links import (
    MAX_SNAPSHOT_BYTES, RiskLinkError, RiskModelIndex, RiskSnapshot, charge_snapshots, describe_links,
    preview_link, resolve_links,
)
from ._scan_helpers import parse_uuid_or_400
from ._scan_queries import VulnerabilityText, fetch_vulnerabilities_texts
from ._scan_diff import invalidate_scan_list_cache
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.assessment_io import (
    build_openvex_doc,
    is_openvex_doc,
    import_statements as _import_openvex_statements,
    build_variant_by_name_map,
    build_custom_data_export,
    custom_data_version,
    detect_review_export_format,
    import_custom_data,
    reconcile_review_export,
)
from ..helpers.assessment_staleness import annotate_assessments_outdated
from ..controllers.assessment_targets import annotate_targets
from ._assessment_write import (
    apply_reconcile,
    create_assessment_record,
    find_valid_finding,
    index_targets,
    parse_reconcile_payload,
    resolve_package,
    resolve_target_set,
    resolve_targets,
    validate_deletions,
)

from flask import request, Flask
from flask.typing import ResponseReturnValue
from sqlalchemy import false, func, select
from sqlalchemy.engine import CursorResult
from werkzeug.exceptions import RequestEntityTooLarge

_SCANNER_AUTHORS = {
    "nvd",
    "unknown",
    "nvd@nist.gov",
    "security-advisories@github.com",
    "cve@mitre.org",
    "secalert@redhat.com",
    "cna@cloudflare.com",
}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

AssessmentDict = dict[str, Any]
CompactAssessment = list[str | None]


def _is_scanner_author(author: str | None) -> bool:
    if not author:
        return True
    a = author.strip().lower()
    if a in _SCANNER_AUTHORS:
        return True
    if _UUID_RE.match(a):
        return True
    return False


def _lock_target_writes() -> None:
    hold_write_lock()
    if db.session.get_bind().dialect.name == "sqlite":
        # SQLite ignores FOR UPDATE. Reserve its database writer before
        # reading membership, including against writers in other processes.
        db.session.execute(db.update(DBAssessment).where(false()).values(origin=DBAssessment.origin))


def _replace_pending_ai(
    vuln_id: str, targets: list[tuple[UUID, UUID]]
) -> list[dict[str, Any]]:
    """Make room for a new AI assessment on *targets* by removing the old one.

    *targets* are the new assessment's ``(variant_id, finding_id)`` pairs. A
    new AI assessment replaces a pending AI assessment (``origin == "ai"``)
    only on the targets they share: the same variant **and** package. Its
    other targets are kept (``trimmed``), so assessing other packages of the
    same variant never discards an earlier suggestion; the old assessment is
    deleted only once no target remains (``deleted``). Approved (``custom``)
    and SBOM assessments are never touched.

    Does not commit; call it inside ``batch_session`` together with the create
    so a failed write leaves the old assessment intact.
    """
    replacing = set(targets)
    replaced: list[dict[str, Any]] = []
    _lock_target_writes()
    pending = db.select(DBAssessment).join(AssessmentTarget).join(Finding).where(
        Finding.vulnerability_id == vuln_id.upper(), DBAssessment.origin == "ai",
    ).order_by(DBAssessment.id).with_for_update(of=DBAssessment).execution_options(populate_existing=True)
    for row in db.session.scalars(pending).unique().all():
        overlap = [t for t in row.target_rows if (t.variant_id, t.finding_id) in replacing]
        if not overlap:
            continue
        removed = sorted({str(t.variant_id) for t in overlap})
        if len(overlap) == len(row.target_rows):
            replaced.append({"id": str(row.id), "action": "deleted", "variant_ids": removed})
            row.delete()
        else:
            for target in overlap:
                row.target_rows.remove(target)
            replaced.append({"id": str(row.id), "action": "trimmed", "variant_ids": removed})
    return replaced


def _assessments_for_vulnerability(
    vuln_id: str,
    project_variant_ids: set[UUID] | None = None,
) -> list[DBAssessment]:
    """Return one row per assessment, optionally limited to project targets."""
    rows = DBAssessment.get_by_vulnerability(vuln_id)
    if project_variant_ids is None:
        return rows
    return [
        assessment for assessment in rows
        if any(target.variant_id in project_variant_ids
               for target in assessment.target_rows)
    ]


def _resolve_pending_ai_row(
    assessment_id: str,
) -> "tuple[DBAssessment | None, ResponseReturnValue | None]":
    """Read the suggestion to validate before the conditional approval write."""
    existing = DBAssessment.get_by_id(assessment_id)
    if existing is None:
        return None, ({"error": "Assessment not found"}, 404)
    if existing.origin != "ai":
        return None, ({"error": "Not a pending AI assessment"}, 400)
    return existing, None


_APPROVAL_REQUEST_MAX_BYTES = 64 * 1024


def _reviewed_links(
    row: DBAssessment, edits: object, *, approval: bool = False,
) -> dict[AssessmentTarget, list[RiskSnapshot]]:
    """Validate all proposed replacements and retained references before applying any."""
    if not isinstance(edits, list):
        raise RiskLinkError("target_risk_links must be a list")
    members = {(str(t.variant_id), t.finding.package.string_id): t for t in row.target_rows}
    requested: dict[AssessmentTarget, object] = {}
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) != {"variant_id", "package", "risk_links"}:
            raise RiskLinkError("Each risk link edit requires variant_id, package and risk_links")
        if not isinstance(edit["variant_id"], str) or not isinstance(edit["package"], str):
            raise RiskLinkError("Invalid risk link target")
        target = members.get((edit["variant_id"], edit["package"]))
        if target is None or target in requested:
            raise RiskLinkError("Unknown or repeated risk link target")
        requested[target] = edit["risk_links"]
    variants = {t.variant_id for t in members.values() if t in requested or t.risk_links}
    models = dict(db.session.execute(
        select(VariantContext.variant_id, VariantContext.stride_model)
        .where(VariantContext.variant_id.in_(variants)).order_by(VariantContext.variant_id).with_for_update()
    ).tuples().all())
    replacements = {}
    remaining = MAX_SNAPSHOT_BYTES
    indexes = {vid: RiskModelIndex(models.get(vid)) for vid in variants}
    for target in members.values():
        if target.variant_id not in indexes:
            continue
        index = indexes[target.variant_id]
        retained = target.risk_links or []
        confirmed: set[tuple[str, str | None]] = set()
        if target in requested:
            try:
                replacements[target] = resolve_links(requested[target], index,
                                                     confirmed=confirmed if approval else None)
            except RiskLinkError as exc:
                raise RiskLinkError(f"{target.finding.package.string_id} ({target.variant_id}): {exc}") from exc
            kept = {(r["risk_id"], r.get("threat_id")) for r in replacements[target]}
            retained = [r for r in retained if (r["risk_id"], r.get("threat_id")) in kept - confirmed]
        remaining = charge_snapshots(remaining, replacements.get(target, retained))
        if retained and any(link["stale"] for link in describe_links(retained, index)):
            raise RiskLinkError(f"Stale modeled risk link for {target.finding.package.string_id} "
                                f"({target.variant_id}): correct or remove it before approval")
    return replacements


def _validate_content_edit(
    existing: "DBAssessment", payload: dict[str, Any], *, preserve_omitted: bool = False,
) -> "tuple[DBAssessment | None, str | None]":
    """Apply a partial content edit to a copy of *existing* and validate it.

    Returns the validated in-memory assessment, or an error message. The
    stored row is never modified, so a rejected edit leaves it untouched.
    """
    mem_assess = DBAssessment.from_dict(existing.to_dict())

    if "status" in payload and isinstance(payload["status"], str):
        if not mem_assess.set_status(payload["status"]):
            return None, "Invalid status"
        if mem_assess.status not in ["not_affected", "false_positive"]:
            mem_assess.justification = ""
            mem_assess.impact_statement = ""

    if "status_notes" in payload and isinstance(payload["status_notes"], str):
        mem_assess.set_status_notes(payload["status_notes"], False)

    if "justification" in payload and isinstance(payload["justification"], str):
        if payload["justification"] == "":
            mem_assess.justification = ""
        elif not mem_assess.set_justification(payload["justification"]):
            return None, "Invalid justification"
    elif not preserve_omitted and mem_assess.is_justification_required():
        return None, "Justification required"

    if "impact_statement" in payload and isinstance(payload["impact_statement"], str):
        if payload["impact_statement"] == "":
            mem_assess.impact_statement = ""
        else:
            mem_assess.set_not_affected_reason(payload["impact_statement"], False)

    if "workaround" in payload and isinstance(payload["workaround"], str):
        mem_assess.set_workaround(payload["workaround"])

    if (preserve_omitted and mem_assess.is_justification_required()
            and not mem_assess.get_justification_openvex() and not (mem_assess.impact_statement or "").strip()):
        return None, "Justification required"

    return mem_assess, None


def _approve_row(
    row: "DBAssessment", payload: dict[str, Any],
) -> ResponseReturnValue:
    """Turn a pending AI row into a custom assessment.

    Apply edits only if the validated snapshot still matches.
    """
    values: dict[str, Any] = {
        "origin": "custom",
        "timestamp": datetime.now(timezone.utc),
    }
    condition = (DBAssessment.id == row.id) & (DBAssessment.origin == "ai")
    conflict = "Assessment changed before approval; reload and review it again"
    expected_targets = None
    expected_responses = None
    if "expected_fingerprint" in payload and payload["expected_fingerprint"] != row.approval_fingerprint():
        return {"error": conflict}, 409
    check_links = "target_risk_links" in payload or any(t.risk_links for t in row.target_rows)
    if "expected_fingerprint" in payload or check_links:
        expected_targets = {(t.variant_id, t.finding_id) for t in row.target_rows}
        expected_responses = list(row.responses or [])
    has_edits = any(key in payload for key in APPROVAL_EDIT_FIELDS)
    if has_edits or "expected_fingerprint" in payload:
        # The omitted fields used during validation must still match at write time.
        for field in APPROVAL_CONTENT_FIELDS:
            condition &= getattr(DBAssessment, field) == getattr(row, field)
    if has_edits:
        reviewed_state = row.get_status_cdx_vex()
        content, error = _validate_content_edit(row, payload, preserve_omitted=True)
        if content is None:
            return {"error": error or "Invalid request data"}, 400
        if content.get_status_cdx_vex() != reviewed_state:
            return {"error": "Changing this justification would change the CycloneDX verdict"}, 400
        values.update({key: getattr(content, key) for key in APPROVAL_EDIT_FIELDS if key in payload})
    with batch_session():
        if expected_targets is not None:
            # Target writers take the same parent lock before changing membership.
            _lock_target_writes()
            locked = db.session.execute(
                db.select(DBAssessment.responses).where(condition).with_for_update()
            ).one_or_none()
            if locked is None or (locked.responses or []) != expected_responses:
                return {"error": conflict}, 409
            pairs = db.session.execute(
                db.select(AssessmentTarget.variant_id, AssessmentTarget.finding_id)
                .where(AssessmentTarget.assessment_id == row.id).with_for_update()
            ).tuples()
            if set(pairs) != expected_targets:
                return {"error": conflict}, 409
        else:
            hold_write_lock()
        try:
            link_edits = (_reviewed_links(row, payload.get("target_risk_links", []), approval=True)
                          if check_links else {})
        except RiskLinkError as exc:
            return {"error": str(exc)}, 400
        result = db.session.execute(
            db.update(DBAssessment)
            .where(condition)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if cast(CursorResult[Any], result).rowcount != 1:
            return {"error": conflict}, 409
        for target, links in link_edits.items():
            target.risk_links = links or None
        db.session.flush()
        db.session.refresh(row)
    return {"status": "success", "assessments": [row.to_dict()]}, 200


def _parse_batch_record_ids() -> tuple[list[UUID] | None, str | None]:
    """Return unique UUIDs from a batch-delete request, or an error message."""
    payload = request.get_json(silent=True) or {}
    raw_ids = payload.get("ids")
    if not isinstance(raw_ids, list) or not raw_ids or not all(isinstance(item, str) for item in raw_ids):
        return None, "'ids' must be a non-empty list of record id strings"
    try:
        return list(dict.fromkeys(UUID(item) for item in raw_ids)), None
    except ValueError:
        return None, "'ids' must contain valid record ids"


def init_app(app: Flask) -> None:

    @overload
    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None = None,
        compact: Literal[False] = False,
    ) -> list[AssessmentDict]:
        ...

    @overload
    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None,
        compact: Literal[True],
    ) -> list[CompactAssessment]:
        ...

    def _get_db_assessment_dicts(
        variant_ids: list[UUID] | None = None,
        compact: bool = False,
    ) -> list[AssessmentDict] | list[CompactAssessment]:
        """Serialize assessments with one lightweight joined query.

        The Explorer endpoint previously materialized tens of thousands of
        Assessment, Finding, and Package ORM objects only to immediately turn
        them into dictionaries.  Selecting the response columns directly
        avoids that object-graph cost and also lets project scope use one query
        instead of one query per variant.
        """
        if compact:
            ranked = (
                db.select(
                    DBAssessment.id.label("id"),
                    AssessmentTarget.variant_id.label("variant_id"),
                    DBAssessment.timestamp.label("timestamp"),
                    DBAssessment.status.label("status"),
                    Finding.vulnerability_id.label("vulnerability_id"),
                    Package.name.label("name"),
                    Package.version.label("version"),
                    Package.supplier.label("supplier"),
                    func.row_number().over(
                        partition_by=(
                            Finding.vulnerability_id,
                            AssessmentTarget.variant_id,
                            Finding.package_id,
                        ),
                        order_by=(DBAssessment.timestamp.desc(), DBAssessment.id.desc()),
                    ).label("assessment_rank"),
                )
                .join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                .join(Finding, AssessmentTarget.finding_id == Finding.id)
                .outerjoin(Package, Finding.package_id == Package.id)
                .where(db.or_(DBAssessment.origin.is_(None), DBAssessment.origin != "ai"))
            )
            if variant_ids is not None:
                if not variant_ids:
                    return []
                ranked = ranked.where(AssessmentTarget.variant_id.in_(variant_ids))
            ranked = ranked.subquery()
            query = (
                db.select(
                    ranked.c.id,
                    ranked.c.variant_id,
                    ranked.c.timestamp,
                    ranked.c.status,
                    ranked.c.vulnerability_id,
                    ranked.c.name,
                    ranked.c.version,
                    ranked.c.supplier,
                )
                .where(ranked.c.assessment_rank == 1)
                .order_by(ranked.c.timestamp)
            )
        else:
            query = (
                db.select(
                    DBAssessment.id.label("id"),
                    DBAssessment.source.label("source"),
                    DBAssessment.origin.label("origin"),
                    AssessmentTarget.variant_id.label("variant_id"),
                    AssessmentTarget.risk_links,
                    DBAssessment.timestamp.label("timestamp"),
                    DBAssessment.status.label("status"),
                    DBAssessment.status_notes.label("status_notes"),
                    DBAssessment.justification.label("justification"),
                    DBAssessment.impact_statement.label("impact_statement"),
                    DBAssessment.responses.label("responses"),
                    DBAssessment.workaround.label("workaround"),
                    Finding.vulnerability_id.label("vulnerability_id"),
                    Package.name.label("name"),
                    Package.version.label("version"),
                    Package.supplier.label("supplier"),
                )
                .join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                .join(Finding, AssessmentTarget.finding_id == Finding.id)
                .outerjoin(Package, Finding.package_id == Package.id)
                .where(db.or_(DBAssessment.origin.is_(None), DBAssessment.origin != "ai"))
            )
            if variant_ids is not None:
                if not variant_ids:
                    return []
                query = query.where(AssessmentTarget.variant_id.in_(variant_ids))
            # A multi-target assessment fans out to one row per target here.
            # Unlike compact (one entry per target by design), this branch's
            # consumers key by assessment id and expect exactly one record per
            # assessment, so the targets are folded back together below rather
            # than ranked: keeping a single representative would drop the
            # other packages and variants from the response entirely.
            query = query.order_by(
                DBAssessment.timestamp,
                DBAssessment.id,
                AssessmentTarget.variant_id,
                AssessmentTarget.finding_id,
            )

        full_by_id: dict[str, AssessmentDict] = {}
        linked_pairs: dict[UUID, list[dict[str, Any]]] = {}
        compact_result: list[CompactAssessment] = []
        for row in db.session.execute(query):
            package_id = ""
            if row.name is not None:
                package_id = f"{row.name}@{row.version}"
                if row.supplier:
                    package_id += f"::{row.supplier}"
            timestamp = ensure_utc_iso(row.timestamp)
            if compact:
                # Positional encoding avoids repeating six field names for
                # every row in this high-volume Explorer-only response:
                # [id, vulnerability, package, variant, timestamp, status].
                compact_result.append([
                    str(row.id),
                    row.vulnerability_id or "",
                    package_id or None,
                    str(row.variant_id) if row.variant_id else None,
                    timestamp,
                    row.status or "",
                ])
                continue
            assessment_id = str(row.id)
            entry = full_by_id.get(assessment_id)
            if entry is None:
                entry = {
                    "id": assessment_id,
                    "source": row.source or "",
                    "origin": row.origin or "sbom",
                    "vuln_id": row.vulnerability_id or "",
                    "packages": [],
                    "variant_id": None,
                    "variant_ids": [],
                    "targets": [],
                    "timestamp": timestamp,
                    "last_update": timestamp or "",
                    "status": row.status or "",
                    "status_notes": row.status_notes or "",
                    "justification": row.justification or "",
                    "impact_statement": row.impact_statement or "",
                    "responses": list(row.responses or []),
                    "workaround": row.workaround or "",
                }
                full_by_id[assessment_id] = entry
            if package_id and package_id not in entry["packages"]:
                entry["packages"].append(package_id)
            variant_id = str(row.variant_id) if row.variant_id else None
            if variant_id and variant_id not in entry["variant_ids"]:
                entry["variant_ids"].append(variant_id)
            # The pair, kept alongside the two flattened sets: those describe
            # the cross-product, which a sparse target set is not.
            if package_id and variant_id:
                pair: dict[str, Any] = {"variant_id": variant_id, "package": package_id}
                if pair not in entry["targets"]:
                    entry["targets"].append(pair)
                    if row.risk_links:
                        pair["risk_links"] = row.risk_links
                        linked_pairs.setdefault(row.variant_id, []).append(pair)

        if compact:
            return compact_result

        if linked_pairs:
            models = dict(db.session.execute(
                select(VariantContext.variant_id, VariantContext.stride_model)
                .where(VariantContext.variant_id.in_(linked_pairs))
            ).tuples().all())
            for vid, linked in linked_pairs.items():
                index = RiskModelIndex(models.get(vid))
                for pair in linked:
                    pair["risk_links"] = describe_links(pair["risk_links"], index)

        for entry in full_by_id.values():
            entry["variant_ids"].sort()
            entry["targets"].sort(key=lambda t: (t["variant_id"], t["package"]))
            # ``variant_id`` stays for backward compatibility and keeps the
            # meaning ``Assessment.to_dict`` gives it: the one variant every
            # target shares, or None for a genuine cross-variant assessment.
            # Consumers that need the full scope read ``variant_ids``.
            entry["variant_id"] = (
                entry["variant_ids"][0] if len(entry["variant_ids"]) == 1 else None
            )
        return list(full_by_id.values())

    @app.route('/api/assessments')
    def index_assess() -> ResponseReturnValue:
        """List assessments with optional variant or project filtering.

        By default returns every assessment; with ``format=dict`` the response
        is keyed by assessment ID.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        query format string optional Response format such as list or dict.
        response 200 AssessmentCollection Assessment collection.
        """
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        compact = request.args.get('format') == 'compact'
        scoped_variant_ids: list[UUID] | None
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            scoped_variant_ids = [variant_uuid]
        elif project_id:
            from ..models.variant import Variant as DBVariant
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            variants = DBVariant.get_by_project(project_uuid)
            scoped_variant_ids = [v.id for v in variants]
        else:
            scoped_variant_ids = None

        if compact:
            compact_assessments = _get_db_assessment_dicts(scoped_variant_ids, compact=True)
            payload = json.dumps(compact_assessments, separators=(",", ":")).encode()
            response = app.response_class(payload, mimetype="application/json")
            if "gzip" in request.headers.get("Accept-Encoding", "") and len(payload) > 1024:
                response.set_data(gzip.compress(payload, compresslevel=1))
                response.headers["Content-Encoding"] = "gzip"
                response.headers["Vary"] = "Accept-Encoding"
            return response

        assessments = _get_db_assessment_dicts(scoped_variant_ids, compact=False)
        annotate_assessments_outdated(assessments)
        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments

    def _current_context_updates(
        assessments: list[DBAssessment],
    ) -> dict[UUID, datetime | None]:
        """Last real context-change time for every targeted variant.

        AI agents consume the merged context, so a variant counts as changed when
        either its own context or its project's description was edited.
        """
        from ..models.project_context import ProjectContext
        from ..models.variant_context import VariantContext

        variant_ids = {
            target.variant_id
            for assessment in assessments
            for target in assessment.target_rows
        }
        updates: dict[UUID, datetime | None] = {
            variant_id: None for variant_id in variant_ids
        }
        if not variant_ids:
            return updates

        for variant_id, updated_at in db.session.execute(
            db.select(VariantContext.variant_id, VariantContext.updated_at).where(
                VariantContext.variant_id.in_(variant_ids)
            )
        ):
            updates[variant_id] = _as_utc(updated_at) if updated_at else None

        variant_project_ids = {
            variant_id: project_id
            for variant_id, project_id in db.session.execute(
                db.select(DBVariant.id, DBVariant.project_id).where(
                    DBVariant.id.in_(variant_ids)
                )
            )
        }
        project_updates = {
            project_id: _as_utc(updated_at)
            for project_id, updated_at in db.session.execute(
                db.select(ProjectContext.project_id, ProjectContext.updated_at).where(
                    ProjectContext.project_id.in_(set(variant_project_ids.values()))
                )
            )
            if updated_at
        }
        for variant_id, project_id in variant_project_ids.items():
            project_updated_at = project_updates.get(project_id)
            current = updates.get(variant_id)
            if project_updated_at is not None and (current is None or project_updated_at > current):
                updates[variant_id] = project_updated_at
        return updates

    def _as_utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    def _is_context_outdated(
        assessment: DBAssessment,
        context_updates: dict[UUID, datetime | None],
    ) -> bool:
        """True when any targeted variant changed after assessment creation."""
        created_at = _as_utc(assessment.created_at)
        return any(
            (updated_at := context_updates.get(target.variant_id)) is not None
            and updated_at > created_at
            for target in assessment.target_rows
        )

    def _review_assessments_by_origin(origin: str) -> ResponseReturnValue:
        """Return assessments matching ``origin``, enriched with a ``vuln_texts``
        key mapping to the vulnerability's ``texts`` dict so the front-end can
        display tooltips without extra requests.
        """
        from ..models.variant import Variant as DBVariant
        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')
        variant_ids: list[UUID] | None = None
        if variant_id:
            vid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if vid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [vid]
        if project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            project_variants = [v.id for v in DBVariant.get_by_project(pid)]
            variant_ids = (project_variants if variant_ids is None else
                           [vid for vid in variant_ids if vid in project_variants])
        if variant_ids == []:
            return [], 200
        assessments = DBAssessment.get_by_origin(variant_ids, origin=origin)

        # Enrich with vulnerability texts for front-end tooltips (single DB pass)
        vuln_ids = {a.vuln_id for a in assessments if a.vuln_id}
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)

        context_updates = _current_context_updates(assessments) if origin == "ai" else {}

        assessments_serialized = []
        link_scope = set(variant_ids) if variant_ids is not None else None
        indexes: dict[UUID, RiskModelIndex] = {}
        for a in assessments:
            a_ser = a.to_dict(link_scope=link_scope, link_indexes=indexes)
            a_ser["vuln_texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[a.vuln_id]))
            if origin == "ai":
                a_ser["context_outdated"] = _is_context_outdated(a, context_updates)
            assessments_serialized.append(a_ser)

        annotate_assessments_outdated(assessments_serialized)
        return assessments_serialized

    @app.route('/api/assessments/review')
    def review_assessments() -> ResponseReturnValue:
        """Return custom assessments awaiting review.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 Assessment[] Custom assessment collection.
        """
        return _review_assessments_by_origin("custom")

    @app.route('/api/assessments/review/ai')
    def review_ai_assessments() -> ResponseReturnValue:
        """Return pending AI-generated assessments.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 Assessment[] AI assessment collection.
        """
        return _review_assessments_by_origin("ai")

    @app.route('/api/assessments/review/export')
    def export_review_openvex() -> ResponseReturnValue:
        """Export custom assessments for one variant as an OpenVEX JSON document.

        OpenAPI:
        query variant_id uuid required Variant to export.
        query author string optional Author name embedded in exported OpenVEX documents.
        response 200 OpenVexDocument OpenVEX JSON download.
        response 400 Error Exactly one variant was not supplied.
        response 404 Error No review assessments available.
        """
        from ..models.variant import Variant as DBVariant

        raw_variant_ids = request.args.getlist('variant_id')
        if len(raw_variant_ids) != 1:
            return {"error": "Exactly one variant_id is required for OpenVEX export"}, 400
        variant_uuid, err = parse_uuid_or_400(raw_variant_ids[0], "variant_id")
        if err:
            return err
        if variant_uuid is None:
            return {"error": "Internal error"}, 500
        variant = DBVariant.get_by_id(variant_uuid)
        if variant is None:
            return {"error": "Variant not found"}, 404

        handmade = DBAssessment.get_by_origin([variant_uuid], origin="custom")
        if not handmade:
            return {"error": "No review assessments to export"}, 404

        author = request.args.get('author', 'Savoir-faire Linux')
        import json
        json_data = json.dumps(
            build_openvex_doc(handmade, author, variant_ids=[variant_uuid]), indent=2)
        filename = re.sub(r"[^\w\-.]", "_", variant.name)
        return json_data, 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="review_openvex_{filename}.json"',
        }

    @app.route('/api/assessments/review/import', methods=['POST'])
    def import_review_openvex() -> ResponseReturnValue:
        """Import an uploaded JSON OpenVEX document into one selected variant.

        OpenAPI:
        body multipart required Multipart request containing the JSON file and variant_id.
        form file binary required OpenVEX JSON file.
        form variant_id uuid required Destination variant.
        form timestamp_policy string optional original (default) or current.
        response 200 ImportSummary Import summary.
        response 400 Error Invalid uploaded OpenVEX payload.
        response 404 Error Variant not found.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload"}, 400
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            return {"error": "No file uploaded"}, 400
        if not uploaded.filename.endswith(".json"):
            return {"error": "Unsupported file type. Please upload a .json file."}, 400

        raw_variant_id = request.form.get('variant_id')
        if not raw_variant_id:
            return {"error": "variant_id is required for OpenVEX import"}, 400
        target_variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
        if err:
            return err
        if target_variant_id is None:
            return {"error": "Internal error"}, 500
        if DBVariant.get_by_id(target_variant_id) is None:
            return {"error": "Variant not found"}, 404

        timestamp_policy = request.form.get('timestamp_policy', 'original')
        if timestamp_policy not in {'original', 'current'}:
            return {"error": "timestamp_policy must be 'original' or 'current'"}, 400

        import json
        try:
            data = json.load(uploaded.stream)
        except Exception:
            return {"error": "Invalid JSON file"}, 400

        if not is_openvex_doc(data):
            return {
                "error": "Not a valid OpenVEX document "
                         "(missing @context with 'openvex' "
                         "or 'statements' array)"
            }, 400

        created, errors, skipped = _import_openvex_statements(
            data["statements"],
            target_variant_id,
            use_original_timestamps=timestamp_policy == 'original',
        )
        return {"status": "success", "imported": len(created), "skipped": skipped, "errors": errors}, 200

    @app.route('/api/assessments/review/time-estimates')
    def review_time_estimates() -> ResponseReturnValue:
        """Return vulnerabilities that have non-zero time estimates.

        Each entry contains the vulnerability ID and its three-point estimate
        (optimistic / likely / pessimistic) as ISO 8601 durations plus the
        raw hour values.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 ReviewTimeEstimate[] Vulnerabilities with time estimates.
        """
        from ..models.time_estimate import TimeEstimate
        from ..models.iso8601_duration import Iso8601Duration
        from ..models.variant import Variant as DBVariant
        from sqlalchemy.orm import joinedload

        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')

        query = (
            db.select(TimeEstimate)
            .join(Finding, TimeEstimate.finding_id == Finding.id)
            .options(joinedload(TimeEstimate.finding))
            .where(
                db.or_(
                    TimeEstimate.optimistic > 0,
                    TimeEstimate.likely > 0,
                    TimeEstimate.pessimistic > 0,
                )
            )
        )

        variant_ids_filter: list[UUID] | None = None
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if variant_uuid is None:
                return {"error": "Internal error"}, 500
            variant_ids_filter = [variant_uuid]
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids_filter = [v.id for v in DBVariant.get_by_project(pid)]

        if variant_ids_filter is not None:
            query = query.where(
                db.or_(
                    TimeEstimate.variant_id.in_(variant_ids_filter),
                    TimeEstimate.variant_id.is_(None),
                )
            )

        all_te = list(db.session.execute(query).scalars().all())

        def _hours_to_iso(h: int) -> str:
            try:
                return str(Iso8601Duration(f"PT{h}H"))
            except (ValueError, TypeError):
                return f"PT{h}H"

        # Bulk-load vulnerability texts to avoid N+1 queries
        vuln_ids_for_te = {te.finding.vulnerability_id for te in all_te}
        vuln_texts: dict[str, list[VulnerabilityText]]
        if vuln_ids_for_te:
            vuln_texts = fetch_vulnerabilities_texts(vuln_ids_for_te, variant_ids=variant_ids_filter)
        else:
            vuln_texts = {}

        # Key by (vuln_id, variant_id) so each variant keeps its own estimate
        # instead of variants overwriting each other for the same vulnerability.
        vuln_map: dict[tuple[str, str | None], dict] = {}
        for te in all_te:
            vid = te.finding.vulnerability_id
            scoped_variant = str(te.variant_id) if te.variant_id else None
            opt = te.optimistic or 0
            lik = te.likely or 0
            pes = te.pessimistic or 0
            vuln_map[(vid, scoped_variant)] = {
                "id": str(te.id),
                "vuln_id": vid,
                "variant_id": scoped_variant,
                "optimistic": opt,
                "likely": lik,
                "pessimistic": pes,
                "optimistic_iso": _hours_to_iso(opt),
                "likely_iso": _hours_to_iso(lik),
                "pessimistic_iso": _hours_to_iso(pes),
                "vuln_texts": list(map(VulnerabilityText.to_dict, vuln_texts.get(vid, []))),
            }

        # Prefer variant-scoped entries: when a vuln has at least one
        # variant-scoped estimate, drop its unscoped (variant-less) entry.
        vulns_with_scoped = {vid for (vid, variant) in vuln_map if variant is not None}
        result = [
            entry for (vid, variant), entry in vuln_map.items()
            if variant is not None or vid not in vulns_with_scoped
        ]

        return sorted(result, key=lambda x: (x["vuln_id"], x["variant_id"] or ""))

    @app.route('/api/assessments/review/custom-cvss')
    def review_custom_cvss() -> ResponseReturnValue:
        """Return vulnerabilities that have custom CVSS scores.

        A custom CVSS score is identified by ``origin == 'custom'``.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to every variant of a project.
        response 200 ReviewCustomCVSS[] Vulnerabilities with custom CVSS scores.
        """
        from ..models.metrics import Metrics

        variant_id = request.args.get('variant_id')
        project_id = request.args.get('project_id')

        variant_ids: list[UUID] | None = None
        query = select(Metrics).where(Metrics.origin == "custom")
        if variant_id:
            vid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if vid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [vid]
            query = query.where(db.or_(Metrics.variant_id == vid, Metrics.variant_id.is_(None)))
        elif project_id:
            pid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if pid is None:
                return {"error": "Internal error"}, 500
            variant_ids = [v.id for v in DBVariant.get_by_project(pid)]
            if variant_ids:
                query = query.where(db.or_(Metrics.variant_id.in_(variant_ids), Metrics.variant_id.is_(None)))
            else:
                query = query.where(db.false())
        query = query.order_by(Metrics.vulnerability_id)

        all_metrics = list(db.session.execute(query).scalars().all())

        vuln_ids = map(lambda m: m.vulnerability_id, all_metrics)
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)

        result: list[dict] = []
        for m in all_metrics:
            if _is_scanner_author(m.author):
                continue
            result.append({
                "id": str(m.id),
                "vuln_id": m.vulnerability_id,
                "variant_id": str(m.variant_id) if m.variant_id else None,
                "version": m.version or "",
                "vector_string": m.vector or "",
                "base_score": float(m.score) if m.score is not None else 0.0,
                "author": m.author,
                "origin": m.origin or "scanner",
                "vuln_texts": list(map(VulnerabilityText.to_dict, vuln_texts.get(m.vulnerability_id, []))),
            })

        return result

    @app.route('/api/assessments/review/time-estimates', methods=['DELETE'])
    def delete_review_time_estimates() -> ResponseReturnValue:
        """Delete the explicitly selected time estimates as one operation.

        OpenAPI:
        body ids uuid[] required Selected time-estimate record IDs.
        response 200 DeletionSummary Deletion confirmation with deleted record IDs.
        response 400 Error Missing or invalid record IDs.
        response 404 Error Time estimate not found.
        """
        from ..models.time_estimate import TimeEstimate

        ids, error = _parse_batch_record_ids()
        if error or ids is None:
            return {"error": error or "Invalid record ids"}, 400
        records = [db.session.get(TimeEstimate, estimate_id) for estimate_id in ids]
        if any(record is None for record in records):
            return {"error": "Time estimate not found"}, 404
        for record in records:
            db.session.delete(record)
        db.session.commit()
        return {"status": "success", "deleted": [str(estimate_id) for estimate_id in ids]}, 200

    @app.route('/api/assessments/review/custom-cvss', methods=['DELETE'])
    def delete_review_custom_cvss() -> ResponseReturnValue:
        """Delete selected custom CVSS records without affecting scanner data.

        OpenAPI:
        body ids uuid[] required Selected custom CVSS record IDs.
        response 200 DeletionSummary Deletion confirmation with deleted record IDs.
        response 400 Error Missing or invalid record IDs.
        response 404 Error Custom CVSS score not found.
        """
        from ..models.metrics import Metrics

        ids, error = _parse_batch_record_ids()
        if error or ids is None:
            return {"error": error or "Invalid record ids"}, 400
        records = [db.session.get(Metrics, metric_id) for metric_id in ids]
        if any(record is None or record.origin != "custom" for record in records):
            return {"error": "Custom CVSS score not found"}, 404
        for record in records:
            db.session.delete(record)
        db.session.commit()
        return {"status": "success", "deleted": [str(metric_id) for metric_id in ids]}, 200

    @app.route('/api/assessments/review/export-custom-data')
    def export_review_custom_data() -> ResponseReturnValue:
        """Export handmade and pending AI assessments, custom CVSS scores and
        time estimates as a single JSON file.

        Query parameters:

        * ``variant_id`` - restrict to selected variants; may be repeated.
        * ``project_id`` - restrict to all variants in a project.

        OpenAPI:
        query variant_id uuid[] optional Restrict export to selected variants; repeat this parameter.
        query project_id uuid optional Restrict export to a single project.
        response 200 CustomDataDocument Custom review data JSON download.
        response 404 Error No custom data available.
        """
        raw_variant_ids = request.args.getlist('variant_id')
        project_id = request.args.get('project_id')

        from ..models.project import Project as DBProject

        variant_ids: list[UUID] | None = None
        project_name = None
        if raw_variant_ids:
            variant_ids = []
            for raw_variant_id in raw_variant_ids:
                variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
                if err:
                    return err
                if variant_id is None:
                    return {"error": "Internal error"}, 500
                variant_ids.append(variant_id)
            variant = DBVariant.get_by_id(variant_ids[0])
            if variant and variant.project:
                project_name = variant.project.name
        elif project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            if project_uuid is None:
                return {"error": "Internal error"}, 500
            project = DBProject.get_by_id(project_uuid)
            if project:
                project_name = project.name
            variant_ids = [variant.id for variant in DBVariant.get_by_project(project_uuid)]

        data = build_custom_data_export(variant_ids)

        if (
            not data["assessments"]
            and not data["ai_assessments"]
            and not data["cvss"]
            and not data["time_estimates"]
        ):
            return {"error": "No custom data to export"}, 404

        import json as _json
        json_bytes = _json.dumps(data, indent=2)
        safe_name = re.sub(r'[^\w\-.]', '_', project_name) if project_name else None
        filename = f"custom_data_{safe_name}.json" if safe_name else "custom_data.json"
        return json_bytes, 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }

    @app.route('/api/assessments/review/export-update', methods=['POST'])
    def update_review_export() -> ResponseReturnValue:
        """Update an uploaded Review export using the currently selected variants.

        The uploaded document determines whether VulnScout JSON or OpenVEX is
        generated. Matching records retain their existing order, records for
        variants outside the current selection are removed, and new records
        are appended.

        OpenAPI:
        body multipart required Existing JSON export, project_id and repeated variant_id fields.
        form file binary required Existing OpenVEX or VulnScout custom-data JSON export.
        form project_id uuid required Project containing the selected variants.
        form variant_id uuid[] required Selected variants; repeat this field.
        response 200 ReviewExport Updated JSON download in the uploaded format.
        response 400 Error Unsupported input or invalid variant selection.
        response 404 Error No review data available.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return {"error": "Expected multipart/form-data with a file upload"}, 400
        uploaded = request.files.get('file')
        if not uploaded or not uploaded.filename:
            return {"error": "No file uploaded"}, 400
        if not uploaded.filename.lower().endswith('.json'):
            return {"error": "Unsupported file type. Please upload a .json file."}, 400

        try:
            existing = json.load(uploaded.stream)
        except (TypeError, ValueError):
            return {"error": "Invalid JSON file"}, 400
        try:
            export_format = detect_review_export_format(existing)
        except ValueError as error:
            return {"error": str(error)}, 400

        raw_variant_ids = request.form.getlist('variant_id')
        if not raw_variant_ids:
            return {"error": "At least one variant_id is required"}, 400
        raw_project_id = request.form.get('project_id')
        if not raw_project_id:
            return {"error": "project_id is required"}, 400
        project_id, err = parse_uuid_or_400(raw_project_id, "project_id")
        if err:
            return err
        if project_id is None:
            return {"error": "Internal error"}, 500
        variant_ids: list[UUID] = []
        for raw_variant_id in raw_variant_ids:
            variant_id, err = parse_uuid_or_400(raw_variant_id, "variant_id")
            if err:
                return err
            if variant_id is None:
                return {"error": "Internal error"}, 500
            variant = DBVariant.get_by_id(variant_id)
            if variant is None:
                return {"error": f"Variant not found: {raw_variant_id}"}, 404
            if variant.project_id != project_id:
                return {"error": f"Variant does not belong to project: {raw_variant_id}"}, 400
            variant_ids.append(variant_id)

        if export_format == 'openvex':
            if len(variant_ids) != 1:
                return {"error": "Exactly one variant_id is required for OpenVEX export"}, 400
            handmade = DBAssessment.get_by_origin(variant_ids, origin="custom")
            current = build_openvex_doc(
                handmade,
                request.form.get('author', existing.get('author', 'Savoir-faire Linux')),
                variant_ids=variant_ids,
            )
        else:
            current = build_custom_data_export(variant_ids)

        try:
            updated = reconcile_review_export(existing, current)
        except ValueError as error:
            return {"error": str(error)}, 400

        filename = re.sub(r'[^\w\-.]', '_', uploaded.filename) or 'review_export.json'
        return json.dumps(updated, indent=2), 200, {
            "Content-Type": "application/json",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }

    @app.route('/api/assessments/review/import-custom-data', methods=['POST'])
    def import_review_custom_data() -> ResponseReturnValue:
        """Import handmade and pending AI assessments, CVSS scores and time
        estimates from a custom-data JSON file.

        Accepts either:

        * ``multipart/form-data`` with a ``file`` field containing a ``.json``
                    file and a destination ``project_id`` field.
        * ``application/json`` body with the custom-data payload directly.

        OpenAPI:
        body CustomDataImport required Custom-data JSON payload with project_id and optional timestamp_policy.
        body multipart required Alternatively upload a custom-data JSON file.
        form file binary required Custom-data JSON file.
        form project_id uuid required Destination project; variants are resolved by names in the file.
        response 200 ImportSummary Import summary.
        response 400 Error Invalid import payload.
        """
        import json as _json
        if request.args.getlist('variant_id'):
            return {"error": "VulnScout JSON import uses the variants in the file"}, 400

        # Parse the incoming data
        data = None
        project_id = None
        if request.content_type and 'multipart/form-data' in request.content_type:
            uploaded = request.files.get('file')
            if not uploaded or not uploaded.filename:
                return {"error": "No file uploaded"}, 400
            try:
                data = _json.load(uploaded.stream)
            except Exception:
                return {"error": "Invalid JSON file"}, 400
            project_id = request.form.get('project_id')
        elif request.content_type and 'application/json' in request.content_type:
            data = request.get_json(silent=True)
            if data is None:
                return {"error": "Invalid JSON body"}, 400
            project_id = data.get('project_id')
        else:
            return {"error": "Expected multipart/form-data or application/json"}, 400

        if not isinstance(data, dict) or "version" not in data:
            return {"error": "Invalid custom-data format. Expected {version, assessments, ...}"}, 400
        try:
            custom_data_version(data)
        except ValueError as error:
            return {"error": str(error)}, 400

        if not isinstance(project_id, str) or not project_id:
            return {"error": "project_id is required"}, 400
        project_uuid, err = parse_uuid_or_400(project_id, "project_id")
        if err:
            return err
        if project_uuid is None:
            return {"error": "Internal error"}, 500

        from ..models.project import Project as DBProject
        if DBProject.get_by_id(project_uuid) is None:
            return {"error": "Project not found"}, 404

        timestamp_policy = data.get('timestamp_policy', 'current')
        if timestamp_policy not in {'original', 'current'}:
            return {"error": "timestamp_policy must be 'original' or 'current'"}, 400

        variant_by_name = build_variant_by_name_map(project_uuid)
        result = import_custom_data(
            data,
            variant_by_name,
            use_original_timestamps=timestamp_policy == 'original',
        )

        status_code = 200 if result["status"] == "success" else 400
        return result, status_code

    @app.get('/api/assessments/<assessment_id>/risk-link-preview')
    def assessment_risk_link_preview(assessment_id: str) -> ResponseReturnValue:
        """Compare one saved link with its current model without expanding every Review row.

        OpenAPI:
        query variant_id uuid required Target variant.
        query package string required Target package string ID.
        query risk_id string required Saved risk ID.
        query threat_id string optional Saved associated threat ID.
        response 200 RiskLinkPreview Current modeled descriptions and revision.
        response 404 Error Pending suggestion, link or model record no longer available.
        """
        row = DBAssessment.get_by_id(assessment_id)
        variant, package = request.args.get("variant_id"), request.args.get("package")
        ids = {k: request.args[k] for k in ("risk_id", "threat_id") if k in request.args}
        if row and row.origin == "ai" and "risk_id" in ids:
            for target in row.target_rows:
                if str(target.variant_id) != variant or target.finding.package.string_id != package:
                    continue
                if any((r["risk_id"], r.get("threat_id")) == (ids["risk_id"], ids.get("threat_id"))
                       for r in target.risk_links or []):
                    context = target.variant.context
                    try:
                        return preview_link(ids, context.stride_model if context else None), 200
                    except RiskLinkError:
                        break
        return {"error": "This modeled link is no longer available; correct or remove it"}, 404

    @app.route('/api/assessments/<assessment_id>')
    def assess_by_id(assessment_id: str) -> ResponseReturnValue:
        """Return a single assessment by identifier.

        OpenAPI:
        response 200 Assessment Assessment payload, targets, fingerprint, and reviews.
        response 404 Error Assessment not found.
        """
        item = DBAssessment.get_by_id(assessment_id)
        if item is None:
            return {"error": "Not found"}, 404
        payload = annotate_targets([item])[0]
        variant_project_ids = {
            variant_id: project_id
            for variant_id, project_id in db.session.execute(
                db.select(DBVariant.id, DBVariant.project_id).where(
                    DBVariant.id.in_({target.variant_id for target in item.target_rows})
                )
            )
        }
        for target in payload["targets"]:
            variant_uuid = UUID(target["variant_id"])
            target["project_id"] = str(variant_project_ids[variant_uuid])
        project_ids = set(variant_project_ids.values())
        payload["project_id"] = (
            str(next(iter(project_ids))) if len(project_ids) == 1 else None
        )
        payload["assessment_fingerprint"] = fingerprint_assessment(item)
        reviews = AssessmentReview.get_all_for_assessment(item.id)
        payload["reviews"] = [r.to_dict() for r in reviews]
        return payload, 200

    @app.route('/api/vulnerabilities/<vuln_id>/assessments')
    def list_assess_by_vuln(vuln_id: str) -> ResponseReturnValue:
        """List assessments linked to a vulnerability.

        OpenAPI:
        query format string optional Response format such as list or dict.
        query project_id uuid optional Restrict results to one project.
        response 200 AssessmentCollection Assessment collection for the vulnerability.
        """
        project_uuid: UUID | None = None
        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err

        project_variant_ids: set[UUID] | None = None
        if project_uuid is not None:
            project_variant_ids = set(db.session.execute(
                select(DBVariant.id).where(DBVariant.project_id == project_uuid)
            ).scalars())

        rows = _assessments_for_vulnerability(vuln_id, project_variant_ids)
        assessments = annotate_targets(rows, project_variant_ids)

        ai_rows = [row for row in rows if row.origin == "ai"]
        if ai_rows:
            context_updates = _current_context_updates(ai_rows)
            outdated_by_id = {
                str(row.id): _is_context_outdated(row, context_updates)
                for row in ai_rows
            }
            for a in assessments:
                if a.get("origin") == "ai":
                    a["context_outdated"] = outdated_by_id.get(str(a["id"]), False)

        if request.args.get('format', 'list') == "dict":
            return {a["id"]: a for a in assessments}
        return assessments, 200

    @app.route('/api/assessments/<assessment_id>/reconcile', methods=['POST'])
    def reconcile_assessment(assessment_id: str) -> ResponseReturnValue:
        """Bring an assessment to the requested state in one transaction.

        OpenAPI:
        body AssessmentReconcile required Desired assessment content and targets.
        response 200 Assessment The reconciled assessment.
        response 400 Error Invalid reconcile payload.
        response 404 Error No such assessment.
        """
        assessment_uuid, err = parse_uuid_or_400(assessment_id, "assessment_id")
        if err:
            return err
        if assessment_uuid is None:
            return {"error": "Internal error"}, 500

        existing = DBAssessment.get_by_id(assessment_uuid)
        if existing is None:
            return {"error": "Assessment not found"}, 404

        req, parse_err = parse_reconcile_payload(request.get_json() or {})
        if parse_err:
            return parse_err, 400
        if req is None:
            return {"error": "Internal error"}, 500

        if req.vuln_id.upper() != (existing.vuln_id or "").upper():
            return {"error": "vuln_id does not match this assessment's vulnerability"}, 400

        try:
            with batch_session():
                _lock_target_writes()
                existing = db.session.scalar(
                    db.select(DBAssessment).where(DBAssessment.id == assessment_uuid).with_for_update()
                    .execution_options(populate_existing=True)
                )
                if existing is None:
                    return {"error": "Assessment not found"}, 404
                targets, target_err = resolve_targets(req, index_targets(existing))
                if target_err:
                    return target_err, 400
                deletion_err = validate_deletions(existing, targets)
                if deletion_err:
                    return deletion_err, 400
                result = apply_reconcile(req, existing, targets)
        except GroupInvariantError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        if result["became_custom"] or result["deleted_non_custom"]:
            invalidate_scan_list_cache()

        return {
            "status": "success",
            "updated": result["updated"],
            "created": result["created"],
            "deleted": result["deleted"],
        }, 200

    @app.route('/api/reviews/assessments', methods=['GET'])
    def list_review_assessments() -> ResponseReturnValue:
        """List assessments for the review table.

        OpenAPI:
        query variant_id uuid optional Restrict results to one variant.
        query project_id uuid optional Restrict results to one project.
        query origin string optional Restrict results to one origin.
        response 200 Assessment[] Assessments for review.
        """
        query = select(DBAssessment)
        # The variant/project filters below match against the joined target
        # rather than the assessment; joining once and adding .distinct()
        # keeps the one-row-per-assessment shape annotate_targets() expects
        # even though the join fans out to one row per matching target.
        joined_targets = False
        variant_ids: list[UUID] | None = None
        variant_id = request.args.get('variant_id')
        if variant_id:
            variant_uuid, err = parse_uuid_or_400(variant_id, "variant_id")
            if err:
                return err
            if not joined_targets:
                query = query.join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                joined_targets = True
            query = query.where(AssessmentTarget.variant_id == variant_uuid)
            variant_ids = [variant_uuid] if variant_uuid else None

        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            project_variant_ids = [v.id for v in DBVariant.get_by_project(project_uuid)] if project_uuid else []
            if not joined_targets:
                query = query.join(AssessmentTarget, AssessmentTarget.assessment_id == DBAssessment.id)
                joined_targets = True
            query = query.where(AssessmentTarget.variant_id.in_(project_variant_ids))
            variant_ids = (project_variant_ids if variant_ids is None else
                           [vid for vid in variant_ids if vid in project_variant_ids])

        origin = request.args.get('origin')
        if origin:
            query = query.where(DBAssessment.origin == origin)

        if joined_targets:
            query = query.distinct()

        rows = list(db.session.execute(query).scalars())
        assessments = annotate_targets(rows, set(variant_ids) if variant_ids is not None else None)

        # Enrich with vulnerability texts for front-end tooltips (single DB
        # pass) — the review table spans several CVEs, unlike the vuln-scoped
        # /assessments route where the caller already knows the texts.
        vuln_ids = {a["vuln_id"] for a in assessments if a.get("vuln_id")}
        vuln_texts = fetch_vulnerabilities_texts(vuln_ids, variant_ids=variant_ids)
        for a in assessments:
            a["vuln_texts"] = list(map(VulnerabilityText.to_dict, vuln_texts.get(a["vuln_id"], [])))

        if origin == "ai":
            context_updates = _current_context_updates(rows)
            outdated_by_id = {
                str(row.id): _is_context_outdated(row, context_updates)
                for row in rows
            }
            for a in assessments:
                a["context_outdated"] = outdated_by_id.get(str(a["id"]), False)

        return assessments, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variants', methods=['GET'])
    def list_variants_by_vuln(vuln_id: str) -> ResponseReturnValue:
        """Return all distinct variants that have a finding for this vulnerability
        (via the Observation → Scan → Variant chain).

        OpenAPI:
        response 200 Variant[] Variants impacted by the vulnerability.
        """
        from ..models.observation import Observation
        from ..models.scan import Scan
        from ..models.variant import Variant as DBVariant
        findings = Finding.get_by_vulnerability(vuln_id)
        seen_variant_ids: set = set()
        variants_out = []
        for finding in findings:
            for obs in Observation.get_by_finding(finding.id):
                scan = db.session.get(Scan, obs.scan_id)
                if scan is None:
                    continue
                if scan.variant_id in seen_variant_ids:
                    continue
                seen_variant_ids.add(scan.variant_id)
                variant = db.session.get(DBVariant, scan.variant_id)
                if variant:
                    variants_out.append({
                        "id": str(variant.id),
                        "name": variant.name,
                        "project_id": str(variant.project_id),
                    })
        return variants_out, 200

    @app.route('/api/vulnerabilities/<vuln_id>/variant-active-packages')
    def list_variant_active_packages(vuln_id: str) -> ResponseReturnValue:
        """For each variant affected by this vulnerability, return the subset of
        the vulnerability's packages still present in that variant's active SBOM.

        Lets the front-end classify deprecated (variant, package) pairs in a
        single request instead of one ``/api/packages`` call per variant.

        OpenAPI:
        query project_id uuid optional Restrict the result to one project.
        response 200 VariantActivePackages Active packages by variant.
        """
        from ..helpers.active_targets import variant_active_packages

        project_uuid: UUID | None = None
        project_id = request.args.get('project_id')
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
        return variant_active_packages(vuln_id, project_uuid), 200

    @app.route("/api/vulnerabilities/<vuln_id>/assessments", methods=["POST"])
    def add_assessment(vuln_id: str) -> ResponseReturnValue:
        """Create one custom assessment for a vulnerability, across every
        selected (package, variant) combo.

        OpenAPI:
        body AssessmentCreate required Assessment content and targets.
        response 200 Assessment Created assessment payload.
        response 400 Error Invalid assessment payload.
        response 500 Error Database error while creating the assessment.
        """
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        if "vuln_id" not in payload_data:
            payload_data["vuln_id"] = vuln_id
        elif payload_data["vuln_id"] != vuln_id or not isinstance(payload_data["vuln_id"], str):
            return {"error": "Invalid vuln_id"}, 400

        explicit_targets: list[tuple[str, UUID]] | None = None
        link_edits = []
        ai_generated = bool(payload_data.get("ai_generated"))
        if "risk_links" in payload_data or "target_risk_links" in payload_data:
            return {"error": "Specify risk_links inside each exact target"}, 400
        raw_targets = payload_data.get("targets")
        if raw_targets is not None:
            if not isinstance(raw_targets, list) or not raw_targets:
                return {"error": "targets must be a non-empty list"}, 400
            explicit_targets = []
            for target in raw_targets:
                if not isinstance(target, dict):
                    return {"error": "Invalid target"}, 400
                package_id = target.get("package")
                if not isinstance(package_id, str) or not package_id:
                    return {"error": "Target package is required"}, 400
                raw_target_variant = target.get("variant_id")
                if not isinstance(raw_target_variant, str):
                    return {"error": "Invalid variant_id"}, 400
                target_variant_id, err = parse_uuid_or_400(
                    raw_target_variant, "variant_id")
                if err:
                    return err
                if target_variant_id is None:
                    return {"error": "Invalid variant_id"}, 400
                pair = (package_id, target_variant_id)
                if "risk_links" in target:
                    links = target["risk_links"]
                    if ai_generated:
                        if links != []:
                            return {
                                "error": "AI assessments must cite modeled risks in status_notes, not risk_links",
                            }, 400
                    else:
                        link_edits.append({"variant_id": str(target_variant_id), "package": package_id,
                                           "risk_links": links})
                if pair not in explicit_targets:
                    explicit_targets.append(pair)
            payload_data["packages"] = list(dict.fromkeys(
                package for package, _variant in explicit_targets))
            payload_data["variant_ids"] = list(dict.fromkeys(
                str(variant) for _package, variant in explicit_targets))

        assessment, status = payload_to_assessment(payload_data)
        if status != 200:
            if not isinstance(assessment, dict):
                return {"error": "Internal error"}, 500
            return assessment, status
        if not isinstance(assessment, DBAssessment):
            return {"error": "Internal error"}, 500

        # Resolve the effective variant id list: variant_ids (plural) takes
        # priority when present; otherwise fall back to the legacy singular
        # variant_id wrapped in a one-element list.
        raw_variant_ids = payload_data.get("variant_ids")
        if not (isinstance(raw_variant_ids, list) and raw_variant_ids):
            single = payload_data.get("variant_id") or None
            raw_variant_ids = [single] if single else []
        if not raw_variant_ids:
            return {"error": "variant_id is required"}, 400

        variant_ids: list[UUID] = []
        for raw in raw_variant_ids:
            parsed, err = parse_uuid_or_400(raw, "variant_id")
            if err:
                return err
            if parsed is None:
                return {"error": "Invalid variant_id"}, 400
            variant_ids.append(parsed)

        target_origin = "ai" if ai_generated else "custom"

        # Use a single timestamp so the created row's own targets (and any
        # sibling row a caller correlates by timestamp) share the exact same
        # value. Prefer the timestamp from the payload (allows frontend to
        # synchronise across multiple requests); fall back to server time.
        from datetime import datetime as _dt, timezone as _tz
        shared_timestamp = getattr(assessment, 'timestamp', None) or _dt.now(_tz.utc)

        # Resolve every package up front. Assessments must never create a
        # package: if any referenced package is missing, block the whole request.
        resolved_packages: list[Package] = []
        missing_packages: list[str] = []
        for pkg_string_id in (assessment.packages or []):
            db_pkg = resolve_package(pkg_string_id)
            if db_pkg is None:
                missing_packages.append(pkg_string_id)
            else:
                resolved_packages.append(db_pkg)
        if missing_packages:
            return {
                "error": "Package not found: " + ", ".join(missing_packages)
                + ". Assessments can only be written for existing packages."
            }, 400

        try:
            resolved, unobserved = resolve_target_set(
                resolved_packages, vuln_id, variant_ids)
        except ValueError as exc:
            return {"error": str(exc)}, 400
        if unobserved:
            return {
                "error": "Invalid package version for vulnerability and variant: "
                + ", ".join(unobserved)
            }, 400

        if explicit_targets is not None:
            missing_targets = [
                f"{package} in {variant}"
                for package, variant in explicit_targets
                if (package, variant) not in resolved
            ]
            if missing_targets:
                return {
                    "error": "Invalid package version for vulnerability and variant: "
                    + ", ".join(missing_targets)
                }, 400
            resolved = {
                pair: resolved[pair]
                for pair in explicit_targets
            }
        targets = [(variant_id, finding.id) for (_pkg, variant_id), finding in resolved.items()]

        replaced: list[dict[str, Any]] = []
        try:
            with batch_session():
                # A new AI assessment replaces the pending one on the same
                # (variant, package) targets. Done in the same transaction as
                # the create, so a failed create rolls the removal back.
                if ai_generated:
                    replaced = _replace_pending_ai(vuln_id, targets)
                # Always create a new record — never merge with an existing
                # one. from_vuln_assessment does a find-or-update which would
                # overwrite previous user assessments on the same target set.
                db_a = create_assessment_record(
                    assessment, targets, timestamp=shared_timestamp, origin=target_origin)
                if link_edits:
                    for target_row, links in _reviewed_links(db_a, link_edits).items():
                        target_row.risk_links = links or None
        except (GroupInvariantError, RiskLinkError) as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": f"DB error: {e}"}, 500

        created = [db_a.to_dict()]
        response_body: dict[str, Any] = {
            "status": "success", "assessments": created, "assessment": created[0]}
        if replaced:
            response_body["replaced"] = replaced
        return response_body, 200

    @app.route("/api/assessments/batch", methods=["POST"])
    def add_assessments_batch() -> ResponseReturnValue:
        """Create multiple custom assessments in a single request.

        OpenAPI:
        body AssessmentBatch required Batch assessment creation payload.
        response 200 AssessmentBatchResult Batch creation summary.
        response 400 Error Invalid batch payload.
        """
        payload_data = request.get_json()
        if not payload_data or "assessments" not in payload_data or not isinstance(payload_data["assessments"], list):
            return {"error": "Invalid request data. Expected: {assessments: [...]}"}, 400

        errors: list[dict[str, Any]] = []
        prepared: list[tuple[DBAssessment, list[tuple[UUID, UUID]]]] = []
        pkg_cache: dict[str, Package] = {}

        # Validate the complete request before opening the write transaction.
        # A batch represents one user action, so one invalid package/variant
        # relationship must cancel every assessment in that action.
        for item in payload_data["assessments"]:
            if not isinstance(item, dict) or "vuln_id" not in item:
                errors.append({"error": "Invalid assessment data", "item": item})
                continue

            assessment, status = payload_to_assessment(item)
            if status != 200:
                error = assessment.get("error", "Unknown error") if isinstance(assessment, dict) else "Internal error"
                errors.append({"vuln_id": item.get("vuln_id"), "error": error})
                continue
            if not isinstance(assessment, DBAssessment):
                errors.append({"vuln_id": item.get("vuln_id"), "error": "Internal error"})
                continue

            vuln_id = assessment.vuln_id
            raw_variant_ids = item.get("variant_ids")
            if not (isinstance(raw_variant_ids, list) and raw_variant_ids):
                single = item.get("variant_id") or None
                raw_variant_ids = [single] if single else []
            if not raw_variant_ids:
                errors.append({"vuln_id": vuln_id, "error": "variant_id is required"})
                continue

            variant_ids: list[UUID] = []
            invalid_variant = False
            for raw_variant_id in raw_variant_ids:
                parsed, err = parse_uuid_or_400(raw_variant_id, "variant_id")
                if err or parsed is None:
                    errors.append({"vuln_id": vuln_id, "error": "Invalid variant_id"})
                    invalid_variant = True
                    break
                variant_ids.append(parsed)
            if invalid_variant:
                continue

            pkg_list = assessment.packages or []
            if not pkg_list:
                errors.append({
                    "vuln_id": vuln_id,
                    "variant_ids": [str(value) for value in variant_ids],
                    "error": "No valid package found",
                })
                continue

            item_packages: list[Package] = []
            item_missing: list[str] = []
            for pkg_string_id in pkg_list:
                db_pkg = pkg_cache.get(pkg_string_id)
                if db_pkg is None:
                    db_pkg = resolve_package(pkg_string_id)
                    if db_pkg is not None:
                        pkg_cache[pkg_string_id] = db_pkg
                if db_pkg is None:
                    item_missing.append(pkg_string_id)
                else:
                    item_packages.append(db_pkg)
            if item_missing:
                errors.append({
                    "vuln_id": vuln_id,
                    "variant_ids": [str(value) for value in variant_ids],
                    "error": "Package not found: " + ", ".join(item_missing)
                    + ". Assessments can only be written for existing packages.",
                })
                continue

            try:
                resolved, unobserved = resolve_target_set(
                    item_packages, vuln_id, variant_ids)
            except ValueError as exc:
                errors.append({"vuln_id": vuln_id, "error": str(exc)})
                continue
            if unobserved:
                errors.append({
                    "vuln_id": vuln_id,
                    "variant_ids": [str(value) for value in variant_ids],
                    "error": "Invalid package version for vulnerability and variant: "
                    + ", ".join(unobserved),
                })
                continue
            item_targets = [
                (variant_id, finding.id)
                for (_package, variant_id), finding in resolved.items()
            ]
            prepared.append((assessment, item_targets))

        if errors:
            return {
                "status": "error",
                "assessments": [],
                "count": 0,
                "vuln_count": 0,
                "errors": errors,
                "error_count": len(errors),
            }, 400

        results: list[AssessmentDict] = []
        try:
            with batch_session():
                # A batch is one user action but may span several CVEs,
                # several projects and several distinct contents. Each item
                # creates exactly one row covering every package in that
                # item; batching never fuses separate items together.
                created_rows: list[DBAssessment] = []
                for assessment, item_targets in prepared:
                    created_rows.append(create_assessment_record(
                        assessment, item_targets,
                        timestamp=getattr(assessment, "timestamp", None),
                    ))

                results = [row.to_dict() for row in created_rows]
        except Exception as e:
            return {
                "status": "error",
                "assessments": [],
                "count": 0,
                "vuln_count": 0,
                "errors": [{"error": f"DB error: {e}"}],
                "error_count": 1,
            }, 500

        distinct_vulns = len({r.get("vuln_id") for r in results if r.get("vuln_id")})
        response = {
            "status": "success" if results else "error",
            "assessments": results,
            "count": len(results),
            "vuln_count": distinct_vulns
        }
        return response, 200 if results else 400

    @app.route("/api/assessments/<assessment_id>", methods=["PUT", "PATCH"])
    def update_assessment(assessment_id: str) -> ResponseReturnValue:
        """Update a custom assessment or override an automated one.

        OpenAPI:
        body AssessmentUpdate required Assessment update payload.
        body allowed_variant_ids uuid[] optional Reject if any current target is outside these variants.
        response 200 Assessment Updated assessment payload.
        response 400 Error Invalid assessment update.
        response 404 Error Assessment not found.
        """
        payload_data = request.get_json()
        if not payload_data:
            return {"error": "Invalid request data"}, 400

        allowed_ids = None
        if "allowed_variant_ids" in payload_data:
            raw_ids = payload_data["allowed_variant_ids"]
            if not isinstance(raw_ids, list) or not raw_ids or any(not isinstance(value, str) for value in raw_ids):
                return {"error": "Invalid allowed_variant_ids"}, 400
            try:
                allowed_ids = {UUID(value) for value in raw_ids}
            except ValueError:
                return {"error": "Invalid allowed_variant_ids or assessment ID"}, 400
        try:
            assessment_uuid = UUID(assessment_id)
        except ValueError:
            if allowed_ids is not None:
                return {"error": "Invalid allowed_variant_ids or assessment ID"}, 400
            return {"error": "Assessment not found"}, 404

        with write_lock():
            # Serialize the read used for validation with edited approvals.
            _lock_target_writes()
            result, status = _update_locked_assessment(assessment_uuid, allowed_ids, payload_data)
            if status != 200:
                db.session.rollback()
            return result, status

    def _update_locked_assessment(
        assessment_uuid: UUID, allowed_ids: set[UUID] | None, payload_data: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        existing = db.session.scalar(
            db.select(DBAssessment).where(DBAssessment.id == assessment_uuid).with_for_update()
            .execution_options(populate_existing=True)
        )
        if existing is None:
            return {"error": "Assessment not found"}, 404
        if allowed_ids is not None:
            current_ids = db.session.execute(
                db.select(AssessmentTarget.variant_id)
                .where(AssessmentTarget.assessment_id == existing.id).with_for_update()
            ).scalars().all()
            if not current_ids or not set(current_ids) <= allowed_ids:
                return {"error": "Assessment targets changed or are outside the current agent scope."}, 409
            db.session.expire(existing, ["target_rows"])
        if not existing.target_rows or any(
            find_valid_finding(
                target.finding.package_id,
                target.finding.vulnerability_id,
                target.variant_id,
            ) is None
            for target in existing.target_rows
        ):
            return {"error": "Assessment references a package version that is not valid for its variant"}, 400

        was_non_custom = (existing.origin or "") != "custom"
        # Editing a pending AI assessment directly must not silently approve
        # it: keep its origin as "ai" so it stays pending until the user
        # explicitly approves/rejects it via the dedicated endpoints.
        new_origin = "ai" if existing.origin == "ai" else "custom"

        mem_assess, content_error = _validate_content_edit(existing, payload_data)
        if mem_assess is None:
            return {"error": content_error or "Invalid request data"}, 400

        update_timestamp = payload_data.get("update_timestamp", True)
        if not isinstance(update_timestamp, bool):
            return {"error": "update_timestamp must be a boolean"}, 400
        edit_timestamp = None
        if update_timestamp and "timestamp" in payload_data:
            if not isinstance(payload_data["timestamp"], str):
                return {"error": "timestamp must be an ISO 8601 string"}, 400
            try:
                edit_timestamp = datetime.fromisoformat(payload_data["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                return {"error": "Invalid timestamp"}, 400

        existing.update(
            status=mem_assess.status,
            origin=new_origin,
            status_notes=mem_assess.status_notes,
            justification=mem_assess.justification,
            impact_statement=mem_assess.impact_statement,
            workaround=getattr(mem_assess, "workaround", None),
            responses=list(mem_assess.responses or []),
            timestamp=edit_timestamp,
            update_timestamp=update_timestamp,
        )
        # Editing an automated assessment removes it from the scan-history
        # counts (it becomes custom-origin), so refresh the cached list view.
        # A pending AI row that stays "ai" after editing has not changed its
        # scan-history membership, so no cache refresh is needed in that case.
        if was_non_custom and new_origin == "custom":
            invalidate_scan_list_cache()
        return {"status": "success", "assessment": existing.to_dict()}, 200

    @app.route("/api/assessments/<assessment_id>", methods=["DELETE"])
    def delete_assessment(assessment_id: str) -> ResponseReturnValue:
        """Delete an assessment.

        OpenAPI:
        response 200 DeletionSummary Deletion summary.
        response 404 Error Assessment not found.
        """
        existing = DBAssessment.get_by_id(assessment_id)
        if existing is None:
            return {"error": "Assessment not found"}, 404
        # A non-custom assessment contributes to the scan-history counts, so
        # its removal must invalidate the cached list view.
        was_non_custom = (existing.origin or "") != "custom"
        if existing.origin == "ai":
            return {"error": "Use the AI approve/reject endpoints for pending AI assessments"}, 400
        existing.delete()
        if was_non_custom:
            invalidate_scan_list_cache()
        return {"status": "success", "message": "Assessment deleted successfully"}, 200

    @app.route("/api/assessments/<assessment_id>/approve", methods=["POST"])
    def approve_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        """Approve a pending AI assessment, converting it to custom.

        An optional body edits the suggestion's rationale in the same
        transaction. Approval cannot change the suggested status.

        OpenAPI:
        body AssessmentApproval optional Rationale edits applied before approval.
        response 200 AssessmentWriteResult Approved assessment.
        response 400 Error Not a pending AI assessment, or invalid content edits.
        response 404 Error Assessment not found.
        response 409 Error Assessment changed before approval.
        response 413 Error Request body exceeds the approval size limit.
        """
        # Only a JSON body carries edits; any other body is ignored as before.
        payload: Any = {}
        current_limit = request.max_content_length
        limit = min(
            current_limit, _APPROVAL_REQUEST_MAX_BYTES
        ) if current_limit is not None else _APPROVAL_REQUEST_MAX_BYTES
        # Werkzeug can stop a terminated, lengthless stream at its limit
        # without signalling overflow. Read at most one extra byte to tell.
        request.max_content_length = limit + 1 if request.content_length is None else limit
        try:
            body = request.get_data(cache=True) if request.is_json else b""
            if len(body) > limit:
                raise RequestEntityTooLarge()
            if body:
                payload = request.get_json(silent=True)
                if not isinstance(payload, dict):
                    return {"error": "Invalid request data"}, 400
        except RequestEntityTooLarge:
            return {"error": "Request body exceeds the approval size limit"}, 413
        if payload.keys() - (*APPROVAL_EDIT_FIELDS, "expected_fingerprint", "target_risk_links"):
            return {"error": "Approval accepts only rationale fields, target_risk_links and expected_fingerprint"}, 400
        if any(not isinstance(value, str) for k, value in payload.items() if k != "target_risk_links"):
            return {"error": "Assessment edit fields must be strings"}, 400
        for field in APPROVAL_EDIT_FIELDS:
            if field in payload and "\x00" in payload[field]:
                return {"error": f"{field} must not contain NUL characters"}, 400
        row, err = _resolve_pending_ai_row(assessment_id)
        if err is not None:
            return err
        if row is None:
            return {"error": "Internal error"}, 500
        return _approve_row(row, payload)

    @app.route("/api/assessments/<assessment_id>/reject", methods=["POST"])
    def reject_ai_assessment(assessment_id: str) -> ResponseReturnValue:
        """Reject a pending AI assessment, deleting it.

        OpenAPI:
        response 200 DeletionSummary Deleted assessment id.
        response 400 Error Not a pending AI assessment.
        response 404 Error Assessment not found.
        """
        try:
            aid = UUID(assessment_id)
        except ValueError:
            return {"error": "Assessment not found"}, 404
        session = db.session()
        with session.begin():
            # Match approval's parent-first ordering before cascading to targets.
            _lock_target_writes()
            row = session.scalar(
                db.select(DBAssessment).where(DBAssessment.id == aid).with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None:
                return {"error": "Assessment not found"}, 404
            if row.origin != "ai":
                return {"error": "Not a pending AI assessment"}, 400
            session.delete(row)
        return {"status": "success", "deleted": [str(aid)]}, 200


def payload_to_assessment(
    data: dict, *, allow_empty_packages: bool = False,
) -> "tuple[DBAssessment | dict[str, str], int]":
    """
    Take an object in input and try to convert it to an Assessment DTO.
    Return either (Assessment, 200) or (error_dict, http_code).
    """
    if ("packages" not in data or not isinstance(data["packages"], list)
            or (not allow_empty_packages and len(data["packages"]) < 1)):
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
