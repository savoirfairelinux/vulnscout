# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for importing and exporting assessments as OpenVEX JSON.

Both the CLI (``cmd_assessments.py``) and the web API (``routes/assessments.py``)
perform the same build/parse logic.  This module contains the common core so
neither caller needs to re-implement it.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime as _dt, timezone as _tz
from typing import TYPE_CHECKING, Any

from .datetime_utils import normalize_timestamp_for_sort

if TYPE_CHECKING:
    from ..models.variant import Variant as _Variant
    from ..models.assessment import Assessment as _Assessment
    from ..models.vulnerability import Vulnerability as _Vulnerability


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _get_vuln_info(vuln_id: str, vuln_cache: "dict[str, _Vulnerability | None]") -> "dict[str, str | list[str]]":
    """Return a dict with description, aliases and url for *vuln_id*.

    Uses *vuln_cache* (mutated in-place) to avoid repeated DB lookups.
    """
    from ..models.vulnerability import Vulnerability as DBVuln

    if vuln_id not in vuln_cache:
        vuln_cache[vuln_id] = DBVuln.get_by_id(vuln_id)
    vuln_obj = vuln_cache[vuln_id]

    description = ""
    aliases: list[str] = []
    vuln_url = ""
    if vuln_obj:
        description = vuln_obj.description or ""
        aliases = list(vuln_obj.aliases or [])
        urls = (
            list(vuln_obj.urls) if vuln_obj.urls
            else list(vuln_obj.links or [])
        )
        vuln_url = urls[0] if urls else ""
        if not vuln_url and vuln_id.startswith("CVE-"):
            vuln_url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        elif not vuln_url and vuln_id.startswith("GHSA-"):
            vuln_url = f"https://github.com/advisories/{vuln_id}"
    return {"description": description, "aliases": aliases, "url": vuln_url}


def sanitize_variant_name(name: str) -> str:
    """Replace filesystem-unsafe characters in a variant name."""
    return name.replace("/", "_").replace("\\", "_")


def build_openvex_doc(
    assessments: "list[_Assessment]",
    author: str,
    now_iso: str | None = None,
    vuln_cache: "dict[str, _Vulnerability | None] | None" = None,
) -> dict[str, Any]:
    """Build a single OpenVEX document dict from a list of assessments.

    Parameters
    ----------
    assessments:
        List of DB ``Assessment`` objects.
    author:
        Author string written into the document header.
    now_iso:
        ISO-8601 timestamp.  Defaults to *now*.
    vuln_cache:
        Optional mutable cache ``{vuln_id: VulnModel | None}`` to avoid
        repeated DB lookups across multiple calls.

    Returns
    -------
    dict — a complete OpenVEX document ready for JSON serialisation.
    """
    if now_iso is None:
        now_iso = _dt.now(_tz.utc).isoformat()
    if vuln_cache is None:
        vuln_cache = {}

    statements = []
    for assess in assessments:
        stmt = assess.to_openvex_dict()
        if stmt is None:
            continue

        vuln_info = _get_vuln_info(assess.vuln_id or "", vuln_cache)
        stmt["vulnerability"] = {
            "name": assess.vuln_id,
            "description": vuln_info["description"],
            "aliases": vuln_info["aliases"],
            "@id": vuln_info["url"],
        }

        products = []
        for pkg_str in assess.packages:
            if "@" in pkg_str:
                name, version = pkg_str.rsplit("@", 1)
            else:
                name, version = pkg_str, ""
            products.append({
                "@id": pkg_str,
                "identifiers": {
                    "cpe23": (
                        f"cpe:2.3:*:*:{name}:{version}"
                        ":*:*:*:*:*:*:*"
                    ),
                    "purl": f"pkg:generic/{name}@{version}",
                },
            })
        stmt["products"] = products
        stmt.setdefault("action_statement_timestamp", "")
        stmt["scanners"] = sorted({
            assess.source or "local_user_data",
            assess.origin or "local_user_data",
        })
        statements.append(stmt)

    # Deterministic ordering so the exported file is stable in git and
    # identical between developers regardless of import history: sort by the
    # assessment date first, then by vulnerability name and product ids as
    # stable tie-breakers.
    statements.sort(
        key=lambda s: (
            normalize_timestamp_for_sort(s.get("timestamp")),
            s.get("vulnerability", {}).get("name") or "",
            tuple(p.get("@id", "") for p in s.get("products", [])),
        )
    )

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": (
            "https://savoirfairelinux.com/sbom/openvex/"
            + str(_uuid.uuid4())
        ),
        "author": author,
        "timestamp": now_iso,
        "version": 1,
        "statements": statements,
    }


# ---------------------------------------------------------------------------
# Import helpers
# ---------------------------------------------------------------------------

def is_openvex_doc(doc: object) -> bool:
    """Return ``True`` if *doc* looks like a valid OpenVEX document."""
    if not isinstance(doc, dict):
        return False
    ctx = doc.get("@context", "")
    return "openvex" in str(ctx) and isinstance(doc.get("statements"), list)


def parse_imported_timestamp(raw_ts: object, use_original_timestamps: bool) -> "_dt | None":
    """Return the timestamp to persist for an imported assessment.

    Returns ``None`` when *use_original_timestamps* is false or when *raw_ts*
    is missing/unparseable, in which case the caller lets the model apply the
    current time.  Parsed values are always converted to UTC: SQLite drops the
    offset when storing, so a non-UTC timestamp would otherwise be read back as
    if its local wall-clock time had been UTC.
    """
    if not use_original_timestamps or not isinstance(raw_ts, str) or not raw_ts:
        return None
    try:
        parsed = _dt.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=_tz.utc)
    return parsed.astimezone(_tz.utc)


def duplicate_assessment_query(
    finding_id: "_uuid.UUID",
    variant_id: "_uuid.UUID | None",
    status: str,
    origin: str,
    timestamp: "_dt | None" = None,
) -> Any:
    """Build the SELECT used to detect an already-imported assessment.

    When *timestamp* is given (i.e. the caller preserves the timestamps stored
    in the file) it is part of the identity: an assessment recorded at another
    date is a distinct entry in the vulnerability's history and must be
    imported instead of being silently dropped as a duplicate.  Without it,
    re-importing the same file stays idempotent.
    """
    from ..extensions import db
    from ..models.assessment import Assessment as DBAssessment

    query = db.select(DBAssessment).where(
        DBAssessment.finding_id == finding_id,
        DBAssessment.variant_id == variant_id,
        DBAssessment.status == status,
        DBAssessment.origin == origin,
    )
    if timestamp is not None:
        query = query.where(DBAssessment.timestamp == timestamp)
    return query


def import_statements(
    statements: list[dict[str, Any]],
    variant_id: "_uuid.UUID",
    use_original_timestamps: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Persist a list of OpenVEX statement dicts as DB assessments.

    Parameters
    ----------
    statements:
        List of OpenVEX statement dicts (the ``"statements"`` array from an
        OpenVEX JSON document).
    variant_id:
        UUID of the target variant to attach the assessments to.
    use_original_timestamps:
        Preserve valid statement timestamps when true.  When false, newly
        created assessments use the database server's current time.

    Returns
    -------
    (created, errors, skipped)
        *created* — list of ``Assessment.to_dict()`` for newly created rows.
        *errors*  — list of error dicts ``{"vuln_id": ..., "error": ...}``.
        *skipped* — count of duplicate assessments that were not re-inserted.
    """
    from ..extensions import db
    from ..models.assessment import Assessment as DBAssessment, STATUS_TO_SIMPLIFIED
    from ..models.vulnerability import Vulnerability as DBVuln
    from ..models.package import Package
    from ..models.finding import Finding

    created: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped = 0

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        vuln_obj = stmt.get("vulnerability", {})
        vuln_name = (
            vuln_obj.get("name") if isinstance(vuln_obj, dict) else None
        )
        if not vuln_name:
            errors.append({
                "error": "Missing vulnerability name",
                "statement": str(stmt)[:200],
            })
            continue

        status = stmt.get("status")
        if not status:
            errors.append({"vuln_id": vuln_name, "error": "Missing status"})
            continue

        products = stmt.get("products", [])
        pkg_ids = []
        for prod in products:
            if isinstance(prod, dict) and "@id" in prod:
                pkg_ids.append(prod["@id"])
            elif isinstance(prod, str):
                pkg_ids.append(prod)
        if not pkg_ids:
            errors.append({
                "vuln_id": vuln_name,
                "error": "No products/packages found",
            })
            continue

        justification = stmt.get("justification", "")
        impact_statement = stmt.get("impact_statement", "")
        status_notes = stmt.get("status_notes", "")
        workaround = stmt.get("action_statement", "")

        # Preserve the original assessment date so exports remain ordered by
        # the date of the custom assessment and stay reproducible when two
        # developers import each other's assessments.
        imported_ts = parse_imported_timestamp(
            stmt.get("timestamp"), use_original_timestamps
        )

        for pkg_string_id in pkg_ids:
            try:
                if "@" in pkg_string_id:
                    name, version = pkg_string_id.rsplit("@", 1)
                else:
                    name, version = pkg_string_id, ""
                db_pkg = Package.find_or_create(name, version)
                DBVuln.get_or_create(vuln_name)
                finding = Finding.get_or_create(db_pkg.id, vuln_name)

                existing = db.session.execute(
                    duplicate_assessment_query(
                        finding_id=finding.id,
                        variant_id=variant_id,
                        status=status,
                        origin="custom",
                        timestamp=imported_ts,
                    )
                ).scalars().first()
                if existing is not None:
                    skipped += 1
                    continue

                db_a = DBAssessment.create(
                    status=status,
                    simplified_status=STATUS_TO_SIMPLIFIED.get(
                        status, "Pending Assessment"
                    ),
                    finding_id=finding.id,
                    variant_id=variant_id,
                    origin="custom",
                    status_notes=status_notes,
                    justification=justification,
                    impact_statement=impact_statement,
                    workaround=workaround,
                    responses=[],
                    timestamp=imported_ts,
                    commit=True,
                )
                created.append(db_a.to_dict())
            except Exception as e:
                errors.append({
                    "vuln_id": vuln_name,
                    "package": pkg_string_id,
                    "error": str(e),
                })

    return created, errors, skipped


def build_variant_by_name_map(project_id: "_uuid.UUID | None" = None) -> "dict[str, _Variant]":
    """Return a ``{name: Variant, sanitised_name: Variant}`` lookup.

    Parameters
    ----------
    project_id:
        When provided, only variants belonging to this project are included.
        When *None*, all variants across all projects are returned (legacy
        behaviour kept for the webapp route).
    """
    from ..models.variant import Variant as DBVariant

    variants = DBVariant.get_by_project(project_id) if project_id else DBVariant.get_all()
    variant_by_name: "dict[str, _Variant]" = {}
    for v in variants:
        sanitised = sanitize_variant_name(v.name)
        variant_by_name[sanitised] = v
        variant_by_name[v.name] = v
    return variant_by_name


# ---------------------------------------------------------------------------
# Custom-data export (assessments + CVSS + time estimates)
# ---------------------------------------------------------------------------

def build_custom_data_export(
    variant_ids: list[_uuid.UUID] | None = None,
) -> dict[str, Any]:
    """Build a custom-data export dict containing assessments, CVSS and time
    estimates for the given variant(s).

    Parameters
    ----------
    variant_ids:
        List of variant UUIDs to scope the export.  When *None* all
        handmade assessments across all variants are exported.

    Returns
    -------
    dict with keys ``version``, ``exported_at``, ``assessments``,
    ``ai_assessments``, ``cvss``, ``time_estimates``.
    """
    from ..extensions import db
    from ..models.assessment import Assessment as DBAssessment
    from ..models.metrics import Metrics
    from ..models.time_estimate import TimeEstimate
    from ..models.iso8601_duration import Iso8601Duration
    from ..models.variant import Variant as DBVariant

    handmade = DBAssessment.get_by_origin(variant_ids, origin="custom")
    pending_ai = DBAssessment.get_by_origin(variant_ids, origin="ai")

    variant_name_by_id: dict[str, str] = {}
    variant_uuid_set: set[_uuid.UUID] = {
        a.variant_id for a in [*handmade, *pending_ai]
        if a.variant_id is not None
    }

    def _export_assessments(
        assessments: "list[DBAssessment]",
    ) -> list[dict[str, Any]]:
        exported = []
        for assessment in assessments:
            assessment_dict = assessment.to_dict()
            exported.append({
                "vuln_id": assessment_dict["vuln_id"],
                "status": assessment_dict["status"],
                "simplified_status": assessment_dict.get("simplified_status", ""),
                "justification": assessment_dict.get("justification") or None,
                "impact_statement": assessment_dict.get("impact_statement") or None,
                "status_notes": assessment_dict.get("status_notes") or None,
                "workaround": assessment_dict.get("workaround") or None,
                "timestamp": assessment_dict["timestamp"],
                "packages": assessment_dict["packages"],
                "variant_id": assessment_dict.get("variant_id"),
            })
        return exported

    exported_assessments = _export_assessments(handmade)
    exported_ai_assessments = _export_assessments(pending_ai)

    # Gather ALL custom CVSS entries, not just those linked to handmade
    # assessments.
    cvss_entries: list[dict] = []
    metrics_query = db.select(Metrics).where(Metrics.origin == "custom")
    if variant_ids is not None:
        metrics_query = metrics_query.where(Metrics.variant_id.in_(variant_ids))
    all_metrics = list(db.session.execute(
        metrics_query.order_by(Metrics.vulnerability_id)
    ).scalars().all())
    for m in all_metrics:
        if m.variant_id is not None:
            variant_uuid_set.add(m.variant_id)
        cvss_entries.append({
            "vuln_id": m.vulnerability_id,
            "variant_id": str(m.variant_id) if m.variant_id is not None else None,
            "variant": None,
            "version": m.version or "",
            "vector_string": m.vector or "",
            "base_score": float(m.score) if m.score is not None else 0.0,
            "author": m.author,
            "origin": m.origin or "scanner",
        })

    # Gather ALL non-zero time estimates, not just those linked to
    # handmade assessments.
    time_estimates: list[dict] = []

    def _hours_to_iso(h: int) -> str:
        try:
            return str(Iso8601Duration(f"PT{h}H"))
        except (ValueError, TypeError):
            return f"PT{h}H"

    from ..models.finding import Finding as _Finding
    te_query = (
        db.select(
            _Finding.vulnerability_id,
            TimeEstimate.variant_id,
            TimeEstimate.optimistic,
            TimeEstimate.likely,
            TimeEstimate.pessimistic,
        )
        .join(_Finding, TimeEstimate.finding_id == _Finding.id)
        .where(
            db.or_(
                TimeEstimate.optimistic > 0,
                TimeEstimate.likely > 0,
                TimeEstimate.pessimistic > 0,
            )
        )
    )
    if variant_ids is not None:
        te_query = te_query.where(TimeEstimate.variant_id.in_(variant_ids))
    te_rows = db.session.execute(te_query).all()

    seen_vulns_te: set[tuple[str, str]] = set()
    for vid, te_variant_id, opt, lik, pes in te_rows:
        if te_variant_id is not None:
            variant_uuid_set.add(te_variant_id)
        variant_key = str(te_variant_id) if te_variant_id is not None else ""
        dedup_key = (vid, variant_key)
        if dedup_key in seen_vulns_te:
            continue
        seen_vulns_te.add(dedup_key)
        opt = opt or 0
        lik = lik or 0
        pes = pes or 0
        time_estimates.append({
            "vuln_id": vid,
            "variant_id": str(te_variant_id) if te_variant_id is not None else None,
            "variant": None,
            "optimistic": _hours_to_iso(opt),
            "likely": _hours_to_iso(lik),
            "pessimistic": _hours_to_iso(pes),
        })
    time_estimates.sort(key=lambda t: (t["vuln_id"], t.get("variant_id") or ""))

    if variant_uuid_set:
        variants = db.session.execute(
            db.select(DBVariant).where(DBVariant.id.in_(variant_uuid_set))
        ).scalars().all()
        variant_name_by_id = {str(v.id): v.name for v in variants}

    for item in exported_assessments:
        vid = item.get("variant_id")
        item["variant"] = variant_name_by_id.get(vid) if vid else None

    for item in exported_ai_assessments:
        vid = item.get("variant_id")
        item["variant"] = variant_name_by_id.get(vid) if vid else None

    for item in cvss_entries:
        vid = item.get("variant_id")
        item["variant"] = variant_name_by_id.get(vid) if vid else None

    for item in time_estimates:
        vid = item.get("variant_id")
        item["variant"] = variant_name_by_id.get(vid) if vid else None

    return {
        "version": 1,
        "exported_at": _dt.now(_tz.utc).isoformat(),
        "assessments": exported_assessments,
        "ai_assessments": exported_ai_assessments,
        "cvss": cvss_entries,
        "time_estimates": time_estimates,
    }


# ---------------------------------------------------------------------------
# Custom-data import (assessments + CVSS + time estimates)
# ---------------------------------------------------------------------------

def import_custom_data(
    data: dict[str, Any],
    variant_by_name: "dict[str, _Variant]",
    variant_id: "_uuid.UUID | None" = None,
    use_original_timestamps: bool = False,
) -> dict[str, Any]:
    """Import a custom-data JSON document containing assessments, CVSS and
    time estimates.

    Parameters
    ----------
    data:
        Parsed JSON matching the custom-data export format
        (``{version, assessments, ai_assessments, cvss, time_estimates}``).
    variant_by_name:
        Mapping ``{name: Variant, sanitised_name: Variant}`` for variant
        resolution.
    variant_id:
        When provided, all assessments are attached to this variant.
        When *None*, each assessment's ``variant_id`` field is used.
    use_original_timestamps:
        Preserve valid assessment timestamps when true.  When false, newly
        created assessments use the database server's current time.

    Returns
    -------
    dict with ``status``, assessment import counts for custom and AI rows,
    ``cvss_imported``, ``time_estimates_imported``, ``errors``.
    """
    from ..extensions import db
    from ..models.assessment import Assessment as DBAssessment, STATUS_TO_SIMPLIFIED
    from ..models.vulnerability import Vulnerability as DBVuln
    from ..models.package import Package
    from ..models.finding import Finding
    from ..models.scan import Scan
    from ..models.observation import Observation
    from .vuln_helpers import (
        validate_effort,
        validate_and_apply_cvss,
        apply_effort,
    )

    result: dict[str, Any] = {
        "status": "success",
        "assessments_imported": 0,
        "assessments_skipped": 0,
        "ai_assessments_imported": 0,
        "ai_assessments_skipped": 0,
        "cvss_imported": 0,
        "time_estimates_imported": 0,
        "errors": [],
    }

    def _variants_for_vuln_id(vuln_id: str) -> list[_uuid.UUID | None]:
        rows = db.session.execute(
            db.select(Scan.variant_id)
            .join(Observation, Observation.scan_id == Scan.id)
            .join(Finding, Observation.finding_id == Finding.id)
            .where(Finding.vulnerability_id == vuln_id)
            .distinct()
        ).all()
        return [variant_id for (variant_id,) in rows]

    def _resolve_variant(raw_item: dict) -> "_uuid.UUID | None":
        if variant_id is not None:
            return variant_id

        variant_token = raw_item.get("variant_id")
        if variant_token in (None, ""):
            variant_token = raw_item.get("variant")

        if variant_token in (None, ""):
            return None

        try:
            return _uuid.UUID(str(variant_token))
        except (ValueError, TypeError):
            mapped_variant = variant_by_name.get(str(variant_token))
            if mapped_variant is None:
                return None
            return mapped_variant.id

    def _import_assessments(
        key: str,
        origin: str,
        imported_key: str,
        skipped_key: str,
    ) -> None:
        assessment_list = data.get(key, [])
        if not isinstance(assessment_list, list):
            return
        for a in assessment_list:
            if not isinstance(a, dict):
                continue
            vuln_name = a.get("vuln_id")
            status = a.get("status")
            if not vuln_name or not status:
                result["errors"].append({
                    "vuln_id": vuln_name or "?",
                    "error": "Missing vuln_id or status",
                })
                continue
            pkg_ids = a.get("packages", [])
            if not pkg_ids:
                result["errors"].append({
                    "vuln_id": vuln_name,
                    "error": "No packages found",
                })
                continue

            # Determine which variant to attach to
            target_variant_id = _resolve_variant(a)

            justification = a.get("justification", "")
            impact_statement = a.get("impact_statement", "")
            status_notes = a.get("status_notes", "")
            workaround = a.get("workaround", "")
            imported_ts = parse_imported_timestamp(
                a.get("timestamp"), use_original_timestamps
            )

            for pkg_string_id in pkg_ids:
                try:
                    if "::" in pkg_string_id:
                        base, _supplier = pkg_string_id.split("::", 1)
                    else:
                        base, _supplier = pkg_string_id, ""
                    if "@" in base:
                        name, version = base.rsplit("@", 1)
                    else:
                        name, version = base, ""
                    db_pkg = Package.find_or_create(name, version, supplier=_supplier)
                    DBVuln.get_or_create(vuln_name)
                    finding = Finding.get_or_create(db_pkg.id, vuln_name)

                    existing = db.session.execute(
                        duplicate_assessment_query(
                            finding_id=finding.id,
                            variant_id=target_variant_id,
                            status=status,
                            origin=origin,
                            timestamp=imported_ts,
                        )
                    ).scalars().first()
                    if existing is not None:
                        result[skipped_key] += 1
                        continue

                    DBAssessment.create(
                        status=status,
                        simplified_status=STATUS_TO_SIMPLIFIED.get(
                            status, "Pending Assessment"
                        ),
                        finding_id=finding.id,
                        variant_id=target_variant_id,
                        origin=origin,
                        status_notes=status_notes,
                        justification=justification,
                        impact_statement=impact_statement,
                        workaround=workaround,
                        responses=[],
                        timestamp=imported_ts,
                        commit=True,
                    )
                    result[imported_key] += 1
                except Exception as e:
                    result["errors"].append({
                        "vuln_id": vuln_name,
                        "package": pkg_string_id,
                        "error": str(e),
                    })

    # Import pending AI assessments separately so the Review page continues to
    # surface them in its AI Assessments tab for approval or rejection.
    _import_assessments(
        "assessments", "custom", "assessments_imported", "assessments_skipped"
    )
    _import_assessments(
        "ai_assessments", "ai", "ai_assessments_imported", "ai_assessments_skipped"
    )

    # -- Import CVSS --
    cvss_list = data.get("cvss", [])
    if isinstance(cvss_list, list):
        for c in cvss_list:
            if not isinstance(c, dict):
                continue
            vuln_id = c.get("vuln_id")
            if not vuln_id:
                continue
            record = DBVuln.get_by_id(vuln_id)
            if not record:
                result["errors"].append({
                    "vuln_id": vuln_id,
                    "error": "Vulnerability not found (CVSS)",
                })
                continue
            cvss_data = {
                "base_score": c.get("base_score"),
                "vector_string": c.get("vector_string"),
                "version": c.get("version"),
                "author": c.get("author", "custom"),
                "origin": c.get("origin", "custom"),
                "exploitability_score": c.get("exploitability_score", 0.0),
                "impact_score": c.get("impact_score", 0.0),
            }
            cvss_variant_id = _resolve_variant(c)

            variant_token = c.get("variant_id")
            if variant_token in (None, ""):
                variant_token = c.get("variant")
            if cvss_variant_id is None and variant_token not in (None, ""):
                result["errors"].append({
                    "vuln_id": vuln_id,
                    "error": f"Variant '{variant_token}' not found",
                })
                continue

            target_variant_ids: list[_uuid.UUID | None]
            if cvss_variant_id is not None:
                target_variant_ids = [cvss_variant_id]
            else:
                target_variant_ids = _variants_for_vuln_id(vuln_id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            cvss_failed = False
            for target_variant_id in target_variant_ids:
                err = validate_and_apply_cvss(
                    cvss_data,
                    record.id,
                    target_variant_id,
                    log_prefix="import-custom-data",
                )
                if err:
                    result["errors"].append({"vuln_id": vuln_id, "error": err})
                    cvss_failed = True
                    break
            if not cvss_failed:
                result["cvss_imported"] += 1

    # -- Import time estimates --
    te_list = data.get("time_estimates", [])
    if isinstance(te_list, list):
        for t in te_list:
            if not isinstance(t, dict):
                continue
            vuln_id = t.get("vuln_id")
            if not vuln_id:
                continue
            record = DBVuln.get_by_id(vuln_id)
            if not record:
                result["errors"].append({
                    "vuln_id": vuln_id,
                    "error": "Vulnerability not found (time estimate)",
                })
                continue
            eff = {
                "optimistic": t.get("optimistic"),
                "likely": t.get("likely"),
                "pessimistic": t.get("pessimistic"),
            }
            effort, err = validate_effort(eff)
            if err:
                result["errors"].append({"vuln_id": vuln_id, "error": err})
                continue

            te_variant_id = _resolve_variant(t)

            variant_token = t.get("variant_id")
            if variant_token in (None, ""):
                variant_token = t.get("variant")
            if te_variant_id is None and variant_token not in (None, ""):
                result["errors"].append({
                    "vuln_id": vuln_id,
                    "error": f"Variant '{variant_token}' not found",
                })
                continue

            if te_variant_id is not None:
                target_variant_ids = [te_variant_id]
            else:
                target_variant_ids = _variants_for_vuln_id(vuln_id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            assert effort is not None
            for target_variant_id in target_variant_ids:
                apply_effort(record, target_variant_id, effort, log_prefix="import-custom-data")
            result["time_estimates_imported"] += 1

    if (
        not result["assessments_imported"]
        and not result["ai_assessments_imported"]
        and not result["cvss_imported"]
        and not result["time_estimates_imported"]
    ):
        if result["errors"]:
            result["status"] = "error"

    return result
