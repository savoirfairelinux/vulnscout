# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import datetime
import decimal
import dataclasses
import gzip
import json
import typing
import re
import urllib.error
import uuid

from flask import jsonify, request, Flask, current_app
from flask.typing import ResponseReturnValue
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload, attributes as orm_attrs
from ..models import (
    Vulnerability,
    CVSS,
    Finding,
    Observation,
    Scan,
    Variant,
    Metrics,
    SBOMDocument,
    SBOMObservation,
    Iso8601Duration
)
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.history_source import refresh_history
from ..helpers.refresh_runs import NO_PROVIDER_RECORD, UNSUPPORTED_CVE_IDENTIFIER, target_result, tracked_single_refresh
from ..extensions import db
from ..controllers.scc_engine import get_cve_json
from ..controllers.nvd_db import NVD_DB, parse_nvd_lookup
from ..controllers.nvd_extract import extract_cve_details
from ..controllers.nvd_apply import apply_cvss_update, apply_nvd_update
from ..controllers.epss_db import EPSS_DB
from ..controllers.euvd_db import EUVD_DB
from ..controllers.refresh_jobs import CVE_RE, _apply_euvd
from ..controllers.vulnerabilities import VulnerabilitiesController
from ..controllers.conditions_parser import ConditionParser
from ..helpers.vuln_helpers import (
    validate_effort,
    validate_and_apply_cvss,
    apply_effort,
    estimate_has_variant_observation,
    Effort
)
from ._scan_helpers import parse_uuid_or_400
from ._scan_queries import VulnerabilityText, fetch_vulnerabilities_texts
from ._evidence_scope import EvidenceScope, VulnerabilityEvidence, resolve_evidence_scope, vulnerability_evidence

TIME_ESTIMATES_PATH = "/scan/outputs/time_estimates.json"
MATCH_CONDITION_MAX_LENGTH = 1_000
MATCH_CONDITION_MAX_ITEMS = 50_000
_GHSA_RE = re.compile(r'^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')


def _attack_vector_from_vector(vector: str) -> str | None:
    """Return the normalized CVSS attack vector used by Explorer filters."""
    for token, label in (
        ("AV:N", "NETWORK"),
        ("AV:A", "ADJACENT"),
        ("AV:L", "LOCAL"),
        ("AV:P", "PHYSICAL"),
    ):
        if token in vector:
            return label
    return None


# Formats that are exclusively vulnerability scanners (never pure package BOMs)
# Mapping from SBOMDocument.format to the found_by string exposed by the API
_FORMAT_TO_FOUND_BY: dict[str, str] = {
    "grype": "grype",
    "yocto_cve_check": "yocto_cve_check",
    "spdx": "spdx3",
    "cdx": "cyclonedx",
    "openvex": "openvex",
    "yocto_vex": "yocto_vex",
}

# Mapping from Scan.scan_source to the found_by string for tool scans
_TOOL_SOURCE_TO_FOUND_BY: dict[str, str] = {
    "nvd": "nvd_cpe",
    "osv": "osv",
}


def effort_to_dict(effort: Effort) -> dict[typing.Literal["optimistic", "likely", "pessimistic"], str | None]:
    def format_hours(hours: int | None) -> str | None:
        return str(Iso8601Duration(f"PT{hours}H")) if hours is not None else None

    return {
        "optimistic": format_hours(effort.optimistic),
        "likely": format_hours(effort.likely),
        "pessimistic": format_hours(effort.pessimistic),
    }


@dataclasses.dataclass
class _ScopedOverrides:
    cvss: list[Metrics]
    effort: Effort
    severity_label: str | None = None


def _apply_scoped_cvss_to_vuln_dict(
    vuln: dict, metrics: typing.Sequence[Metrics], severity_label: str | None
) -> None:
    """Apply CVSS records and aggregate severity values from one metric scope."""
    vuln["severity"] = CVSS.summarize(
        [metric.to_dict() for metric in metrics], severity_label or "unknown"
    )


def _variant_scoped_metrics_and_effort_overrides(
    records: list[Vulnerability], variant_uuid: uuid.UUID
) -> dict[str, _ScopedOverrides]:
    """Build response-level overrides for one variant's metrics/effort."""
    return _scoped_metrics_and_effort_overrides(records, [variant_uuid])


def _scoped_metrics_and_effort_overrides(
    records: list[Vulnerability], variant_ids: list[uuid.UUID]
) -> dict[str, _ScopedOverrides]:
    """Select scope-owned metrics/effort, retaining global scanner fallbacks."""
    if not records:
        return {}

    vuln_ids = [r.id for r in records]

    metric_rows = db.session.execute(
        db.select(Metrics).where(
            Metrics.vulnerability_id.in_(vuln_ids),
            db.or_(Metrics.variant_id.in_(variant_ids), Metrics.variant_id.is_(None)),
        )
    ).scalars().all()

    metrics_by_vuln: dict[str, dict[str, list]] = {}
    for m in metric_rows:
        bucket = metrics_by_vuln.setdefault(m.vulnerability_id, {"scoped": [], "fallback": []})
        if m.variant_id is not None:
            bucket["scoped"].append(m)
        else:
            bucket["fallback"].append(m)

    from ..models.time_estimate import TimeEstimate

    raw_te_rows = db.session.execute(
        db.select(
            Finding.vulnerability_id,
            TimeEstimate.variant_id,
            TimeEstimate.optimistic,
            TimeEstimate.likely,
            TimeEstimate.pessimistic,
        )
        .join(Finding, TimeEstimate.finding_id == Finding.id)
        .where(
            Finding.vulnerability_id.in_(vuln_ids),
            db.or_(TimeEstimate.variant_id.in_(variant_ids), TimeEstimate.variant_id.is_(None)),
        )
        .order_by(estimate_has_variant_observation().desc(), TimeEstimate.id)
    ).all()

    effort_by_vuln: dict[str, Effort] = {}
    fallback_effort_by_vuln: dict[str, Effort] = {}
    for vuln_id, te_variant_id, opti, like, pess in raw_te_rows:
        packed = Effort(opti, like, pess)
        if te_variant_id is not None and vuln_id not in effort_by_vuln:
            effort_by_vuln[vuln_id] = packed
        elif te_variant_id is None and vuln_id not in fallback_effort_by_vuln:
            fallback_effort_by_vuln[vuln_id] = packed

    overrides: dict[str, _ScopedOverrides] = {}
    for r in records:
        metric_bucket = metrics_by_vuln.get(r.id, {"scoped": [], "fallback": []})
        # CVSS is a union: global (scanner, variant_id IS NULL) scores are
        # standard data shown for every variant, plus this variant's own
        # custom scores. Custom scores add to — they don't hide — scanner data.
        selected_metrics = metric_bucket["fallback"] + metric_bucket["scoped"]

        # Effort is a single value per vuln: a variant-scoped estimate overrides
        # the global one, falling back to global when none is set.
        chosen_effort = effort_by_vuln.get(r.id) or fallback_effort_by_vuln.get(r.id)
        overrides[str(r.id)] = _ScopedOverrides(
            selected_metrics,
            chosen_effort or Effort(None, None, None),
            r.status,
        )

    return overrides


def _apply_variant_scoped_overrides_to_vuln_dicts(
    vulns: dict[str, dict], overrides: dict[str, _ScopedOverrides]
) -> None:
    """Apply variant-scoped metrics/effort overrides to serialized vulnerability dicts."""
    if not vulns or not overrides:
        return

    for vuln_id, vuln in vulns.items():
        scoped = overrides.get(str(vuln_id))
        if scoped is None:
            continue
        _apply_scoped_cvss_to_vuln_dict(vuln, scoped.cvss, scoped.severity_label)
        vuln["effort"] = effort_to_dict(scoped.effort)


def _variant_ids_for_vulnerability(vulnerability_id: str) -> list[uuid.UUID | None]:
    """Return distinct variant IDs where a vulnerability is observed."""
    rows = db.session.execute(
        db.select(Scan.variant_id)
        .join(Observation, Observation.scan_id == Scan.id)
        .join(Finding, Observation.finding_id == Finding.id)
        .where(Finding.vulnerability_id == vulnerability_id)
        .distinct()
    ).all()
    return [variant_id for (variant_id,) in rows]


def _populate_found_by(
    records: list[Vulnerability],
    active_scan_ids: list[uuid.UUID] | None = None,
    scans_by_vulnerability: dict[str, set[uuid.UUID]] | None = None,
) -> None:
    """Populate transient found_by with factual provenance.

    Attribution strategy:
      1) Exact per-file provenance from SBOMObservation -> SBOMDocument.format
      2) Fallback for vulns without an observation-backed format: derive from
         observing scans/documents in scope, without preference heuristics.
    """
    if not records:
        return

    vuln_ids = [r.id for r in records]

    found_by_map: dict[str, set[str]] = {}

    # 1) Exact provenance from existing SBOMObservations.
    provenance_q = (
        db.select(SBOMObservation.vulnerability_id, SBOMDocument.format)
        .join(SBOMDocument, SBOMObservation.sbom_document_id == SBOMDocument.id)
        .where(SBOMObservation.vulnerability_id.in_(vuln_ids))
        .where(SBOMDocument.format.isnot(None))
    )
    if active_scan_ids is not None:
        provenance_q = provenance_q.where(SBOMDocument.scan_id.in_(active_scan_ids))
    if scans_by_vulnerability is not None:
        provenance_q = provenance_q.add_columns(SBOMDocument.scan_id)
    provenance_rows = db.session.execute(provenance_q.distinct()).all()

    for vuln_id, doc_format, *scans in provenance_rows:
        if scans_by_vulnerability is not None and scans[0] not in scans_by_vulnerability.get(vuln_id, ()):
            continue
        if not isinstance(doc_format, str):
            continue
        mapped = _FORMAT_TO_FOUND_BY.get(doc_format, doc_format)
        found_by_map.setdefault(vuln_id, set()).add(mapped)

    unresolved_vuln_ids = [vid for vid in vuln_ids if vid not in found_by_map]

    # 2) Fallback: derive from observing scans/documents in scope. Fetch the
    # observation-to-scan rows separately from document metadata: joining
    # every finding observation to every document in its scan creates a very
    # large intermediate result on scans with many findings and documents.
    if unresolved_vuln_ids:
        fallback_q = (
            db.select(
                Finding.vulnerability_id,
                Scan.id.label("scan_id"),
                Scan.scan_source,
            )
            .select_from(Finding)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(Finding.vulnerability_id.in_(unresolved_vuln_ids))
        )
        if active_scan_ids is not None:
            fallback_q = fallback_q.where(Observation.scan_id.in_(active_scan_ids))
        fallback_rows = db.session.execute(fallback_q.distinct()).all()
        if scans_by_vulnerability is not None:
            fallback_rows = [row for row in fallback_rows if row.scan_id in scans_by_vulnerability.get(row[0], ())]

        fallback_scan_ids = {scan_id for _, scan_id, _ in fallback_rows}
        formats_by_scan: dict[uuid.UUID, set[str]] = {}
        if fallback_scan_ids:
            format_rows = db.session.execute(
                db.select(SBOMDocument.scan_id, SBOMDocument.format)
                .where(
                    SBOMDocument.scan_id.in_(fallback_scan_ids),
                    SBOMDocument.format.isnot(None),
                )
                .distinct()
            ).all()
            for scan_id, doc_format in format_rows:
                if isinstance(doc_format, str):
                    formats_by_scan.setdefault(scan_id, set()).add(doc_format)

        for vuln_id, scan_id, scan_source in fallback_rows:
            doc_formats = formats_by_scan.get(scan_id, set())
            if doc_formats:
                for doc_format in doc_formats:
                    mapped = _FORMAT_TO_FOUND_BY.get(doc_format, doc_format)
                    found_by_map.setdefault(vuln_id, set()).add(mapped)
            elif isinstance(scan_source, str):
                mapped = _TOOL_SOURCE_TO_FOUND_BY.get(scan_source, scan_source)
                found_by_map.setdefault(vuln_id, set()).add(mapped)

    for record in records:
        for scanner in found_by_map.get(record.id, set()):
            record.add_found_by(scanner)


def _serialize_evidence(
    records: list[Vulnerability], scope: EvidenceScope, evidence: VulnerabilityEvidence, *, include_texts: bool,
) -> dict[str, dict]:
    if not records:
        return {}
    overrides = _scoped_metrics_and_effort_overrides(records, scope.override_variants)
    member_records = [record for record in records if record.id in evidence.ids]
    _populate_found_by(
        member_records, active_scan_ids=evidence.scan_ids, scans_by_vulnerability=evidence.scans_by_vulnerability,
    )
    payload = {}
    for record in records:
        vuln_id = record.id
        visible = evidence.visible.display.get(vuln_id, {})
        current = evidence.current.display.get(vuln_id, {})
        writable = evidence.current.writable.get(vuln_id, {})
        members = evidence.variants.get(vuln_id, set())
        # All inventory and overrides are already loaded in bulk, including the empty cases.
        orm_attrs.set_committed_value(record, "findings", [])
        orm_attrs.set_committed_value(record, "metrics", [])
        vuln = record.to_dict()
        vuln.update({
            "packages": sorted(set().union(*visible.values())),
            "packages_current": sorted(set().union(*current.values())),
            "packages_current_by_variant": {vid: sorted(packages) for vid, packages in current.items()},
            "assessment_targets_by_variant": {vid: sorted(packages) for vid, packages in writable.items()},
            "variants": sorted({scope.variants[vid] for vid in members}),
            "effort_variant_ids": [
                str(vid) for vid in scope.override_variants if vid in evidence.finding_variants.get(vuln_id, ())
            ],
        })
        if scope.historical:
            vuln["packages_status_by_variant"] = {vid: sorted(packages) for vid, packages in visible.items()}
        payload[vuln_id] = vuln
    _apply_variant_scoped_overrides_to_vuln_dicts(payload, overrides)

    if evidence.ids:
        first_observed = db.session.execute(
            db.select(Finding.vulnerability_id, func.min(Scan.timestamp))
            .join(Observation, Finding.id == Observation.finding_id)
            .join(Scan, Observation.scan_id == Scan.id)
            .where(Finding.vulnerability_id.in_(evidence.ids), Scan.id.in_(scope.scans(scope.all_by_variant)))
            .group_by(Finding.vulnerability_id)
        )
        for vuln_id, timestamp in first_observed:
            payload[vuln_id]["first_scan_date"] = ensure_utc_iso(timestamp)

    if include_texts:
        for ids, scans in ((evidence.ids, evidence.scan_ids), (payload.keys() - evidence.ids, [])):
            if ids:
                texts = fetch_vulnerabilities_texts(
                    ids, include_packages=True, scan_ids=scans, scans_by_vulnerability=evidence.scans_by_vulnerability,
                )
                for vuln_id, entries in texts.items():
                    payload[vuln_id]["texts"] = [entry.to_dict() for entry in entries]
    return payload


def _compact_json_response(payload_obj: typing.Any) -> ResponseReturnValue:
    """Serialise a large list response without Flask's JSON provider.

    Going through the provider would pretty-print the payload when the app runs
    in debug mode and would route encoding through the pure-Python encoder;
    ``json.dumps`` without a ``default`` hook keeps the C implementation.
    """
    payload = json.dumps(payload_obj, separators=(",", ":")).encode()
    response = current_app.response_class(payload, mimetype="application/json")
    if request.accept_encodings["gzip"] > 0 and len(payload) > 1024:
        response.set_data(gzip.compress(payload, compresslevel=1))
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Vary"] = "Accept-Encoding"
    return response


def _apply_individual_refresh_scope(data: dict, record: Vulnerability, scope: dict) -> None:
    """Remove out-of-scope inventory and overrides from a provider response."""
    selection, _ = resolve_evidence_scope(scope, historical=False)
    if selection is None:
        raise ValueError("Invalid refresh evidence scope")
    evidence = vulnerability_evidence(selection, [record.id])
    data["packages"] = sorted(set().union(*evidence.visible.display.get(record.id, {}).values()))
    overrides = _scoped_metrics_and_effort_overrides([record], selection.override_variants)
    _apply_variant_scoped_overrides_to_vuln_dicts({record.id: data}, overrides)
    texts = fetch_vulnerabilities_texts(
        [record.id], scan_ids=evidence.scan_ids, include_packages=True,
        scans_by_vulnerability=evidence.scans_by_vulnerability,
    )
    data["texts"] = [text.to_dict() for text in texts[record.id]]
    record.found_by = []
    if record.id in evidence.ids:
        _populate_found_by(
            [record], active_scan_ids=evidence.scan_ids, scans_by_vulnerability=evidence.scans_by_vulnerability,
        )
    data["found_by"] = list(record.found_by)


def init_app(app: Flask) -> None:

    if "TIME_ESTIMATES_PATH" not in app.config:
        app.config["TIME_ESTIMATES_PATH"] = TIME_ESTIMATES_PATH

    @app.post('/api/vulnerabilities/match-condition')
    def match_condition() -> ResponseReturnValue:
        """Evaluate a condition against supplied data objects.

        OpenAPI:
        body MatchConditionRequest required Condition string and items containing id and data fields.
        response 200 MatchConditionResult IDs of items matching the condition.
        response 400 Error Invalid request or condition.
        """
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "Request body must be a JSON object"}, 400

        condition = payload.get("condition")
        items = payload.get("items")
        if not isinstance(condition, str) or not condition.strip():
            return {"error": "condition must be a non-empty string"}, 400
        if len(condition) > MATCH_CONDITION_MAX_LENGTH:
            return {"error": f"condition must be at most {MATCH_CONDITION_MAX_LENGTH} characters"}, 400
        if not isinstance(items, list):
            return {"error": "items must be a list"}, 400
        if len(items) > MATCH_CONDITION_MAX_ITEMS:
            return {"error": f"items must contain at most {MATCH_CONDITION_MAX_ITEMS} entries"}, 400

        parser = ConditionParser()
        matching_ids: list[str] = []
        try:
            for item in items:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("id"), str)
                    or not isinstance(item.get("data"), dict)
                ):
                    return {"error": "Each item must contain a string id and an object data field"}, 400
                if parser.evaluate(condition, item["data"]):
                    matching_ids.append(item["id"])
        except Exception as exc:
            return {"error": f"Invalid match condition: {exc}"}, 400

        return jsonify({"matching_ids": matching_ids})

    @app.route('/api/vulnerabilities')
    def index_vulns() -> ResponseReturnValue:
        """List vulnerabilities with optional variant and project filters.

        Supports single-variant, project-wide, pairwise comparison, and
        multi-variant union or intersection modes.

        OpenAPI:
        query variant_id uuid optional Restrict to a single variant.
        query project_id uuid optional Restrict to a single project.
        query compare_variant_id uuid optional Compare against a second variant.
        query variant_ids string optional Comma-separated list of variant IDs.
        query operation string optional Comparison mode such as difference, intersection, or union.
        query include_outdated boolean optional Include vulnerabilities and status targets from superseded SBOMs.
        query format string optional Response format such as list or dict.
        response 200 VulnerabilityCollection Vulnerability collection; list/compact arrays or a map with format=dict.
        response 400 Error Invalid query or variants outside the selected project.
        response 404 Error A comparison variant does not exist.
        """
        response_format = request.args.get('format', 'list')
        scope, err = resolve_evidence_scope(request.args)
        if scope is None:
            return err if err is not None else ({"error": "Internal error"}, 500)
        evidence = vulnerability_evidence(scope)
        records = list(db.session.scalars(
            select(Vulnerability).options(joinedload(Vulnerability.refresh))
            .where(Vulnerability.id.in_(evidence.ids)).order_by(Vulnerability.id)
        )) if evidence.ids else []
        vulns = _serialize_evidence(records, scope, evidence, include_texts=response_format != "compact")
        for vuln in vulns.values():
            vuln.pop("description", None)

        match response_format:
            case "list":
                return list(vulns.values())
            case "compact":
                for vuln in vulns.values():
                    vuln.pop("texts", None)
                    vuln.pop("urls", None)
                    vuln.pop("cpes", None)
                    vuln["details_loaded"] = False
                    cvss_entries = vuln.get("severity", {}).get("cvss", [])
                    vuln["severity"]["cvss"] = [
                        {
                            "version": cvss.get("version", ""),
                            "base_score": cvss.get("base_score", 0.0),
                            "attack_vector": _attack_vector_from_vector(
                                cvss.get("vector_string", "")
                            ),
                        }
                        for cvss in cvss_entries
                    ]
                return _compact_json_response(list(vulns.values()))
            case "dict":
                return vulns
            case _ as fmt:
                raise ValueError("Unknown format", fmt)

    @app.post('/api/vulnerabilities/search-descriptions')
    def search_vulnerability_descriptions() -> ResponseReturnValue:
        """Return vulnerability IDs whose scoped descriptions contain each term.

        OpenAPI:
        query variant_id uuid optional Restrict descriptions to a variant's scans.
        query project_id uuid optional Restrict descriptions to a project's scans.
        query compare_variant_id uuid optional Select the second variant in a comparison.
        query variant_ids string optional Comma-separated variants in a comparison.
        query operation string optional Select the comparison operation.
        query include_outdated boolean optional Search descriptions from superseded SBOMs too.
        body DescriptionSearchRequest required Vulnerability ID and search-term arrays.
        response 200 DescriptionSearchResult Matching vulnerability IDs grouped by normalized term.
        response 400 Error Invalid input, size limits, or variants outside the selected project.
        response 404 Error A comparison variant does not exist.
        """
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "Expected a JSON object"}, 400

        raw_vuln_ids = payload.get("vulnerability_ids")
        raw_terms = payload.get("terms")
        if not isinstance(raw_vuln_ids, list) or not all(
            isinstance(vuln_id, str) for vuln_id in raw_vuln_ids
        ):
            return {"error": "vulnerability_ids must be a list of strings"}, 400
        if not isinstance(raw_terms, list) or not all(
            isinstance(term, str) for term in raw_terms
        ):
            return {"error": "terms must be a list of strings"}, 400
        if len(raw_vuln_ids) > 100_000:
            return {"error": "Too many vulnerability IDs"}, 400
        if len(raw_terms) > 50 or any(len(term) > 256 for term in raw_terms):
            return {"error": "Too many or excessively long search terms"}, 400

        vuln_ids = list(dict.fromkeys(raw_vuln_ids))
        terms = list(dict.fromkeys(term.casefold() for term in raw_terms if term))
        matches: dict[str, set[str]] = {term: set() for term in terms}
        if not vuln_ids or not terms:
            return {"matches": {term: [] for term in terms}}

        scope, err = resolve_evidence_scope(request.args)
        if scope is None:
            return err if err is not None else ({"error": "Internal error"}, 500)
        evidence = vulnerability_evidence(scope, vuln_ids)
        vuln_ids = sorted(evidence.ids)
        scan_ids = evidence.scan_ids

        description_rows = db.session.execute(
            db.select(Vulnerability.id, Vulnerability.description)
            .where(Vulnerability.id.in_(vuln_ids))
            .where(Vulnerability.description.is_not(None))
        ).all()

        observation_query = (
            db.select(SBOMObservation.vulnerability_id, SBOMObservation.description, SBOMDocument.scan_id)
            .join(SBOMDocument, SBOMObservation.sbom_document_id == SBOMDocument.id)
            .where(SBOMObservation.vulnerability_id.in_(vuln_ids))
            .where(SBOMDocument.scan_id.in_(scan_ids))
        )
        observation_rows = [
            (vuln_id, description)
            for vuln_id, description, scan_id in db.session.execute(observation_query)
            if scan_id in evidence.scans_by_vulnerability[vuln_id]
        ]

        for vuln_id, content in (*description_rows, *observation_rows):
            if not isinstance(content, str):
                continue
            folded_content = content.casefold()
            for term in terms:
                if term in folded_content:
                    matches[term].add(str(vuln_id))

        return {
            "matches": {
                term: sorted(matched_ids)
                for term, matched_ids in matches.items()
            }
        }

    @app.get('/api/vulnerabilities/<id>')
    def get_vuln(id: str) -> ResponseReturnValue:
        """Return a single vulnerability.

        OpenAPI:
        query variant_id uuid optional Apply variant-scoped CVSS and effort overrides.
        query project_id uuid optional Scope vulnerability texts to one project when variant_id is absent.
        query compare_variant_id uuid optional Select the second variant in a comparison.
        query variant_ids string optional Comma-separated variants in a comparison.
        query operation string optional Select the comparison operation.
        query include_outdated boolean optional Use the historical list's scope for SBOM texts and packages.
        query agent_scoped string optional When '1', require one variant_id and return only its exact current targets.
        response 200 Vulnerability Vulnerability payload.
        response 400 Error Invalid evidence scope.
        response 404 Error Vulnerability not found.
        response 404 html Missing vulnerability record.
        """
        agent_scoped = request.args.get("agent_scoped") == "1"
        if agent_scoped and (
            not request.args.get("variant_id")
            or any(param in request.args for param in ("compare_variant_id", "variant_ids", "operation"))
        ):
            return {"error": "Agent-scoped detail requires a single variant_id without comparison arguments."}, 400

        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        scope, err = resolve_evidence_scope(request.args, historical=False if agent_scoped else None)
        if scope is None:
            return err if err is not None else ({"error": "Internal error"}, 500)
        evidence = vulnerability_evidence(scope, [id])
        response = _serialize_evidence([record], scope, evidence, include_texts=True)[id]
        if agent_scoped:
            variant_key = str(scope.selected[0]) if scope.selected else ""
            packages = response["assessment_targets_by_variant"].get(variant_key)
            if not packages:
                return {"error": "Vulnerability is outside the current variant scope."}, 404
            exact_targets = {variant_key: packages}
            response["packages"] = response["packages_current"] = packages
            response["packages_current_by_variant"] = exact_targets
            response["assessment_targets_by_variant"] = exact_targets
        return response

    @app.get('/api/vulnerabilities/<id>/variant-snapshots')
    def get_vuln_variant_snapshots(id: str) -> ResponseReturnValue:
        """Return variant-scoped effort and custom CVSS for every variant that
        observes this vulnerability, in a single response.

        Replaces the previous per-variant N+1 fetch performed by the modal.

        OpenAPI:
        query project_id uuid optional Restrict snapshots to variants from one project.
        response 200 VariantSnapshots Variant-scoped vulnerability snapshots.
        response 404 html Vulnerability not found.
        """
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        variant_uuids = _variant_ids_for_vulnerability(record.id)

        project_id = request.args.get("project_id")
        if project_id:
            project_uuid, err = parse_uuid_or_400(project_id, "project_id")
            if err:
                return err
            allowed = set(db.session.execute(
                db.select(Variant.id).where(Variant.project_id == project_uuid)
            ).scalars().all())
            variant_uuids = [v for v in variant_uuids if v in allowed]

        snapshots: list[dict] = []
        for variant_uuid in variant_uuids:
            if variant_uuid is None:
                continue
            overrides = _variant_scoped_metrics_and_effort_overrides([record], variant_uuid)
            scoped = overrides.get(str(record.id))
            if scoped is None:
                continue
            custom_cvss = [
                m.to_dict() for m in scoped.cvss
                if (m.origin or "scanner") == "custom"
            ]
            snapshots.append({
                "variant_id": str(variant_uuid),
                "effort": effort_to_dict(scoped.effort),
                "custom_cvss": custom_cvss,
            })

        return jsonify(snapshots)

    @app.patch('/api/vulnerabilities/<id>')
    def patch_vuln(id: str) -> ResponseReturnValue:
        """Update variant-scoped effort or custom CVSS data for a vulnerability.

        OpenAPI:
        body VulnerabilityUpdate required Variant-scoped effort or custom CVSS update.
        response 200 Vulnerability Updated vulnerability payload.
        response 400 Error Invalid update payload.
        response 404 html Vulnerability not found.
        """
        record = Vulnerability.get_by_id(id)
        if not record:
            return "Not found", 404

        payload_data = request.get_json()
        if payload_data is None:
            return {"error": "Invalid request data"}, 400
        response_variant_id: uuid.UUID | None = None
        _updated_effort: Effort | None = None

        if "effort" in payload_data:
            eff = payload_data["effort"]
            _updated_effort, err = validate_effort(eff)
            if err:
                return err, 400
            if _updated_effort is None:
                return {"error": "Internal error"}, 500

            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_uuid, uuid_err = parse_uuid_or_400(variant_id, "variant_id")
                if uuid_err:
                    return uuid_err
                if variant_uuid is None:
                    return {"error": "Internal error"}, 500
                target_variant_ids: list[uuid.UUID | None] = [variant_uuid]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            effort_error = apply_effort(
                record, target_variant_ids, _updated_effort, log_prefix=f"PATCH /api/vulnerabilities/{record.id}",
            )
            if effort_error:
                return {"error": effort_error}, 400

            if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                response_variant_id = target_variant_ids[0]

        if "cvss" in payload_data:
            variant_id = payload_data.get("variant_id")
            if variant_id is not None:
                variant_uuid, uuid_err = parse_uuid_or_400(variant_id, "variant_id")
                if uuid_err:
                    return uuid_err
                if variant_uuid is None:
                    return {"error": "Internal error"}, 500
                target_variant_ids = [variant_uuid]
            else:
                target_variant_ids = _variant_ids_for_vulnerability(record.id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            if isinstance(payload_data["cvss"], dict):
                payload_data["cvss"].setdefault("origin", "custom")

            for target_variant_id in target_variant_ids:
                cvss_err = validate_and_apply_cvss(
                    payload_data["cvss"], record.id, target_variant_id,
                    log_prefix=f"PATCH /api/vulnerabilities/{record.id}")
                if cvss_err:
                    return cvss_err, 400

            if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                response_variant_id = target_variant_ids[0]
            db.session.expire(record, ['metrics'])

        response = record.to_dict()
        if response_variant_id is not None:
            overrides = _variant_scoped_metrics_and_effort_overrides([record], response_variant_id)
            _apply_variant_scoped_overrides_to_vuln_dicts({response["id"]: response}, overrides)
        if _updated_effort is not None and response_variant_id is None:
            response["effort"] = effort_to_dict(_updated_effort)
        return response

    @app.route('/api/vulnerabilities/batch', methods=['PATCH'])
    def update_vulns_batch() -> ResponseReturnValue:
        """Update multiple vulnerabilities in a single request.

        OpenAPI:
        body VulnerabilityBatchUpdate required Batch vulnerability updates.
        response 200 VulnerabilityBatchResult Batch update summary.
        response 400 Error Invalid batch payload.
        """
        payload_data = request.get_json()
        if (not payload_data
                or "vulnerabilities" not in payload_data
                or not isinstance(payload_data["vulnerabilities"], list)):
            return {"error": "Invalid request data. Expected: {vulnerabilities: [...]}"}, 400

        results: list[dict] = []
        errors: list[dict] = []

        for item in payload_data["vulnerabilities"]:
            if not isinstance(item, dict) or "id" not in item:
                errors.append({"error": "Invalid vulnerability data", "item": item})
                continue

            record = Vulnerability.get_by_id(item["id"])
            if not record:
                errors.append({"id": item["id"], "error": "Vulnerability not found"})
                continue

            response_variant_id: uuid.UUID | None = None
            _updated_effort: Effort | None = None

            if "effort" in item:
                eff = item["effort"]
                _updated_effort, err = validate_effort(eff)
                if err:
                    errors.append({"id": item["id"], "error": err})
                    continue
                if _updated_effort is None:
                    errors.append({"id": item["id"], "error": "Internal error"})
                    continue
                item_variant_id = item.get("variant_id")
                if item_variant_id is not None:
                    item_variant_uuid, uuid_err = parse_uuid_or_400(item_variant_id, "variant_id")
                    if uuid_err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    if item_variant_uuid is None:
                        errors.append({"id": item["id"], "error": "Internal error"})
                        continue
                    target_variant_ids: list[uuid.UUID | None] = [item_variant_uuid]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                effort_error = apply_effort(
                    record, target_variant_ids, _updated_effort,
                    log_prefix=f"PATCH /api/vulnerabilities/batch {item['id']!r}",
                    require_observation=True,
                )
                if effort_error:
                    errors.append({"id": item["id"], "error": effort_error})
                    continue

                if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                    response_variant_id = target_variant_ids[0]

            if "cvss" in item:
                cvss_variant_id = item.get("variant_id")
                if cvss_variant_id is not None:
                    cvss_variant_uuid, uuid_err = parse_uuid_or_400(cvss_variant_id, "variant_id")
                    if uuid_err:
                        errors.append({"id": item["id"], "error": "Invalid variant_id"})
                        continue
                    if cvss_variant_uuid is None:
                        errors.append({"id": item["id"], "error": "Internal error"})
                        continue
                    target_variant_ids = [cvss_variant_uuid]
                else:
                    target_variant_ids = _variant_ids_for_vulnerability(record.id)
                    if not target_variant_ids:
                        target_variant_ids = [None]

                if isinstance(item["cvss"], dict):
                    item["cvss"].setdefault("origin", "custom")

                cvss_failed = False
                for target_variant_id in target_variant_ids:
                    cvss_err = validate_and_apply_cvss(
                        item["cvss"], record.id, target_variant_id,
                        log_prefix=f"PATCH /api/vulnerabilities/batch {item['id']!r}")
                    if cvss_err:
                        errors.append({"id": item["id"], "error": cvss_err})
                        cvss_failed = True
                        break

                if cvss_failed:
                    continue

                if len(target_variant_ids) == 1 and target_variant_ids[0] is not None:
                    response_variant_id = target_variant_ids[0]
                db.session.expire(record, ['metrics'])

            result_dict = record.to_dict()
            if response_variant_id is not None:
                overrides = _variant_scoped_metrics_and_effort_overrides([record], response_variant_id)
                _apply_variant_scoped_overrides_to_vuln_dicts({result_dict["id"]: result_dict}, overrides)
            if _updated_effort is not None and response_variant_id is None:
                result_dict["effort"] = effort_to_dict(_updated_effort)
            results.append(result_dict)

        response = {
            "status": "success" if results else "error",
            "vulnerabilities": results,
            "count": len(results)
        }
        if errors:
            response["errors"] = errors
            response["error_count"] = len(errors)
        return response, 200 if results else 400

    def _unreturned_refresh(source: str, identifier: str, status: str) -> ResponseReturnValue:
        target_result(source, identifier, status, UNSUPPORTED_CVE_IDENTIFIER if status == "skipped" else None)
        return jsonify({"vulnerabilities": [], "outcome": status}), 200

    @app.route('/api/vulnerabilities/<cve_id>/nvd-refresh', methods=['POST'])
    @tracked_single_refresh("nvd")
    @refresh_history("nvd")
    def refresh_single_cve(cve_id: str) -> ResponseReturnValue:
        """Refresh NVD data for a single CVE.

        OpenAPI:
        body NvdRefreshRequest optional Request body containing mode: local or api.
        response 200 VulnerabilityRefreshResponse Refreshed vulnerability collection or a completed lookup without data.
        response 404 Error CVE not found.
        response 401 Error NVD API key rejected.
        response 403 Error NVD API credentials forbidden.
        response 429 Error NVD API rate limit exceeded.
        response 503 Error NVD data source unavailable.
        """
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404
        if not CVE_RE.fullmatch(cve_id_upper):
            return _unreturned_refresh("nvd", cve_id_upper, "skipped")

        body = request.get_json(force=True, silent=True) or {}
        mode = body.get("mode", "local")  # "local" (default) or "api"

        if mode == "api":
            import os as _os
            api_key = _os.getenv("NVD_API_KEY")
            api_key_configured = bool(api_key)
            try:
                nvd = NVD_DB(nvd_api_key=api_key)
                status_code, data_api = nvd.api_get_cve(cve_id_upper, max_retries=0)
            except Exception as e:
                return jsonify({
                    "error": f"NVD API unavailable: {e}",
                    "error_code": "unavailable",
                    "api_key_configured": api_key_configured,
                }), 503
            if status_code == 429:
                return jsonify({
                    "error": "NVD API rate limit exceeded",
                    "error_code": "rate_limited",
                    "api_key_configured": api_key_configured,
                }), 429
            if status_code in (401, 403):
                return jsonify({
                    "error": f"NVD API rejected credentials (HTTP {status_code})",
                    "error_code": "unauthorized",
                    "api_key_configured": api_key_configured,
                }), status_code
            try:
                if status_code != 200:
                    raise ValueError(f"NVD lookup failed (HTTP {status_code})")
                cve_obj = parse_nvd_lookup(data_api, cve_id_upper)
                if cve_obj is None:
                    return _unreturned_refresh("nvd", cve_id_upper, NO_PROVIDER_RECORD)
                details = NVD_DB.extract_cve_details(cve_obj)
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                return jsonify({
                    "error": str(e),
                    "error_code": "unavailable",
                    "api_key_configured": api_key_configured,
                }), 503
        else:
            try:
                cve_obj = get_cve_json(cve_id_upper, strict=True)
                if cve_obj is None:
                    return _unreturned_refresh("nvd", cve_id_upper, NO_PROVIDER_RECORD)
                details = extract_cve_details(cve_obj)
            except Exception as e:
                current_app.logger.warning("Local NVD refresh failed: %s", e)
                return jsonify({
                    "error": "Local NVD lookup failed",
                    "error_code": "unavailable",
                }), 503
        now = datetime.datetime.now(datetime.timezone.utc)
        apply_nvd_update(rec, details, now)

        apply_cvss_update(rec, details, db)
        db.session.commit()

        # After commit, mapped columns are expired but transient attributes
        # still hold pre-update values. Reload mapped columns then re-derive
        # all transient attrs so to_dict() returns fresh data.
        db.session.refresh(rec)
        rec._init_transient()

        # Repopulate transient severity scores from now-committed metrics so
        # to_dict() returns correct min/max without a full controller preload.
        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        data = rec.to_dict()

        # Note: we don't have "variant" information here so we fetch all texts.
        # This can be incoherent.
        vuln_texts = fetch_vulnerabilities_texts([cve_id_upper], variant_ids=None)
        data["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[cve_id_upper]))

        return jsonify({"vulnerabilities": [data]}), 200

    @app.route('/api/vulnerabilities/<cve_id>/epss-refresh', methods=['POST'])
    @tracked_single_refresh("epss")
    @refresh_history("epss")
    def refresh_single_cve_epss(cve_id: str) -> ResponseReturnValue:
        """Refresh EPSS data for a single CVE.

        OpenAPI:
        response 200 VulnerabilityRefreshResponse Refreshed vulnerability collection or a completed lookup without data.
        response 404 Error CVE not found.
        response 503 Error EPSS data source unavailable.
        """
        cve_id_upper = cve_id.upper()
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        if not CVE_RE.fullmatch(cve_id_upper):
            return _unreturned_refresh("epss", cve_id_upper, "skipped")
        try:
            epss_data = EPSS_DB().api_get_epss(cve_id_upper, strict=True)
        except Exception as e:
            current_app.logger.warning("EPSS refresh failed: %s", e)
            return jsonify({"error": "EPSS API lookup failed"}), 503
        if epss_data is None:
            return _unreturned_refresh("epss", cve_id_upper, NO_PROVIDER_RECORD)

        now = datetime.datetime.now(datetime.timezone.utc)
        new_score = decimal.Decimal(str(epss_data["score"]))
        update_kwargs: dict = {"epss_score": new_score, "epss_fetched_at": now, "commit": False}
        if rec.epss_score is None or rec.epss_score != new_score:
            update_kwargs["epss_data_updated_at"] = now
        rec.update_record(**update_kwargs)
        db.session.commit()

        db.session.refresh(rec)
        rec._init_transient()
        # Set percentile in transient epss dict (not stored in DB)
        rec.epss["percentile"] = epss_data.get("percentile")

        # Repopulate transient severity scores from committed metrics
        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        return jsonify({"vulnerabilities": [rec.to_dict()]}), 200

    @app.route('/api/vulnerabilities/<cve_id>/euvd-refresh', methods=['POST'])
    @tracked_single_refresh("euvd")
    @refresh_history("euvd")
    def refresh_single_cve_euvd(cve_id: str) -> ResponseReturnValue:
        """Refresh ENISA EUVD and EU KEV data for a single CVE.

        OpenAPI:
        response 200 VulnerabilityRefreshResponse Refreshed vulnerability collection.
        response 400 Error Invalid CVE identifier.
        response 404 Error CVE not found.
        response 503 Error ENISA EUVD data source unavailable.
        """
        cve_id_upper = cve_id.upper()
        if not CVE_RE.match(cve_id_upper):
            return jsonify({"error": "Only valid CVE identifiers are supported"}), 400
        rec = db.session.get(Vulnerability, cve_id_upper)
        if rec is None:
            return jsonify({"error": "CVE not found"}), 404

        euvd = EUVD_DB()
        full_map = euvd.get_full_mapping()
        kev_map = euvd.get_mapping()
        # An empty dump means ENISA was unreachable; applying it would clear KEV flags.
        if not full_map or not kev_map:
            return jsonify({"error": "ENISA EUVD data unavailable"}), 503

        _apply_euvd(cve_id_upper, full_map, kev_map, datetime.datetime.now(datetime.timezone.utc))
        db.session.commit()

        db.session.refresh(rec)
        rec._init_transient()
        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        return jsonify({"vulnerabilities": [rec.to_dict()]}), 200

    @app.route('/api/vulnerabilities/<ghsa_id>/ghsa-refresh', methods=['POST'])
    @tracked_single_refresh("ghsa")
    @refresh_history("ghsa")
    def refresh_single_ghsa(ghsa_id: str) -> ResponseReturnValue:
        """Refresh GitHub advisory metadata for a single GHSA identifier.

        OpenAPI:
        response 200 VulnerabilityRefreshResponse Refreshed vulnerability collection.
        response 400 Error Invalid GHSA identifier.
        response 404 Error GHSA advisory not found.
        response 502 Error Upstream GitHub advisory error.
        response 503 Error GitHub advisory data source unavailable.
        """
        ghsa_id_upper = ghsa_id.upper()
        if not _GHSA_RE.match(ghsa_id_upper):
            return jsonify({"error": "Only valid GHSA identifiers (GHSA-xxxx-xxxx-xxxx) are supported"}), 400
        rec = db.session.get(Vulnerability, ghsa_id_upper)
        if rec is None:
            return jsonify({"error": "GHSA advisory not found"}), 404

        try:
            published_at = VulnerabilitiesController._fetch_ghsa_published(ghsa_id_upper)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return jsonify({"error": "Advisory not found in GitHub Advisory Database"}), 404
            return jsonify({"error": f"GitHub Advisory Database returned HTTP {e.code}"}), 502
        except urllib.error.URLError:
            return jsonify({"error": "Failed to reach GitHub Advisory Database"}), 503
        if published_at is None:
            return jsonify({"error": "GitHub Advisory Database returned no published date"}), 503

        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            publish_date = datetime.date.fromisoformat(published_at[:10])
        except (ValueError, AttributeError):
            return jsonify({"error": "GitHub Advisory Database returned an unparseable date"}), 503
        update_kwargs: dict = {
            "publish_date": publish_date,
            "ghsa_fetched_at": now,
            "commit": False,
        }
        if rec.publish_date != publish_date:
            update_kwargs["ghsa_data_updated_at"] = now
        rec.update_record(**update_kwargs)
        db.session.commit()

        db.session.refresh(rec)
        rec._init_transient()

        for m in (rec.metrics or []):
            if m.score is not None:
                score = float(m.score)
                if rec.severity_min_score is None or score < rec.severity_min_score:
                    rec.severity_min_score = score
                if rec.severity_max_score is None or score > rec.severity_max_score:
                    rec.severity_max_score = score

        data = rec.to_dict()
        vuln_texts = fetch_vulnerabilities_texts([ghsa_id_upper], variant_ids=None)
        data["texts"] = list(map(VulnerabilityText.to_dict, vuln_texts[ghsa_id_upper]))

        return jsonify({"vulnerabilities": [data]}), 200

    @app.route('/api/vulnerabilities/<vuln_id>/refresh', methods=['POST'])
    def refresh_individual(vuln_id: str) -> ResponseReturnValue:
        """Refresh all relevant providers as one individual refresh run.

        OpenAPI:
        body NvdRefreshRequest optional NVD mode; use api for the live provider.
        response 200 IndividualRefreshResponse Per-provider outcomes and refresh run identity.
        response 404 Error Vulnerability not found or outside the selected scope.
        """
        from flask import abort, current_app, make_response
        from ..helpers.refresh_runs import create_run, single_refresh_run, single_refresh_scope

        identifier = vuln_id.upper()
        record = db.session.get(Vulnerability, identifier)
        if record is None:
            abort(404, description="Vulnerability not found")
        scope = single_refresh_scope(identifier)
        providers = ([("ghsa", refresh_single_ghsa)] if identifier.startswith("GHSA-") else
                     [("nvd", refresh_single_cve), ("epss", refresh_single_cve_epss),
                      ("euvd", refresh_single_cve_euvd)])
        run_id = create_run({source: [identifier] for source, _ in providers},
                            scope={**scope, "refresh_type": "individual"})
        results = {}
        with single_refresh_run(run_id):
            for source, refresh in providers:
                try:
                    response = make_response(refresh(identifier))
                    body = response.get_json()
                    if response.status_code == 200 and any(scope.values()):
                        for data in body["vulnerabilities"]:
                            _apply_individual_refresh_scope(data, record, scope)
                    results[source] = {"status": response.status_code, "body": body}
                except Exception:
                    current_app.logger.exception("Individual %s refresh failed for %s", source, identifier)
                    results[source] = {"status": 500, "body": {"error": "Source refresh failed"}}
        response = jsonify({"run_id": run_id, "results": results})
        response.headers["X-Refresh-Run-ID"] = run_id
        return response
