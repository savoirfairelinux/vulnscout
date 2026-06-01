# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for importing and exporting assessments as OpenVEX archives.

Both the CLI (``cmd_assessments.py``) and the web API (``routes/assessments.py``)
perform the same build/parse logic.  This module contains the common core so
neither caller needs to re-implement it.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import uuid as _uuid
from collections import defaultdict
from datetime import datetime as _dt, timezone as _tz
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models.variant import Variant as _Variant  # noqa: F401


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _get_vuln_info(vuln_id: str, vuln_cache: dict) -> dict:
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
        desc = vuln_obj.texts.get("description", "")
        yocto_desc = vuln_obj.texts.get("yocto description", "")
        description = desc or yocto_desc or ""
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
    assessments: list,
    author: str,
    now_iso: str | None = None,
    vuln_cache: dict | None = None,
) -> dict:
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
        stmt["scanners"] = list({
            assess.source or "local_user_data",
            assess.origin or "local_user_data",
        })
        statements.append(stmt)

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


def build_openvex_archive(
    handmade_assessments: list,
    variant_names: dict[str, str],
    author: str,
    now_iso: str | None = None,
) -> bytes:
    """Build an in-memory tar.gz archive of OpenVEX JSON files.

    One ``.json`` file is created per variant (named
    ``<variant_name>.json``).  Assessments without a variant go into
    ``unassigned.json``.

    Parameters
    ----------
    handmade_assessments:
        List of DB ``Assessment`` objects (usually from
        ``Assessment.get_handmade()``).
    variant_names:
        Mapping ``str(variant_id) → variant_name`` used to name the files.
    author:
        Author string written into every OpenVEX document header.
    now_iso:
        ISO-8601 timestamp written into every document.  Defaults to *now*.

    Returns
    -------
    bytes
        Raw tar.gz content.
    """
    if now_iso is None:
        now_iso = _dt.now(_tz.utc).isoformat()

    vuln_cache: dict = {}

    by_variant: dict[str | None, list] = defaultdict(list)
    for assess in handmade_assessments:
        vid = str(assess.variant_id) if assess.variant_id else None
        by_variant[vid].append(assess)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for vid, assessments in by_variant.items():
            filename = sanitize_variant_name(
                variant_names.get(vid, "unassigned") if vid else "unassigned"
            ) + ".json"

            doc = build_openvex_doc(assessments, author, now_iso, vuln_cache)

            json_bytes = json.dumps(doc, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name=filename)
            info.size = len(json_bytes)
            tar.addfile(info, io.BytesIO(json_bytes))

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Import helpers
# ---------------------------------------------------------------------------

def is_openvex_doc(doc: object) -> bool:
    """Return ``True`` if *doc* looks like a valid OpenVEX document."""
    if not isinstance(doc, dict):
        return False
    ctx = doc.get("@context", "")
    return "openvex" in str(ctx) and isinstance(doc.get("statements"), list)


def import_statements(
    statements: list,
    variant_id,
) -> tuple[list[dict], list[dict], int]:
    """Persist a list of OpenVEX statement dicts as DB assessments.

    Parameters
    ----------
    statements:
        List of OpenVEX statement dicts (the ``"statements"`` array from an
        OpenVEX JSON document).
    variant_id:
        UUID of the target variant to attach the assessments to.

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

    created: list[dict] = []
    errors: list[dict] = []
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
                    db.select(DBAssessment).where(
                        DBAssessment.finding_id == finding.id,
                        DBAssessment.variant_id == variant_id,
                        DBAssessment.status == status,
                    )
                ).scalar_one_or_none()
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


def build_variant_by_name_map(project_id: "_uuid.UUID | None" = None) -> dict:
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
    variant_by_name: dict = {}
    for v in variants:
        sanitised = sanitize_variant_name(v.name)
        variant_by_name[sanitised] = v
        variant_by_name[v.name] = v
    return variant_by_name


def import_archive_bytes(
    file_bytes: bytes,
    variant_by_name: dict,
) -> tuple[list[dict], list[dict], int, int]:
    """Import OpenVEX assessments from a tar.gz archive (as raw bytes).

    Returns
    -------
    (created, errors, skipped, variant_files_found)
    """
    total_created: list[dict] = []
    total_errors: list[dict] = []
    total_skipped = 0
    variant_files_found = 0

    try:
        tar = tarfile.open(fileobj=io.BytesIO(file_bytes), mode='r:gz')
    except Exception:
        raise ValueError("Unable to open tar.gz archive")

    for member in tar.getmembers():
        if not member.isfile() or not member.name.endswith(".json"):
            continue
        base = os.path.basename(member.name)
        variant_name = base[: -len(".json")]
        variant = variant_by_name.get(variant_name)
        if variant is None:
            total_errors.append({
                "file": member.name,
                "error": f"No variant found matching name '{variant_name}'",
            })
            continue

        f = tar.extractfile(member)
        if f is None:
            continue
        try:
            doc = json.load(f)
        except Exception:
            total_errors.append({"file": member.name, "error": "Invalid JSON"})
            continue

        if not is_openvex_doc(doc):
            total_errors.append({
                "file": member.name,
                "error": "Not a valid OpenVEX document",
            })
            continue

        variant_files_found += 1
        c, e, s = import_statements(doc["statements"], variant.id)
        total_created.extend(c)
        total_errors.extend(e)
        total_skipped += s

    tar.close()
    return total_created, total_errors, total_skipped, variant_files_found


def import_directory(
    dir_path: str,
    variant_by_name: dict,
) -> tuple[list[dict], list[dict], int, int]:
    """Import OpenVEX assessments from a directory of JSON files.

    Each ``.json`` file is matched to a variant by its filename (sans
    extension).

    Returns
    -------
    (created, errors, skipped, variant_files_found)
    """
    total_created: list[dict] = []
    total_errors: list[dict] = []
    total_skipped = 0
    variant_files_found = 0

    json_files = sorted(f for f in os.listdir(dir_path) if f.endswith(".json"))
    if not json_files:
        raise ValueError("No .json files found in directory")

    for json_name in json_files:
        variant_name = json_name[: -len(".json")]
        variant = variant_by_name.get(variant_name)
        if variant is None:
            total_errors.append({
                "file": json_name,
                "error": f"No variant found matching name '{variant_name}'",
            })
            continue

        json_path = os.path.join(dir_path, json_name)
        try:
            with open(json_path) as fh:
                doc = json.load(fh)
        except Exception:
            total_errors.append({"file": json_name, "error": "Invalid JSON"})
            continue

        if not is_openvex_doc(doc):
            total_errors.append({
                "file": json_name,
                "error": "Not a valid OpenVEX document",
            })
            continue

        variant_files_found += 1
        c, e, s = import_statements(doc["statements"], variant.id)
        total_created.extend(c)
        total_errors.extend(e)
        total_skipped += s

    return total_created, total_errors, total_skipped, variant_files_found


# ---------------------------------------------------------------------------
# Custom-data export (assessments + CVSS + time estimates)
# ---------------------------------------------------------------------------

def build_custom_data_export(
    variant_ids: list | None = None,
) -> dict:
    """Build a custom-data export dict containing assessments, CVSS and time
    estimates for the given variant(s).

    Parameters
    ----------
    variant_ids:
        List of variant UUIDs to scope the export.  When *None* all
        handmade assessments across all variants are exported.

    Returns
    -------
    dict with keys ``version``, ``exported_at``, ``assessments``, ``cvss``,
    ``time_estimates``.
    """
    from ..extensions import db
    from ..models.assessment import Assessment as DBAssessment
    from ..models.metrics import Metrics
    from ..models.time_estimate import TimeEstimate
    from ..models.iso8601_duration import Iso8601Duration

    handmade = DBAssessment.get_handmade(variant_ids)

    exported_assessments = []
    for a in handmade:
        d = a.to_dict()
        exported_assessments.append({
            "vuln_id": d["vuln_id"],
            "status": d["status"],
            "simplified_status": d.get("simplified_status", ""),
            "justification": d.get("justification") or None,
            "impact_statement": d.get("impact_statement") or None,
            "status_notes": d.get("status_notes") or None,
            "workaround": d.get("workaround") or None,
            "packages": d["packages"],
            "variant_id": d.get("variant_id"),
        })

    # Gather ALL custom CVSS entries, not just those linked to handmade
    # assessments.
    cvss_entries: list[dict] = []
    all_metrics = list(db.session.execute(
        db.select(Metrics).where(
            Metrics.origin == "custom",
        )
    ).scalars().all())
    for m in sorted(all_metrics, key=lambda m: m.vulnerability_id):
        if variant_ids is not None:
            if m.variant_id is None or m.variant_id not in variant_ids:
                continue
        cvss_entries.append({
            "vuln_id": m.vulnerability_id,
            "variant_id": str(m.variant_id) if m.variant_id is not None else None,
            "version": m.version or "",
            "vector_string": m.vector or "",
            "base_score": float(m.score) if m.score is not None else 0.0,
            "author": m.author,
            "origin": m.origin or "scanner",
        })

    # Gather ALL non-zero time estimates, not just those linked to
    # handmade assessments.
    time_estimates: list[dict] = []
    all_te = list(db.session.execute(
        db.select(TimeEstimate).where(
            db.or_(
                TimeEstimate.optimistic > 0,
                TimeEstimate.likely > 0,
                TimeEstimate.pessimistic > 0,
            )
        )
    ).scalars().all())

    def _hours_to_iso(h: int) -> str:
        try:
            return str(Iso8601Duration(f"PT{h}H"))
        except (ValueError, TypeError):
            return f"PT{h}H"

    seen_vulns_te: set[tuple[str, str]] = set()
    for te in all_te:
        if te.finding is None:
            continue
        if variant_ids is not None:
            if te.variant_id is None or te.variant_id not in variant_ids:
                continue
        vid = te.finding.vulnerability_id
        variant_key = str(te.variant_id) if te.variant_id is not None else ""
        dedup_key = (vid, variant_key)
        if dedup_key in seen_vulns_te:
            continue
        seen_vulns_te.add(dedup_key)
        opt = te.optimistic or 0
        lik = te.likely or 0
        pes = te.pessimistic or 0
        time_estimates.append({
            "vuln_id": vid,
            "variant_id": str(te.variant_id) if te.variant_id is not None else None,
            "optimistic": _hours_to_iso(opt),
            "likely": _hours_to_iso(lik),
            "pessimistic": _hours_to_iso(pes),
        })
    time_estimates.sort(key=lambda t: (t["vuln_id"], t.get("variant_id") or ""))

    return {
        "version": 1,
        "exported_at": _dt.now(_tz.utc).isoformat(),
        "assessments": exported_assessments,
        "cvss": cvss_entries,
        "time_estimates": time_estimates,
    }


# ---------------------------------------------------------------------------
# Custom-data import (assessments + CVSS + time estimates)
# ---------------------------------------------------------------------------

def import_custom_data(
    data: dict,
    variant_by_name: dict,
    variant_id: "_uuid.UUID | None" = None,
) -> dict:
    """Import a custom-data JSON document containing assessments, CVSS and
    time estimates.

    Parameters
    ----------
    data:
        Parsed JSON matching the custom-data export format
        (``{version, assessments, cvss, time_estimates}``).
    variant_by_name:
        Mapping ``{name: Variant, sanitised_name: Variant}`` for variant
        resolution.
    variant_id:
        When provided, all assessments are attached to this variant.
        When *None*, each assessment's ``variant_id`` field is used.

    Returns
    -------
    dict with ``status``, ``assessments_imported``, ``assessments_skipped``,
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
        _validate_effort,
        _validate_and_apply_cvss,
        _apply_effort,
    )

    result: dict = {
        "status": "success",
        "assessments_imported": 0,
        "assessments_skipped": 0,
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

    # -- Import assessments --
    assessments_list = data.get("assessments", [])
    if isinstance(assessments_list, list):
        for a in assessments_list:
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
            target_variant_id = variant_id
            if target_variant_id is None and a.get("variant_id"):
                try:
                    target_variant_id = _uuid.UUID(a["variant_id"])
                except (ValueError, TypeError):
                    v = variant_by_name.get(a["variant_id"])
                    if v:
                        target_variant_id = v.id

            justification = a.get("justification", "")
            impact_statement = a.get("impact_statement", "")
            status_notes = a.get("status_notes", "")
            workaround = a.get("workaround", "")

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
                        db.select(DBAssessment).where(
                            DBAssessment.finding_id == finding.id,
                            DBAssessment.variant_id == target_variant_id,
                            DBAssessment.status == status,
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        result["assessments_skipped"] += 1
                        continue

                    DBAssessment.create(
                        status=status,
                        simplified_status=STATUS_TO_SIMPLIFIED.get(
                            status, "Pending Assessment"
                        ),
                        finding_id=finding.id,
                        variant_id=target_variant_id,
                        origin="custom",
                        status_notes=status_notes,
                        justification=justification,
                        impact_statement=impact_statement,
                        workaround=workaround,
                        responses=[],
                        commit=True,
                    )
                    result["assessments_imported"] += 1
                except Exception as e:
                    result["errors"].append({
                        "vuln_id": vuln_name,
                        "package": pkg_string_id,
                        "error": str(e),
                    })

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
            cvss_variant_id = variant_id
            if cvss_variant_id is None and c.get("variant_id"):
                try:
                    cvss_variant_id = _uuid.UUID(c["variant_id"])
                except (ValueError, TypeError):
                    mapped_variant = variant_by_name.get(c["variant_id"])
                    if mapped_variant is not None:
                        cvss_variant_id = mapped_variant.id

            target_variant_ids: list[_uuid.UUID | None]
            if cvss_variant_id is not None:
                target_variant_ids = [cvss_variant_id]
            else:
                target_variant_ids = _variants_for_vuln_id(vuln_id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            cvss_failed = False
            for target_variant_id in target_variant_ids:
                err = _validate_and_apply_cvss(cvss_data, record.id, target_variant_id,
                                               log_prefix="import-custom-data")
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
            opt, lik, pes, err = _validate_effort(eff)
            if err:
                result["errors"].append({"vuln_id": vuln_id, "error": err})
                continue

            te_variant_id = variant_id
            if te_variant_id is None and t.get("variant_id"):
                try:
                    te_variant_id = _uuid.UUID(t["variant_id"])
                except (ValueError, TypeError):
                    mapped_variant = variant_by_name.get(t["variant_id"])
                    if mapped_variant is not None:
                        te_variant_id = mapped_variant.id

            if te_variant_id is not None:
                target_variant_ids = [te_variant_id]
            else:
                target_variant_ids = _variants_for_vuln_id(vuln_id)
                if not target_variant_ids:
                    target_variant_ids = [None]

            for target_variant_id in target_variant_ids:
                _apply_effort(record, target_variant_id, opt, lik, pes,
                              log_prefix="import-custom-data")
            result["time_estimates_imported"] += 1

    if not result["assessments_imported"] and not result["cvss_imported"] and not result["time_estimates_imported"]:
        if result["errors"]:
            result["status"] = "error"

    return result
