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
            filename = (
                variant_names.get(vid, "unassigned") if vid else "unassigned"
            ) + ".json"
            filename = filename.replace("/", "_").replace("\\", "_")

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

            doc = {
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
                        DBAssessment.justification == justification,
                        DBAssessment.impact_statement == impact_statement,
                        DBAssessment.status_notes == status_notes,
                        DBAssessment.workaround == workaround,
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


def build_variant_by_name_map() -> dict:
    """Return a ``{name: Variant, sanitised_name: Variant}`` lookup for all variants."""
    from ..models.variant import Variant as DBVariant

    variant_by_name: dict = {}
    for v in DBVariant.get_all():
        sanitised = v.name.replace("/", "_").replace("\\", "_")
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
