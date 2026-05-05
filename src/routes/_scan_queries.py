# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Low-level DB query helpers and serialisation primitives for scan routes.

All functions are *stateless* — they run batch queries and return plain
dicts/sets without any diff or comparison logic.
"""

import uuid as uuid_module

from sqlalchemy.orm import selectinload

from ..models.scan import Scan
from ..models.observation import Observation
from ..models.finding import Finding
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.package import Package
from ..models.variant import Variant
from ..models.project import Project
from ..extensions import db


# ---------------------------------------------------------------------------
# Batch query — findings
# ---------------------------------------------------------------------------

def _findings_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(finding_id)} using a single DB query."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(Observation.scan_id, Observation.finding_id)
        .where(Observation.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, fid in rows:
        result.setdefault(sid, set()).add(fid)
    return result


# ---------------------------------------------------------------------------
# Batch query — vulnerabilities
# ---------------------------------------------------------------------------

def _vulns_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(vulnerability_id)} via Observation -> Finding join."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(Observation.scan_id, Finding.vulnerability_id)
        .join(Finding, Finding.id == Observation.finding_id)
        .where(Observation.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, vid in rows:
        result.setdefault(sid, set()).add(vid)
    return result


# ---------------------------------------------------------------------------
# Batch query — packages
# ---------------------------------------------------------------------------

def _packages_by_scan_ids(scan_ids: list) -> dict:
    """Return {scan_id: set(package_id)} via sbom_documents -> sbom_packages, in one query."""
    if not scan_ids:
        return {}
    rows = db.session.execute(
        db.select(SBOMDocument.scan_id, SBOMPackage.package_id)
        .join(SBOMPackage, SBOMPackage.sbom_document_id == SBOMDocument.id)
        .where(SBOMDocument.scan_id.in_(scan_ids))
    ).all()
    result: dict = {}
    for sid, pid in rows:
        result.setdefault(sid, set()).add(pid)
    return result


def _package_rows(package_ids: set) -> dict:
    """Return {package_id: Package} for the given id set, in one query."""
    if not package_ids:
        return {}
    pkgs = db.session.execute(
        db.select(Package).where(Package.id.in_(package_ids))
    ).scalars().all()
    return {p.id: p for p in pkgs}


def _pkg_to_dict(pkg: Package) -> dict:
    return {
        "package_id": str(pkg.id),
        "package_name": pkg.name or "unknown",
        "package_version": pkg.version or "",
    }


# ---------------------------------------------------------------------------
# Batch query — variant / project names
# ---------------------------------------------------------------------------

def _variant_info(variant_ids: list) -> dict:
    """Return {variant_id: (variant_name, project_name)} in two queries."""
    if not variant_ids:
        return {}
    variants = db.session.execute(
        db.select(Variant).where(Variant.id.in_(variant_ids))
    ).scalars().all()
    project_ids = list({v.project_id for v in variants})
    projects = db.session.execute(
        db.select(Project).where(Project.id.in_(project_ids))
    ).scalars().all()
    project_map = {p.id: p.name for p in projects}
    return {
        v.id: (v.name, project_map.get(v.project_id))
        for v in variants
    }


# ---------------------------------------------------------------------------
# Eager-loading helpers
# ---------------------------------------------------------------------------

def _load_scan_with_findings(scan_id: uuid_module.UUID) -> Scan | None:
    """Load a scan with all observations -> finding -> package eagerly."""
    return db.session.execute(
        db.select(Scan)
        .options(
            selectinload(Scan.observations)  # type: ignore[arg-type]
            .selectinload(Observation.finding)  # type: ignore[arg-type]
            .selectinload(Finding.package)
        )
        .where(Scan.id == scan_id)
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Observation / finding serialisation
# ---------------------------------------------------------------------------

def _obs_to_dict(obs: Observation, origin: str = "Imported SBOM") -> dict:
    f = obs.finding
    pkg = f.package
    return {
        "finding_id": str(f.id),
        "package_name": pkg.name if pkg else "unknown",
        "package_version": pkg.version if pkg else "",
        "package_id": str(f.package_id),
        "vulnerability_id": f.vulnerability_id,
        "origin": origin,
    }


_TOOL_SOURCE_LABELS: dict = {
    "grype": "Grype Scan",
    "nvd": "NVD CPE Scan",
    "osv": "OSV Scan",
}


def _origin_for_scan(scan) -> str:
    """Return a human-readable origin label for a scan."""
    if (scan.scan_type or "sbom") == "tool":
        return _TOOL_SOURCE_LABELS.get(scan.scan_source or "", "Vulnerability Scan")
    return "Imported SBOM"
