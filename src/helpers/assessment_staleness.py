# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Helpers for determining whether a custom assessment has been superseded.

An assessment is *outdated* when the package it was written against has been
replaced by a newer version in the active SBOM **and** that newer version
is still affected by the same CVE.  This indicates the analyst's verdict may
no longer apply to the component that is actually shipped.

Precise semantics
-----------------
A custom assessment (``origin == 'custom'``, ``variant_id`` set) is outdated
when **any** package name it covers has been superseded, i.e. all four
conditions hold for that name:

1. None of the assessed versions of that package *name* (name@version pairs,
   supplier suffix ignored) are present in the variant's current active SBOM.
2. That package *name* is present in the active SBOM at a *different* version.
3. That newer version has a Finding for the same CVE (``vulnerability_id``).
4. That Finding is observed in the variant's active scan set (latest SBOM
   scan plus the latest tool scan per source — nvd, osv, grype, scc, …).
   CVE findings are recorded by *tool* scans, so restricting this check to
   SBOM scans would miss every real-world case.

Staleness is evaluated **per package name**.  An assessment covering several
different packages (e.g. ``firefox@1.0`` and ``chrome@1.0``) is flagged as
soon as *one* of them is superseded (``firefox@2.0`` appears and is still
affected) — even if the other package (``chrome@1.0``) is unchanged.  A name
referenced at multiple versions (``firefox@1.0`` and ``firefox@2.0``) stays
current while any of those versions is still active.

Non-custom assessments (scanner / SBOM origin) are left unchanged — they are
regenerated from scratch on every scan.

Performance
-----------
The annotation always executes exactly **three** SQL queries regardless of
how many variants appear in the input list.  Earlier versions ran 3 queries
per variant, which was noticeable when a single vulnerability had assessments
across many variants (e.g. opening VulnModal on a widely-shared CVE).

Usage
-----
::

    dicts = [a.to_dict() for a in db_assessments]
    annotate_assessments_outdated(dicts)
    # dicts now have "outdated": bool, "superseded_by": list[str],
    # "stale_packages": list[str] and "superseded_map": dict[str, list[str]]
"""

from __future__ import annotations

import uuid
from collections import defaultdict

from ..extensions import db
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.package import Package
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.scan import Scan


def _parse_pkg_name_version(pkg_string_id: str) -> tuple[str, str]:
    """Extract ``(name, version)`` from ``'name@version'`` or ``'name@version::supplier'``."""
    base = pkg_string_id.split("::", 1)[0]
    if "@" in base:
        name, version = base.rsplit("@", 1)
    else:
        name, version = base, ""
    return name, version


def annotate_assessments_outdated(assessment_dicts: list[dict]) -> None:
    """Mutate *assessment_dicts* in-place, adding ``outdated`` and ``superseded_by``.

    Keys added to every dict:
    - ``"outdated"``: ``True`` when the assessment has been superseded per the
      semantics described in the module docstring, ``False`` otherwise.
    - ``"superseded_by"``: sorted list of ``"name@version"`` strings for the
      package versions that replace the stale ones (empty when not outdated).
    - ``"stale_packages"``: sorted list of the assessment's *own* package
      references (exactly as they appear in ``packages``) that are outdated —
      i.e. the specific packages the UI should flag (empty when not outdated).
    - ``"superseded_map"``: mapping of each stale package reference to the
      sorted ``"name@version"`` list that supersedes it (empty when not
      outdated).

    The function is a no-op (sets defaults) when there are no custom assessments
    with a ``variant_id``, so it is safe to call unconditionally.

    Exactly three SQL queries are issued regardless of the number of variants.
    """
    # Always initialise so every dict has predictable keys.
    for d in assessment_dicts:
        d["outdated"] = False
        d["superseded_by"] = []
        d["stale_packages"] = []
        d["superseded_map"] = {}

    # Only custom assessments with a variant scope can be outdated.
    candidates = [
        d for d in assessment_dicts
        if d.get("origin") == "custom" and d.get("variant_id")
    ]
    if not candidates:
        return

    # ------------------------------------------------------------------
    # Validate variant UUIDs and group assessments by variant.
    # ------------------------------------------------------------------
    valid_variants: dict[uuid.UUID, list[dict]] = {}
    for d in candidates:
        try:
            vid = uuid.UUID(d["variant_id"])
        except (ValueError, AttributeError, TypeError):
            continue
        valid_variants.setdefault(vid, []).append(d)

    if not valid_variants:
        return

    # Collect all (name, version) pairs and vuln_ids referenced across
    # every candidate assessment (used to constrain the queries below).
    all_referenced_names: set[str] = set()
    all_vuln_ids: set[str] = set()
    for group in valid_variants.values():
        for d in group:
            vuln_id_val = d.get("vuln_id", "")
            if vuln_id_val:
                all_vuln_ids.add(vuln_id_val)
            for p in d.get("packages", []):
                name, _ = _parse_pkg_name_version(p)
                all_referenced_names.add(name)

    if not all_referenced_names:
        return

    # ------------------------------------------------------------------
    # QUERY 1 (of 3): every scan for the candidate variants, in one
    # round-trip.  From this we derive two per-variant scan sets in
    # Python (no per-variant helper calls):
    #
    #   * SBOM active scan   — the single latest SBOM scan.  Packages
    #     come exclusively from SBOM scans, so conditions 1-2 use this.
    #   * Full active set    — latest SBOM + latest tool scan per source
    #     (nvd, osv, grype, scc, …).  CVE findings are observed in TOOL
    #     scans, so conditions 3-4 must use this — mirroring the logic in
    #     ``active_scans.active_scan_ids_for_variant``.
    # ------------------------------------------------------------------
    scan_rows = db.session.execute(
        db.select(Scan.id, Scan.variant_id, Scan.scan_type, Scan.scan_source, Scan.timestamp)
        .where(Scan.variant_id.in_(list(valid_variants.keys())))
        .order_by(Scan.variant_id, Scan.timestamp.desc(), Scan.id.desc())
    ).all()

    # variant_id -> latest SBOM scan id (packages)
    sbom_scan_by_variant: dict[uuid.UUID, uuid.UUID] = {}
    # variant_id -> list of active scan ids (SBOM + latest tool per source)
    full_active_scans_by_variant: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    # scan_id -> variant_id, for every scan in the full active set
    scan_to_variant: dict[uuid.UUID, uuid.UUID] = {}
    _seen_keys: dict[uuid.UUID, set[str]] = defaultdict(set)

    for scan_id, var_id, scan_type, scan_source, _ts in scan_rows:
        st = scan_type or "sbom"
        key = f"tool:{scan_source}" if st == "tool" else "sbom"
        if key in _seen_keys[var_id]:
            continue  # already have a newer scan for this source
        _seen_keys[var_id].add(key)
        full_active_scans_by_variant[var_id].append(scan_id)
        scan_to_variant[scan_id] = var_id
        if key == "sbom":
            sbom_scan_by_variant[var_id] = scan_id

    if not sbom_scan_by_variant:
        return

    # SBOM scans only (for the package queries).
    sbom_active_scan_ids = list(sbom_scan_by_variant.values())
    # Full active set (for the finding-observation query).
    full_active_scan_ids: list[uuid.UUID] = []
    for scan_id_list in full_active_scans_by_variant.values():
        full_active_scan_ids.extend(scan_id_list)

    # ------------------------------------------------------------------
    # QUERY 2 (of 3): active SBOM packages across all variants at once,
    # restricted to the package names referenced by our assessments.
    # Packages come from SBOM scans, so this is scoped to SBOM scans.
    # ------------------------------------------------------------------
    active_pkg_rows = db.session.execute(
        db.select(SBOMDocument.scan_id, Package.name, Package.version, Package.id)
        .join(SBOMPackage, SBOMPackage.package_id == Package.id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .where(SBOMDocument.scan_id.in_(sbom_active_scan_ids))
        .where(Package.name.in_(list(all_referenced_names)))
        .distinct()
    ).all()

    # Per-variant indexes built from query 2.
    # variant_id → name → set of active versions
    active_versions_by_name: dict[uuid.UUID, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    # variant_id → (name, version) → set of package_ids
    active_pkg_ids_by_nv: dict[uuid.UUID, dict[tuple[str, str], set[uuid.UUID]]] = (
        defaultdict(lambda: defaultdict(set))
    )

    for scan_id, pkg_name, pkg_version, pkg_id in active_pkg_rows:
        var_id = scan_to_variant.get(scan_id)
        if var_id is None:
            continue
        active_versions_by_name[var_id][pkg_name].add(pkg_version)
        active_pkg_ids_by_nv[var_id][(pkg_name, pkg_version)].add(pkg_id)

    # ------------------------------------------------------------------
    # QUERY 3 (of 3): observed findings for all active packages ×
    # all relevant vuln IDs across all variants at once.
    #
    # Scoped to the FULL active set (SBOM + tool scans): a CVE finding
    # for the new package version is observed in a *tool* scan, never in
    # the SBOM scan, so restricting to SBOM scans here would miss every
    # real-world case.
    # ------------------------------------------------------------------
    # variant_id → set of (package_id, vuln_id) pairs confirmed in that variant
    observed_pairs_by_variant: dict[uuid.UUID, set[tuple[uuid.UUID, str]]] = defaultdict(set)

    if all_vuln_ids:
        all_active_pkg_ids: set[uuid.UUID] = set()
        for by_nv in active_pkg_ids_by_nv.values():
            for pkg_id_set in by_nv.values():
                all_active_pkg_ids.update(pkg_id_set)

        if all_active_pkg_ids:
            finding_rows = db.session.execute(
                db.select(Finding.package_id, Finding.vulnerability_id, Observation.scan_id)
                .join(Observation, Observation.finding_id == Finding.id)
                .where(Finding.package_id.in_(list(all_active_pkg_ids)))
                .where(Finding.vulnerability_id.in_(list(all_vuln_ids)))
                .where(Observation.scan_id.in_(full_active_scan_ids))
                .distinct()
            ).all()
            for pkg_id, vuln_id, scan_id in finding_rows:
                var_id = scan_to_variant.get(scan_id)
                if var_id is not None:
                    observed_pairs_by_variant[var_id].add((pkg_id, vuln_id))

    # ------------------------------------------------------------------
    # Annotate each assessment using the per-variant indexes.
    # ------------------------------------------------------------------
    for variant_uuid, group in valid_variants.items():
        if variant_uuid not in sbom_scan_by_variant:
            continue  # no active SBOM scan for this variant

        v_active_versions = active_versions_by_name[variant_uuid]
        v_active_pkg_ids = active_pkg_ids_by_nv[variant_uuid]
        v_observed = observed_pairs_by_variant[variant_uuid]

        for d in group:
            _annotate_one(d, v_active_versions, v_active_pkg_ids, v_observed)


def _annotate_one(
    d: dict,
    v_active_versions: dict[str, set[str]],
    v_active_pkg_ids: dict[tuple[str, str], set[uuid.UUID]],
    v_observed: set[tuple[uuid.UUID, str]],
) -> None:
    """Annotate a single assessment dict *d* in-place with staleness info.

    Staleness is decided *per package name*.  A name is still current — and
    therefore cannot be superseded — when either a version-less reference
    matches any active version, or one of its assessed versions is still in the
    active SBOM.  A name that is NOT current is superseded when the active SBOM
    carries a different, still-affected version of it.  The assessment is
    outdated as soon as ANY covered name is superseded, regardless of whether
    its other packages remain current.
    """
    vuln_id = d.get("vuln_id", "")
    orig_refs = d.get("packages", [])
    if not orig_refs:
        return

    # Group the assessed references by package name.  A name may be referenced
    # at several concrete versions and/or version-lessly.  Also remember the
    # *original* package strings per name so the exact stale references can be
    # reported back to the UI.
    assessed_versions_by_name: dict[str, set[str]] = defaultdict(set)
    versionless_names: set[str] = set()
    orig_refs_by_name: dict[str, list[str]] = defaultdict(list)
    for ref in orig_refs:
        name, ver = _parse_pkg_name_version(ref)
        orig_refs_by_name[name].append(ref)
        if ver:
            assessed_versions_by_name[name].add(ver)
        else:
            versionless_names.add(name)

    superseded_by: list[str] = []
    stale_packages: list[str] = []
    superseded_map: dict[str, list[str]] = {}
    for name in set(assessed_versions_by_name) | versionless_names:
        name_superseded_by = _superseding_versions_for_name(
            name,
            assessed_versions_by_name.get(name, set()),
            name in versionless_names,
            vuln_id,
            v_active_versions,
            v_active_pkg_ids,
            v_observed,
        )
        if not name_superseded_by:
            continue
        for label in name_superseded_by:
            if label not in superseded_by:
                superseded_by.append(label)
        # Every original reference for this name is now stale.
        for ref in orig_refs_by_name[name]:
            if ref not in stale_packages:
                stale_packages.append(ref)
            superseded_map[ref] = sorted(name_superseded_by)

    if superseded_by:
        d["outdated"] = True
        d["superseded_by"] = sorted(superseded_by)
        d["stale_packages"] = sorted(stale_packages)
        d["superseded_map"] = superseded_map


def _superseding_versions_for_name(
    name: str,
    old_versions: set[str],
    versionless: bool,
    vuln_id: str,
    v_active_versions: dict[str, set[str]],
    v_active_pkg_ids: dict[tuple[str, str], set[uuid.UUID]],
    v_observed: set[tuple[uuid.UUID, str]],
) -> list[str]:
    """Return the ``"name@version"`` labels that supersede *name*, or ``[]``.

    Empty when the name is still current (an assessed version — or a
    version-less reference — is still active) or when no newer, still-affected
    version of it exists in the active SBOM.
    """
    active_versions = v_active_versions.get(name, set())
    if versionless and name in v_active_versions:
        return []  # version-less reference keeps this name current
    if active_versions & old_versions:
        return []  # an assessed version is still active → current

    result: list[str] = []
    for new_version in active_versions:
        if new_version in old_versions:
            continue
        new_pkg_ids = v_active_pkg_ids.get((name, new_version), set())
        if any((pid, vuln_id) in v_observed for pid in new_pkg_ids):
            label = f"{name}@{new_version}"
            if label not in result:
                result.append(label)
    return result
