# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for PR-B's target-join conversion of the scan query modules.

``_scan_queries.py``, ``_scan_diff.py`` and ``_scan_helpers.py`` no longer
reach an assessment through the scalar ``Assessment.finding_id`` /
``Assessment.variant_id`` columns; they join ``assessment_targets`` instead.

PR-A's ``uq_assessment_targets_assessment_id`` still holds every assessment to
exactly one target row that mirrors those scalar columns, so the conversion is
behaviour-neutral by construction.  Two things therefore have to be proved:

1. **Equivalence** — on data created through the ordinary write paths, the
   target join and the scalar predicate return byte-identical result sets.
2. **Reach** — the new queries find an assessment through its target row even
   when the mirrored scalar columns are absent, which is the shape PR-D
   leaves behind.  Stripping the scalars from a committed row is how a
   single-target world simulates the reference branch's multi-target
   assessment, which ``uq_assessment_targets_assessment_id`` forbids here.
"""

import os
import uuid

import pytest


@pytest.fixture()
def app():
    from src.bin.webapp import create_app
    from src.extensions import db as _db

    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def _variant(project_id: uuid.UUID, name: str):
    from src.models.variant import Variant

    return Variant.create(name=name, project_id=project_id)


def _finding(vuln_id: str, pkg_name: str):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability

    vuln = db.session.get(Vulnerability, vuln_id.upper()) or Vulnerability.create_record(id=vuln_id)
    pkg = Package.create(name=pkg_name, version="1.0.0")
    return Finding.create(package_id=pkg.id, vulnerability_id=vuln.id)


def _strip_scalar_mirror(assessment_id: uuid.UUID) -> None:
    """Clear the mirrored scalar columns, leaving only the target row.

    This is the PR-D row shape.  Reached through Core SQL rather than the ORM
    so the model's mirroring logic cannot put the columns back.
    """
    from src.extensions import db
    from src.models.assessment import Assessment

    db.session.execute(
        db.update(Assessment)
        .where(Assessment.id == assessment_id)
        .values(variant_id=None, finding_id=None)
    )
    db.session.commit()
    db.session.expire_all()


def _scalar_assessment_rows_for_scans(scan_ids):
    """The pre-PR-B shape of :func:`_assessment_rows_for_scans`, kept here as
    the oracle the target join is compared against."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.scan import Scan

    if not scan_ids:
        return []
    return db.session.execute(
        db.select(
            Observation.scan_id,
            Assessment.id,
            Assessment.timestamp,
            Assessment.status,
            Assessment.simplified_status,
            Assessment.justification,
            Assessment.impact_statement,
            Assessment.status_notes,
            Finding.vulnerability_id,
            Assessment.origin,
            Package.name,
            Package.version,
            Package.supplier,
        )
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .join(Package, Package.id == Finding.package_id)
        .where(
            Observation.scan_id.in_(scan_ids),
            Assessment.variant_id == Scan.variant_id,
        )
    ).all()


def _scalar_global_assessment_rows_by_scan(scan_ids):
    """The pre-PR-B shape of :func:`_global_assessment_rows_by_scan`."""
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan

    result: dict = {}
    if not scan_ids:
        return result
    rows = db.session.execute(
        db.select(Assessment.id, Observation.scan_id, Finding.package_id)
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Observation.scan_id.in_(scan_ids),
            Assessment.variant_id == Scan.variant_id,
            Assessment.origin != "custom",
        )
    ).all()
    for aid, sid, pkg_id in rows:
        result.setdefault(sid, []).append((aid, pkg_id))
    return result



def _scalar_global_assessment_ids_for(
    sbom_scan,
    latest_tool,
    _cache=None,
    _obs_prefetch=None,
    _pkg_prefetch=None,
):
    """The pre-PR-B shape of :func:`_global_assessment_ids_for`.

    A line-for-line restatement of ``d500d329:src/routes/_scan_diff.py``; the
    unchanged helpers it calls are imported from production.
    """
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.scan import Scan
    from src.routes._scan_queries import _packages_by_scan_ids

    contributing_ids = [sbom_scan.id] if sbom_scan else []
    contributing_ids += [s.id for s in latest_tool.values()]
    contributing_ids = list(dict.fromkeys(contributing_ids))
    if not contributing_ids:
        return set()

    cache_key = None
    if _cache is not None:
        cache_key = frozenset(contributing_ids)
        cached = _cache.get(cache_key)
        if cached is not None:
            return cached

    tool_scan_ids = {s.id for s in latest_tool.values()}
    if _pkg_prefetch is not None:
        sbom_pkg_ids = _pkg_prefetch.get(sbom_scan.id, set()) if sbom_scan else set()
    else:
        sbom_pkg_ids = _packages_by_scan_ids([sbom_scan.id]).get(
            sbom_scan.id, set()
        ) if sbom_scan else set()

    result = set()
    if _obs_prefetch is not None:
        for sid in contributing_ids:
            for aid, pkg_id in _obs_prefetch.get(sid, ()):
                if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
                    continue
                result.add(aid)
    else:
        rows = db.session.execute(
            db.select(Assessment.id, Observation.scan_id, Finding.package_id)
            .select_from(Observation)
            .join(Finding, Finding.id == Observation.finding_id)
            .join(Assessment, Assessment.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(
                Observation.scan_id.in_(contributing_ids),
                Assessment.variant_id == Scan.variant_id,
                Assessment.origin.notin_(("custom", "ai")),
            )
        ).all()
        for aid, sid, pkg_id in rows:
            # Skip tool-scan assessments whose finding's package is not in SBOM
            if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
                continue
            result.add(aid)
    if _cache is not None:
        _cache[cache_key] = result
    return result


def _scalar_global_result_full(scan, all_variant_scans) -> dict:
    """The pre-PR-B shape of :func:`_global_result_full`.

    A line-for-line restatement of ``d500d329:src/routes/_scan_diff.py``; the
    unchanged helpers it calls are imported from production.
    """
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.routes._scan_diff import _contributing_scans_at
    from src.routes._scan_queries import _load_scan_with_findings, _TOOL_SOURCE_LABELS

    sbom_scan, latest_tool = _contributing_scans_at(scan, all_variant_scans)
    if sbom_scan is None:
        return {
            "scan_id": str(scan.id),
            "scan_type": scan.scan_type or "sbom",
            "packages": [], "findings": [], "vulnerabilities": [], "assessments": [],
            "package_count": 0, "finding_count": 0, "vuln_count": 0, "assessment_count": 0,
        }

    contributing_ids = [sbom_scan.id] + [
        s.id for s in latest_tool.values()
    ]
    contributing_ids = list(dict.fromkeys(contributing_ids))

    tool_scan_ids = {s.id for s in latest_tool.values()}

    # --- Packages (from SBOM only) ---
    pkg_rows = db.session.execute(
        db.select(
            Package.id, Package.name, Package.version, Package.supplier,
            SBOMDocument.source_name, SBOMDocument.format,
        )
        .join(SBOMPackage, SBOMPackage.package_id == Package.id)
        .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
        .where(SBOMDocument.scan_id == sbom_scan.id)
    ).all()
    pkg_map: dict = {}
    sbom_pkg_ids = set()
    for pid, pname, pversion, psupplier, src_name, src_fmt in pkg_rows:
        sbom_pkg_ids.add(pid)
        source_label = f"{src_name} ({src_fmt})" if src_fmt else src_name
        if pid not in pkg_map:
            pkg_map[pid] = {
                "package_id": str(pid),
                "package_name": pname or "unknown",
                "package_version": pversion or "",
                "package_supplier": psupplier or "",
                "sources": [source_label],
            }
        else:
            if source_label not in pkg_map[pid]["sources"]:
                pkg_map[pid]["sources"].append(source_label)
    packages = sorted(
        pkg_map.values(),
        key=lambda p: (p["package_name"], p["package_version"]),
    )

    # --- Build scan_id -> source_label mapping ---
    sbom_loaded = _load_scan_with_findings(sbom_scan.id)
    sbom_doc_names = []
    if sbom_loaded and hasattr(sbom_loaded, 'sbom_documents'):
        for doc in (sbom_loaded.sbom_documents or []):
            label = (
                f"{doc.source_name} ({doc.format})"
                if doc.format else doc.source_name
            )
            sbom_doc_names.append(label)
    sbom_source_label = ", ".join(sbom_doc_names) if sbom_doc_names else "SBOM Scan"

    scan_source_labels: dict = {sbom_scan.id: sbom_source_label}
    for tool_scan in latest_tool.values():
        scan_source_labels[tool_scan.id] = _TOOL_SOURCE_LABELS.get(
            tool_scan.scan_source or "", "Vulnerability Scan"
        )
    # --- Findings & vulns (batch query) ---
    obs_rows = db.session.execute(
        db.select(
            Observation.scan_id, Observation.finding_id,
            Finding.package_id, Finding.vulnerability_id,
            Package.name, Package.version, Package.supplier,
        )
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Package, Package.id == Finding.package_id)
        .where(Observation.scan_id.in_(contributing_ids))
    ).all()

    finding_map: dict = {}
    vuln_set: dict = {}
    for sid, fid, pkg_id, vid, pname, pversion, psupplier in obs_rows:
        # Skip tool-scan findings whose package is not in the SBOM
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        source_label = scan_source_labels.get(sid, "Unknown")
        if fid not in finding_map:
            finding_map[fid] = {
                "finding_id": str(fid),
                "package_name": pname or "unknown",
                "package_version": pversion or "",
                "package_supplier": psupplier or "",
                "package_id": str(pkg_id),
                "vulnerability_id": vid,
                "sources": [source_label],
            }
        else:
            if source_label not in finding_map[fid]["sources"]:
                finding_map[fid]["sources"].append(source_label)
        vuln_set.setdefault(vid, set()).add(source_label)

    findings = sorted(
        finding_map.values(),
        key=lambda f: (f["vulnerability_id"], f["package_name"]),
    )
    vulnerabilities = [
        {"vulnerability_id": vid, "sources": sorted(srcs)}
        for vid, srcs in sorted(vuln_set.items())
    ]

    # --- Assessments for active findings in this variant ---
    next_scan_ts = None
    for s in sorted(all_variant_scans, key=lambda s: s.timestamp):
        if s.timestamp > scan.timestamp:
            next_scan_ts = s.timestamp
            break

    assessments: list = []
    assess_q = (
        db.select(
            Assessment.id,
            Finding.vulnerability_id,
            Assessment.status,
            Assessment.simplified_status,
            Assessment.justification,
            Assessment.impact_statement,
            Assessment.status_notes,
            Observation.scan_id,
            Finding.package_id,
        )
        .select_from(Observation)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Assessment, Assessment.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Observation.scan_id.in_(contributing_ids),
            Assessment.variant_id == Scan.variant_id,
            Assessment.origin.notin_(("custom", "ai")),
        )
    )
    if next_scan_ts is not None:
        assess_q = assess_q.where(
            db.or_(Assessment.timestamp.is_(None), Assessment.timestamp < next_scan_ts)
        )
    assess_rows = db.session.execute(assess_q).all()

    seen_assess = set()
    for aid, vid, status, simp_status, justification, impact, notes, sid, pkg_id in assess_rows:
        # Skip tool-scan assessments whose finding's package is not in SBOM
        if sid in tool_scan_ids and pkg_id not in sbom_pkg_ids:
            continue
        if aid in seen_assess:
            continue
        seen_assess.add(aid)
        package = pkg_map.get(pkg_id, {})
        assessments.append({
            "vulnerability_id": vid,
            "status": status or "under_investigation",
            "simplified_status": simp_status or "Pending Assessment",
            "justification": justification or "",
            "impact_statement": impact or "",
            "status_notes": notes or "",
            "package_name": package.get("package_name", ""),
            "package_version": package.get("package_version", ""),
            "package_supplier": package.get("package_supplier", ""),
        })
    assessments.sort(key=lambda a: a["vulnerability_id"])

    return {
        "scan_id": str(scan.id),
        "scan_type": scan.scan_type or "sbom",
        "packages": packages,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "assessments": assessments,
        "package_count": len(packages),
        "finding_count": len(findings),
        "vuln_count": len(vulnerabilities),
        "assessment_count": len(assessments),
    }


def _assessment_with_target(variant_id, finding_id):
    """Return the single assessment whose one target row is (variant, finding)."""
    from src.extensions import db
    from src.models.assessment import Assessment

    matches = [
        a for a in db.session.query(Assessment).all()
        if a.targets == [(variant_id, finding_id)]
    ]
    assert len(matches) == 1
    return matches[0]


def _seed_two_variants(tag: str):
    """Seed two variants of one project, each with an SBOM scan observing the
    same two findings, and one ``sbom`` assessment per (variant, finding).

    Also seeds the two cases a target join has to keep excluding: an
    assessment targeting variant B on a finding only variant A observes, and
    a ``custom`` assessment.
    """
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.observation import Observation
    from src.models.scan import Scan

    project = uuid.uuid4()
    variant_a = _variant(project, "a")
    variant_b = _variant(project, "b")
    openssl = _finding(f"CVE-2026-{tag}", "openssl")
    zlib = _finding(f"CVE-2026-{tag}", "zlib")
    only_a = _finding(f"CVE-2026-{tag}", "busybox")

    scan_a = Scan.create("a.json", variant_a.id, scan_type="sbom")
    scan_b = Scan.create("b.json", variant_b.id, scan_type="sbom")
    for finding in (openssl, zlib, only_a):
        Observation.create(finding_id=finding.id, scan_id=scan_a.id, commit=False)
    for finding in (openssl, zlib):
        Observation.create(finding_id=finding.id, scan_id=scan_b.id, commit=False)
    db.session.commit()

    for variant, finding in (
        (variant_a, openssl), (variant_a, zlib),
        (variant_b, openssl), (variant_b, zlib),
    ):
        Assessment.create(
            status="not_affected", simplified_status="Not Affected", origin="sbom",
            targets=[(variant.id, finding.id)], commit=True,
        )
    # Targets variant B, but only variant A's scan observes this finding: the
    # scan-to-variant predicate must keep it out of both scans' rows.
    Assessment.create(
        status="affected", origin="sbom",
        targets=[(variant_b.id, only_a.id)], commit=True,
    )
    # Excluded from the diff query by the origin filter, not by the join.
    custom = Assessment.create(
        status="fixed", origin="custom",
        targets=[(variant_a.id, only_a.id)], commit=True,
    )
    return {
        "variant_a": variant_a, "variant_b": variant_b,
        "openssl": openssl, "zlib": zlib, "only_a": only_a,
        "scan_a": scan_a, "scan_b": scan_b, "custom": custom,
    }


def test_assessment_rows_for_scans_equals_the_scalar_read(app):
    """The target join returns exactly the rows the scalar predicate did."""
    with app.app_context():
        from src.routes._scan_queries import _assessment_rows_for_scans

        seeded = _seed_two_variants("5001")
        scan_ids = [seeded["scan_a"].id, seeded["scan_b"].id]

        joined = _assessment_rows_for_scans(scan_ids)
        scalar = _scalar_assessment_rows_for_scans(scan_ids)

        # 2 variants x 2 shared findings; the variant-B-on-busybox assessment
        # and nothing else is excluded by the scan-to-variant predicate.
        # ``custom`` has no origin filter in this query, so it is counted.
        assert len(joined) == 5
        assert sorted(map(tuple, joined)) == sorted(map(tuple, scalar))


def test_assessment_rows_for_scans_excludes_a_target_on_another_variant(app):
    """An assessment whose target names variant B never appears under
    variant A's scan, even though both scans observe the finding."""
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.routes._scan_queries import _assessment_rows_for_scans

        seeded = _seed_two_variants("5002")
        b_on_openssl = next(
            a for a in db.session.query(Assessment).all()
            if a.targets == [(seeded["variant_b"].id, seeded["openssl"].id)]
        )

        rows_a = _assessment_rows_for_scans([seeded["scan_a"].id])

        assert len(rows_a) == 3
        assert b_on_openssl.id not in {row[1] for row in rows_a}


def test_assessment_rows_for_scans_reaches_a_scalarless_assessment(app):
    """With the mirrored columns cleared, the target row alone still carries
    the assessment into the result — and the scalar read no longer can."""
    with app.app_context():
        from src.routes._scan_queries import _assessment_rows_for_scans

        seeded = _seed_two_variants("5003")
        rows_before = _assessment_rows_for_scans([seeded["scan_a"].id])
        assert len(rows_before) == 3
        stripped = rows_before[0][1]

        _strip_scalar_mirror(stripped)

        rows_after = _assessment_rows_for_scans([seeded["scan_a"].id])
        assert len(rows_after) == 3
        assert stripped in {row[1] for row in rows_after}
        assert stripped not in {
            row[1] for row in _scalar_assessment_rows_for_scans([seeded["scan_a"].id])
        }


def test_global_assessment_rows_by_scan_equals_the_scalar_read(app):
    """_scan_diff's batch query matches its scalar predecessor exactly, and
    still drops ``custom`` assessments."""
    with app.app_context():
        from src.routes._scan_diff import _global_assessment_rows_by_scan

        seeded = _seed_two_variants("5004")
        scan_ids = [seeded["scan_a"].id, seeded["scan_b"].id]

        joined = _global_assessment_rows_by_scan(scan_ids)
        scalar = _scalar_global_assessment_rows_by_scan(scan_ids)

        assert {k: sorted(v) for k, v in joined.items()} == {
            k: sorted(v) for k, v in scalar.items()
        }
        assert len(joined[seeded["scan_a"].id]) == 2
        assert len(joined[seeded["scan_b"].id]) == 2
        assert seeded["custom"].id not in {
            aid for rows in joined.values() for aid, _ in rows
        }


def test_global_assessment_rows_by_scan_reaches_a_scalarless_assessment(app):
    """The batch diff query reaches an assessment that has only a target row."""
    with app.app_context():
        from src.routes._scan_diff import _global_assessment_rows_by_scan

        seeded = _seed_two_variants("5005")
        rows_before = _global_assessment_rows_by_scan([seeded["scan_a"].id])
        assert len(rows_before[seeded["scan_a"].id]) == 2
        stripped = rows_before[seeded["scan_a"].id][0][0]

        _strip_scalar_mirror(stripped)

        rows_after = _global_assessment_rows_by_scan([seeded["scan_a"].id])
        assert len(rows_after[seeded["scan_a"].id]) == 2
        assert stripped in {aid for aid, _ in rows_after[seeded["scan_a"].id]}


def test_scan_helpers_existence_check_reaches_a_scalarless_assessment(app):
    """``create_observation_and_assessment`` must not add a second, pending
    assessment when the (variant, finding) pair is covered by a target row
    whose mirrored scalar columns are gone."""
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.scan import Scan
        from src.routes._scan_helpers import create_observation_and_assessment

        project = uuid.uuid4()
        variant = _variant(project, "a")
        openssl = _finding("CVE-2026-5006", "openssl")
        assessment = Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant.id, openssl.id)], commit=True,
        )
        _strip_scalar_mirror(assessment.id)
        scan = Scan.create("s.json", variant.id, scan_type="tool")

        create_observation_and_assessment(
            openssl, scan, variant.id, "grype", set(), set(),
        )
        db.session.commit()

        assert db.session.query(Assessment).count() == 1


def test_scan_helpers_existence_check_still_creates_when_uncovered(app):
    """The converse: an unassessed (variant, finding) pair still gets its
    pending assessment, so the join did not simply stop matching."""
    with app.app_context():
        from src.extensions import db
        from src.models.assessment import Assessment
        from src.models.scan import Scan
        from src.routes._scan_helpers import create_observation_and_assessment

        project = uuid.uuid4()
        variant_a = _variant(project, "a")
        variant_b = _variant(project, "b")
        openssl = _finding("CVE-2026-5007", "openssl")
        # Covers variant B only; variant A's scan must still be assessed.
        Assessment.create(
            status="not_affected", origin="custom",
            targets=[(variant_b.id, openssl.id)], commit=True,
        )
        scan = Scan.create("s.json", variant_a.id, scan_type="tool")

        create_observation_and_assessment(
            openssl, scan, variant_a.id, "grype", set(), set(),
        )
        db.session.commit()

        assert db.session.query(Assessment).count() == 2
        created = (
            db.session.query(Assessment)
            .filter(Assessment.status == "under_investigation")
            .one()
        )
        assert created.targets == [(variant_a.id, openssl.id)]


def test_untargeted_assessment_is_absent_from_both_reads(app):
    """The legacy variant-less custom-data import shape (NULL ``variant_id``,
    no target row) was already invisible to the scalar predicate — NULL never
    equals ``scan.variant_id`` — so the target join changes nothing for it."""
    with app.app_context():
        from src.models.assessment import Assessment
        from src.models.observation import Observation
        from src.models.scan import Scan
        from src.routes._scan_diff import _global_assessment_rows_by_scan
        from src.routes._scan_queries import _assessment_rows_for_scans

        project = uuid.uuid4()
        variant = _variant(project, "a")
        openssl = _finding("CVE-2026-5008", "openssl")
        scan = Scan.create("s.json", variant.id, scan_type="sbom")
        Observation.create(finding_id=openssl.id, scan_id=scan.id)
        untargeted = Assessment.create(
            status="not_affected", origin="sbom",
            targets=[], allow_untargeted=True, commit=True,
        )
        assert untargeted.target_rows == []
        assert untargeted.variant_id is None

        assert _assessment_rows_for_scans([scan.id]) == []
        assert _scalar_assessment_rows_for_scans([scan.id]) == []
        assert _global_assessment_rows_by_scan([scan.id]) == {}
        assert _scalar_global_assessment_rows_by_scan([scan.id]) == {}


def test_global_assessment_ids_for_equals_the_scalar_read(app):
    """The global-result ID query returns exactly the set the scalar
    predicate returned, for both variants' scans."""
    with app.app_context():
        from src.routes._scan_diff import _global_assessment_ids_for

        seeded = _seed_two_variants("5009")
        expected_a = {
            _assessment_with_target(seeded["variant_a"].id, seeded["openssl"].id).id,
            _assessment_with_target(seeded["variant_a"].id, seeded["zlib"].id).id,
        }

        joined_a = _global_assessment_ids_for(seeded["scan_a"], {})
        joined_b = _global_assessment_ids_for(seeded["scan_b"], {})

        assert joined_a == _scalar_global_assessment_ids_for(seeded["scan_a"], {})
        assert joined_b == _scalar_global_assessment_ids_for(seeded["scan_b"], {})
        assert len(joined_a) == 2
        assert len(joined_b) == 2
        assert joined_a == expected_a


def test_global_assessment_ids_for_excludes_other_variants_assessments(app):
    """Variant B's assessments never reach variant A's global result, even on
    findings both scans observe — the scan-to-variant predicate is what keeps
    them out, and its absence would inflate every scan's assessment count."""
    with app.app_context():
        from src.routes._scan_diff import (
            _global_assessment_count,
            _global_assessment_ids_for,
        )

        seeded = _seed_two_variants("5010")
        b_ids = {
            _assessment_with_target(seeded["variant_b"].id, seeded["openssl"].id).id,
            _assessment_with_target(seeded["variant_b"].id, seeded["zlib"].id).id,
            _assessment_with_target(seeded["variant_b"].id, seeded["only_a"].id).id,
        }

        ids_a = _global_assessment_ids_for(seeded["scan_a"], {})

        assert len(ids_a) == 2
        assert ids_a & b_ids == set()
        assert seeded["custom"].id not in ids_a
        assert _global_assessment_count(seeded["scan_a"], [seeded["scan_a"]]) == 2


def test_global_assessment_ids_for_reaches_a_scalarless_assessment(app):
    """With the mirrored columns cleared, the target row alone still carries
    the assessment into the global result — and the scalar read cannot."""
    with app.app_context():
        from src.routes._scan_diff import _global_assessment_ids_for

        seeded = _seed_two_variants("5011")
        stripped = _assessment_with_target(
            seeded["variant_a"].id, seeded["openssl"].id
        ).id

        _strip_scalar_mirror(stripped)

        ids_after = _global_assessment_ids_for(seeded["scan_a"], {})
        assert len(ids_after) == 2
        assert stripped in ids_after
        assert stripped not in _scalar_global_assessment_ids_for(seeded["scan_a"], {})


def test_global_result_full_equals_the_scalar_read(app):
    """The serialised global result is byte-identical to the one the scalar
    predicate produced, assessment list and count included."""
    with app.app_context():
        from src.routes._scan_diff import _global_result_full

        seeded = _seed_two_variants("5012")
        scan_a = seeded["scan_a"]

        joined = _global_result_full(scan_a, [scan_a])
        scalar = _scalar_global_result_full(scan_a, [scan_a])

        assert joined == scalar
        assert joined["assessment_count"] == 2
        assert len(joined["assessments"]) == 2


def test_global_result_full_excludes_other_variants_assessments(app):
    """Variant B's judgements must not appear in variant A's scan result.

    Both scans observe openssl and zlib, so only the scan-to-variant
    predicate separates them; without it the modal would show five
    assessments instead of two.
    """
    with app.app_context():
        from src.routes._scan_diff import _global_result_full

        seeded = _seed_two_variants("5013")
        scan_a = seeded["scan_a"]

        result = _global_result_full(scan_a, [scan_a])

        assert result["assessment_count"] == 2
        assert sorted(a["status"] for a in result["assessments"]) == [
            "not_affected", "not_affected",
        ]
        # variant B's only_a assessment is "affected"; its openssl/zlib ones
        # are "not_affected" too, so the count above is the discriminator.
        assert "affected" not in {a["status"] for a in result["assessments"]}
        assert "fixed" not in {a["status"] for a in result["assessments"]}


def test_global_result_full_reaches_a_scalarless_assessment(app):
    """The scan-result query reaches an assessment that has only a target
    row, and the scalar read no longer does."""
    with app.app_context():
        from src.routes._scan_diff import _global_result_full

        seeded = _seed_two_variants("5014")
        scan_a = seeded["scan_a"]
        stripped = _assessment_with_target(
            seeded["variant_a"].id, seeded["openssl"].id
        ).id

        _strip_scalar_mirror(stripped)

        joined = _global_result_full(scan_a, [scan_a])
        scalar = _scalar_global_result_full(scan_a, [scan_a])

        assert joined["assessment_count"] == 2
        assert scalar["assessment_count"] == 1
