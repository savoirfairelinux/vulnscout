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
