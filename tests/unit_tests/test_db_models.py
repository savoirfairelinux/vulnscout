# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Simple coverage tests for Project/Variant/Scan/SBOMDocument models and controllers."""

import pytest
from src.bin.webapp import create_app
from src.extensions import db as _db
from src.models.project import Project
from src.models.variant import Variant
from src.models.scan import Scan
from src.models.sbom_document import SBOMDocument
from src.controllers.projects import ProjectController
from src.controllers.variants import VariantController
from src.controllers.scans import ScanController
from src.controllers.sbom_documents import SBOMDocumentController


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": "/dev/null",
        })
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def project(app):
    return Project.create("TestProject")


@pytest.fixture()
def variant(app, project):
    return Variant.create("TestVariant", project.id)


@pytest.fixture()
def scan(app, variant):
    return Scan.create("initial scan", variant.id)


@pytest.fixture()
def document(app, scan):
    return SBOMDocument.create("/path/to/sbom.spdx", "spdx-source", scan.id)


# ===========================================================================
# Project model
# ===========================================================================

class TestProjectModel:
    def test_create_and_get(self, app):
        p = Project.create("Alpha")
        assert p.id is not None
        assert Project.get_by_id(p.id) == p

    def test_get_all(self, app):
        Project.create("B")
        Project.create("A")
        names = [p.name for p in Project.get_all()]
        assert names == sorted(names)

    def test_get_or_create_existing(self, app):
        p1 = Project.create("Existing")
        p2 = Project.get_or_create("Existing")
        assert p1.id == p2.id

    def test_get_or_create_new(self, app):
        p = Project.get_or_create("Brand New")
        assert p.name == "Brand New"

    def test_unique_constraint_raises_on_duplicate_name(self, app):
        """Direct double-INSERT must be rejected by the unique constraint."""
        from sqlalchemy.exc import IntegrityError
        Project.create("DupeName")
        with pytest.raises(IntegrityError):
            Project.create("DupeName")

    def test_get_or_create_recovers_from_concurrent_insert(self, app):
        """
        Simulate a concurrent INSERT race: the initial SELECT inside
        get_or_create returns nothing (as if it ran before a concurrent
        commit), but the subsequent INSERT hits the unique constraint.
        get_or_create must catch the IntegrityError and re-fetch the winner's
        row instead of propagating the error.
        """
        from unittest.mock import patch, MagicMock

        winner = Project.create("RaceProject")
        real_execute = _db.session.execute

        call_count = [0]

        def fake_execute(stmt, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Pretend the initial guard SELECT found nothing.
                m = MagicMock()
                m.scalar_one_or_none.return_value = None
                return m
            # All subsequent calls (re-SELECT after rollback) are real.
            return real_execute(stmt, *args, **kwargs)

        with patch("src.models.project.db.session.execute", side_effect=fake_execute):
            result = Project.get_or_create("RaceProject")

        assert result.id == winner.id

    def test_update(self, project):
        project.update("Renamed")
        assert project.name == "Renamed"

    def test_delete(self, app):
        p = Project.create("ToDelete")
        pid = p.id
        p.delete()
        assert Project.get_by_id(pid) is None

    def test_repr(self, project):
        assert "TestProject" in repr(project)

    def test_get_by_id_missing(self, app):
        import uuid
        assert Project.get_by_id(uuid.uuid4()) is None


# ===========================================================================
# Variant model
# ===========================================================================

class TestVariantModel:
    def test_create_and_get(self, project):
        v = Variant.create("v1", project.id)
        assert Variant.get_by_id(v.id) == v

    def test_get_all(self, project):
        Variant.create("Z", project.id)
        Variant.create("A", project.id)
        names = [v.name for v in Variant.get_all()]
        assert names == sorted(names)

    def test_get_by_project(self, project):
        Variant.create("x", project.id)
        Variant.create("y", project.id)
        variants = Variant.get_by_project(project.id)
        assert all(v.project_id == project.id for v in variants)

    def test_get_or_create_existing(self, variant):
        v2 = Variant.get_or_create(variant.name, variant.project_id)
        assert v2.id == variant.id

    def test_get_or_create_new(self, project):
        v = Variant.get_or_create("NewVariant", project.id)
        assert v.name == "NewVariant"

    def test_unique_constraint_raises_on_duplicate_name_and_project(self, project):
        """Direct double-INSERT for the same (name, project_id) must fail."""
        from sqlalchemy.exc import IntegrityError
        Variant.create("DupeVariant", project.id)
        with pytest.raises(IntegrityError):
            Variant.create("DupeVariant", project.id)

    def test_same_name_allowed_across_projects(self, app):
        """The same variant name is allowed under different projects."""
        p1 = Project.create("Proj1")
        p2 = Project.create("Proj2")
        v1 = Variant.create("shared-name", p1.id)
        v2 = Variant.create("shared-name", p2.id)
        assert v1.id != v2.id

    def test_get_or_create_recovers_from_concurrent_insert(self, project):
        """
        Simulate a race: the initial SELECT inside Variant.get_or_create
        returns nothing, but the subsequent INSERT hits the unique constraint.
        get_or_create must catch the IntegrityError and return the existing row.
        """
        from unittest.mock import patch, MagicMock

        winner = Variant.create("RaceVariant", project.id)
        real_execute = _db.session.execute

        call_count = [0]

        def fake_execute(stmt, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                m = MagicMock()
                m.scalar_one_or_none.return_value = None
                return m
            return real_execute(stmt, *args, **kwargs)

        with patch("src.models.variant.db.session.execute", side_effect=fake_execute):
            result = Variant.get_or_create("RaceVariant", project.id)

        assert result.id == winner.id

    def test_update(self, variant):
        variant.update("Updated")
        assert variant.name == "Updated"

    def test_delete(self, project):
        v = Variant.create("Del", project.id)
        vid = v.id
        v.delete()
        assert Variant.get_by_id(vid) is None

    def test_repr(self, variant):
        assert "TestVariant" in repr(variant)


# ===========================================================================
# Scan model
# ===========================================================================

class TestScanModel:
    def test_create_and_get(self, variant):
        s = Scan.create("desc", variant.id)
        assert Scan.get_by_id(s.id) == s

    def test_get_all(self, variant):
        Scan.create("s1", variant.id)
        Scan.create("s2", variant.id)
        assert len(Scan.get_all()) >= 2

    def test_get_by_variant(self, variant):
        Scan.create("scan-a", variant.id)
        scans = Scan.get_by_variant_id(variant.id)
        assert all(s.variant_id == variant.id for s in scans)

    def test_get_by_project(self, project, variant):
        Scan.create("proj-scan", variant.id)
        scans = Scan.get_by_project(project.id)
        assert len(scans) >= 1

    def test_update(self, scan):
        scan.update("updated description")
        assert scan.description == "updated description"

    def test_delete(self, variant):
        s = Scan.create("del", variant.id)
        sid = s.id
        s.delete()
        assert Scan.get_by_id(sid) is None

    def test_repr(self, scan):
        assert "Scan" in repr(scan)

    def test_timestamp_set(self, scan):
        assert scan.timestamp is not None


# ===========================================================================
# SBOMDocument model
# ===========================================================================

class TestSBOMDocumentModel:
    def test_create_and_get(self, scan):
        d = SBOMDocument.create("/a/b.spdx", "src", scan.id)
        assert SBOMDocument.get_by_id(d.id) == d

    def test_get_all(self, scan):
        SBOMDocument.create("/z.spdx", "s1", scan.id)
        SBOMDocument.create("/a.spdx", "s2", scan.id)
        paths = [d.path for d in SBOMDocument.get_all()]
        assert paths == sorted(paths)

    def test_get_by_scan(self, scan):
        SBOMDocument.create("/scan-doc.spdx", "src", scan.id)
        docs = SBOMDocument.get_by_scan(scan.id)
        assert all(d.scan_id == scan.id for d in docs)

    def test_get_by_variant(self, variant, scan):
        SBOMDocument.create("/v.spdx", "src", scan.id)
        docs = SBOMDocument.get_by_variant(variant.id)
        assert len(docs) >= 1

    def test_get_by_project(self, project, variant, scan):
        SBOMDocument.create("/p.spdx", "src", scan.id)
        docs = SBOMDocument.get_by_project(project.id)
        assert len(docs) >= 1

    def test_update(self, document):
        document.update("/new/path.spdx", "new-source")
        assert document.path == "/new/path.spdx"
        assert document.source_name == "new-source"

    def test_delete(self, scan):
        d = SBOMDocument.create("/del.spdx", "src", scan.id)
        did = d.id
        d.delete()
        assert SBOMDocument.get_by_id(did) is None

    def test_repr(self, document):
        assert "SBOMDocument" in repr(document)


# ===========================================================================
# ProjectController
# ===========================================================================

class TestProjectController:
    def test_serialize(self, project):
        data = ProjectController.serialize(project)
        assert data["name"] == "TestProject"
        assert "id" in data

    def test_serialize_list(self, project):
        lst = ProjectController.serialize_list([project])
        assert len(lst) == 1

    def test_get(self, project):
        assert ProjectController.get(str(project.id)).id == project.id

    def test_get_all(self, project):
        assert len(ProjectController.get_all()) >= 1

    def test_create(self, app):
        p = ProjectController.create("  New  ")
        assert p.name == "New"

    def test_create_empty_raises(self, app):
        with pytest.raises(ValueError):
            ProjectController.create("   ")

    def test_get_or_create(self, project):
        p2 = ProjectController.get_or_create(project.name)
        assert p2.id == project.id

    def test_get_or_create_empty_raises(self, app):
        with pytest.raises(ValueError):
            ProjectController.get_or_create("")

    def test_update_by_id(self, project):
        ProjectController.update(str(project.id), "Changed")
        assert project.name == "Changed"

    def test_update_empty_raises(self, project):
        with pytest.raises(ValueError):
            ProjectController.update(project, "")

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            ProjectController.update(str(uuid.uuid4()), "X")

    def test_delete_by_instance(self, app):
        p = ProjectController.create("DelMe")
        pid = p.id
        ProjectController.delete(p)
        assert ProjectController.get(pid) is None

    def test_delete_by_id(self, app):
        p = ProjectController.create("DelMe2")
        pid = str(p.id)
        ProjectController.delete(pid)
        assert ProjectController.get(pid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            ProjectController.delete(str(uuid.uuid4()))


# ===========================================================================
# VariantController
# ===========================================================================

class TestVariantController:
    def test_serialize(self, variant):
        data = VariantController.serialize(variant)
        assert data["name"] == "TestVariant"
        assert "project_id" in data

    def test_serialize_list(self, variant):
        lst = VariantController.serialize_list([variant])
        assert len(lst) == 1

    def test_get(self, variant):
        assert VariantController.get(str(variant.id)).id == variant.id

    def test_get_all(self, variant):
        assert len(VariantController.get_all()) >= 1

    def test_get_by_project(self, project, variant):
        variants = VariantController.get_by_project(str(project.id))
        assert any(v.id == variant.id for v in variants)

    def test_create(self, project):
        v = VariantController.create("  NewV  ", str(project.id))
        assert v.name == "NewV"

    def test_create_empty_raises(self, project):
        with pytest.raises(ValueError):
            VariantController.create("", str(project.id))

    def test_get_or_create(self, variant):
        v2 = VariantController.get_or_create(variant.name, str(variant.project_id))
        assert v2.id == variant.id

    def test_get_or_create_empty_raises(self, project):
        with pytest.raises(ValueError):
            VariantController.get_or_create("  ", str(project.id))

    def test_update_by_instance(self, variant):
        VariantController.update(variant, "UPD")
        assert variant.name == "UPD"

    def test_update_empty_raises(self, variant):
        with pytest.raises(ValueError):
            VariantController.update(variant, "")

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            VariantController.update(str(uuid.uuid4()), "X")

    def test_delete_by_instance(self, project):
        v = VariantController.create("DelV", str(project.id))
        vid = v.id
        VariantController.delete(v)
        assert VariantController.get(vid) is None

    def test_delete_by_id(self, project):
        v = VariantController.create("DelV2", str(project.id))
        vid = str(v.id)
        VariantController.delete(vid)
        assert VariantController.get(vid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            VariantController.delete(str(uuid.uuid4()))


# ===========================================================================
# ScanController
# ===========================================================================

class TestScanController:
    def test_serialize(self, scan):
        data = ScanController.serialize(scan)
        assert data["description"] == "initial scan"
        assert "timestamp" in data
        assert "variant_id" in data

    def test_serialize_list(self, scan):
        lst = ScanController.serialize_list([scan])
        assert len(lst) == 1

    def test_get(self, scan):
        assert ScanController.get(str(scan.id)).id == scan.id

    def test_get_all(self, scan):
        assert len(ScanController.get_all()) >= 1

    def test_get_by_variant(self, variant, scan):
        scans = ScanController.get_by_variant(str(variant.id))
        assert any(s.id == scan.id for s in scans)

    def test_get_by_project(self, project, variant, scan):
        scans = ScanController.get_by_project(str(project.id))
        assert any(s.id == scan.id for s in scans)

    def test_create(self, variant):
        s = ScanController.create("desc", str(variant.id))
        assert s.description == "desc"

    def test_update_by_instance(self, scan):
        ScanController.update(scan, "new desc")
        assert scan.description == "new desc"

    def test_update_by_id(self, scan):
        ScanController.update(str(scan.id), "by id")
        assert scan.description == "by id"

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            ScanController.update(str(uuid.uuid4()), "X")

    def test_delete_by_instance(self, variant):
        s = ScanController.create("del", str(variant.id))
        sid = s.id
        ScanController.delete(s)
        assert ScanController.get(sid) is None

    def test_delete_by_id(self, variant):
        s = ScanController.create("del2", str(variant.id))
        sid = str(s.id)
        ScanController.delete(sid)
        assert ScanController.get(sid) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            ScanController.delete(str(uuid.uuid4()))


# ===========================================================================
# SBOMDocumentController
# ===========================================================================

class TestSBOMDocumentController:
    def test_serialize(self, document):
        data = SBOMDocumentController.serialize(document)
        assert data["path"] == "/path/to/sbom.spdx"
        assert data["source_name"] == "spdx-source"
        assert "scan_id" in data

    def test_serialize_list(self, document):
        lst = SBOMDocumentController.serialize_list([document])
        assert len(lst) == 1

    def test_get(self, document):
        assert SBOMDocumentController.get(str(document.id)).id == document.id

    def test_get_all(self, document):
        assert len(SBOMDocumentController.get_all()) >= 1

    def test_get_by_scan(self, scan, document):
        docs = SBOMDocumentController.get_by_scan(str(scan.id))
        assert any(d.id == document.id for d in docs)

    def test_get_by_variant(self, variant, document):
        docs = SBOMDocumentController.get_by_variant(str(variant.id))
        assert any(d.id == document.id for d in docs)

    def test_get_by_project(self, project, document):
        docs = SBOMDocumentController.get_by_project(str(project.id))
        assert any(d.id == document.id for d in docs)

    def test_create(self, scan):
        d = SBOMDocumentController.create("/new.spdx", "src", str(scan.id))
        assert d.path == "/new.spdx"

    def test_create_empty_path_raises(self, scan):
        with pytest.raises(ValueError):
            SBOMDocumentController.create("  ", "src", str(scan.id))

    def test_create_empty_source_raises(self, scan):
        with pytest.raises(ValueError):
            SBOMDocumentController.create("/p.spdx", "", str(scan.id))

    def test_update_by_instance(self, document):
        SBOMDocumentController.update(document, "/updated.spdx", "new-src")
        assert document.path == "/updated.spdx"

    def test_update_by_id(self, document):
        SBOMDocumentController.update(str(document.id), "/by-id.spdx", "s")
        assert document.path == "/by-id.spdx"

    def test_update_empty_path_raises(self, document):
        with pytest.raises(ValueError):
            SBOMDocumentController.update(document, "", "src")

    def test_update_empty_source_raises(self, document):
        with pytest.raises(ValueError):
            SBOMDocumentController.update(document, "/p.spdx", "  ")

    def test_update_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            SBOMDocumentController.update(str(uuid.uuid4()), "/x", "s")

    def test_delete_by_instance(self, scan):
        d = SBOMDocumentController.create("/del.spdx", "s", str(scan.id))
        did = d.id
        SBOMDocumentController.delete(d)
        assert SBOMDocumentController.get(did) is None

    def test_delete_by_id(self, scan):
        d = SBOMDocumentController.create("/del2.spdx", "s", str(scan.id))
        did = str(d.id)
        SBOMDocumentController.delete(did)
        assert SBOMDocumentController.get(did) is None

    def test_delete_not_found_raises(self, app):
        import uuid
        with pytest.raises(ValueError):
            SBOMDocumentController.delete(str(uuid.uuid4()))


# ===========================================================================
# Observation model
# ===========================================================================

class TestObservationModel:
    def test_create_with_str_ids_and_flush(self, app, scan):
        """Observation.create with string UUID arguments (lines 42, 44) and commit=False (line 50)."""
        from src.models.observation import Observation
        from src.models.finding import Finding
        from src.models.vulnerability import Vulnerability as VulnModel
        from src.models.package import Package as PkgModel

        pkg = PkgModel.create("obs-test-pkg", "1.0")
        vuln = VulnModel.create_record("CVE-OBS-TEST-1")
        finding = Finding.get_or_create(pkg.id, vuln.id)

        # str UUIDs trigger lines 42 and 44
        obs1 = Observation.create(str(finding.id), str(scan.id))
        assert obs1.finding_id == finding.id
        assert obs1.scan_id == scan.id


# ===========================================================================
# Metrics model
# ===========================================================================

class TestMetricsModel:
    def test_get_by_vulnerability(self, app):
        """Metrics.get_by_vulnerability returns list (line 62)."""
        from src.models.metrics import Metrics
        from src.models.vulnerability import Vulnerability as VulnModel

        VulnModel.create_record("CVE-METRICS-1")
        results = Metrics.get_by_vulnerability("CVE-METRICS-1")
        assert isinstance(results, list)
        assert len(results) == 0  # no metrics created yet

    def test_update_and_delete(self, app):
        """Metrics.update (line 81) and .delete (line 85)."""
        from src.models.metrics import Metrics
        from src.models.vulnerability import Vulnerability as VulnModel

        VulnModel.create_record("CVE-METRICS-2")
        m = Metrics.create("CVE-METRICS-2", version="3.1", score=7.5,
                           vector="AV:N/AC:L", author="tester")
        m.update(score=8.0, vector="AV:N/AC:H", author="updated")
        assert float(m.score) == 8.0
        assert m.vector == "AV:N/AC:H"

        mid = m.id
        m.delete()
        assert Metrics.get_by_id(mid) is None

    def test_from_cvss_dedup_cache_hit(self, app):
        """Second call with same CVSS hits _seen cache and returns None (line 103)."""
        from src.models.metrics import Metrics
        from src.models.cvss import CVSS
        from src.models.vulnerability import Vulnerability as VulnModel

        VulnModel.create_record("CVE-METRICS-3")
        Metrics.reset_cache()
        cvss = CVSS("3.1",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "auto", 9.8, 0.0, 0.0)
        m1 = Metrics.from_cvss(cvss, "CVE-METRICS-3")
        m2 = Metrics.from_cvss(cvss, "CVE-METRICS-3")  # dedup cache hit
        assert m1 is not None
        assert m2 is None  # returned None due to _seen dedup


# ===========================================================================
# batch_session edge cases
# ===========================================================================

def test_batch_session_without_app_context():
    """batch_session yields None when there is no Flask app context (lines 40-43)."""
    from src.extensions import batch_session
    # No 'app' fixture here — no Flask context is active
    with batch_session() as session:
        assert session is None


def test_batch_session_exception_propagates(app):
    """batch_session re-raises an exception raised inside the block (lines 52-57)."""
    from src.extensions import batch_session

    with pytest.raises(ValueError, match="test error"):
        with batch_session():
            raise ValueError("test error")
