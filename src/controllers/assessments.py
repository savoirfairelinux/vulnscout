# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.assessment import Assessment
from ..models.package import Package
from typing import Optional


def _persist_assessment_to_db(assessment: Assessment, pkg_id_cache=None, finding_cache=None) -> None:
    """Persist an Assessment DTO to the DB via Finding resolution.

    Uses a SAVEPOINT so that a failure only rolls back this single
    assessment instead of the whole ``batch_session()`` transaction.

    *pkg_id_cache* and *finding_cache* are optional dicts from
    ``PackagesController`` that avoid redundant SELECT queries.
    """
    if pkg_id_cache is None:
        pkg_id_cache = {}
    if finding_cache is None:
        finding_cache = {}
    try:
        from ..extensions import db
        from ..models.assessment import Assessment as DBAssessment
        from ..models.finding import Finding

        with db.session.begin_nested():
            for pkg_string_id in (assessment.packages or []):
                # Resolve package UUID from cache first
                pkg_uuid = pkg_id_cache.get(pkg_string_id)
                if pkg_uuid is None:
                    db_pkg = Package.get_by_string_id(pkg_string_id)
                    if db_pkg is None:
                        continue
                    pkg_uuid = db_pkg.id
                    pkg_id_cache[pkg_string_id] = pkg_uuid
                else:
                    db_pkg = None  # not needed if we have the UUID

                # Resolve Finding from cache first
                cache_key = (pkg_uuid, assessment.vuln_id)
                finding = finding_cache.get(cache_key)
                if finding is None:
                    finding = Finding.get_or_create(pkg_uuid, assessment.vuln_id)
                    finding_cache[cache_key] = finding

                DBAssessment.from_vuln_assessment(assessment, finding_id=finding.id)
    except Exception:
        pass


class AssessmentsController:
    """
    A class to handle a list of assessments, de-duplicating them and handling low-level stuff.
    Assessments can be added, removed, retrieved and exported or imported as dictionaries.
    """

    def __init__(self, pkgCtrl, vulnCtrl):
        """
        Take an instance of PackagesController and VulnerabilitiesController.
        They are used to resolve package and vulnerabilities by their id.
        """
        self.packagesCtrl = pkgCtrl
        self.vulnerabilitiesCtrl = vulnCtrl
        self.assessments = {}
        """A dictionary of assessments, indexed by their id."""

    def get_by_id(self, assess_id) -> Optional[Assessment]:
        """Return an assessment by id (str or UUID) or None if not found."""
        key = str(assess_id) if assess_id is not None else None
        if key in self.assessments:
            return self.assessments[key]
        return None

    def gets_by_vuln(self, vuln_id) -> list:
        """Return assessments for a vulnerability, querying DB then supplementing with in-memory."""
        if vuln_id is None:
            return []
        vuln_str = vuln_id if isinstance(vuln_id, str) else vuln_id.id
        results: dict[str, Assessment] = {}
        # In-memory first (covers partially-parsed data not yet in DB)
        for a in self.assessments.values():
            if a.vuln_id == vuln_str:
                results[str(a.id)] = a
        # DB fills any gaps (covers routes context where in-memory is empty)
        try:
            for a in Assessment.get_by_vulnerability(vuln_str):
                if str(a.id) not in results:
                    results[str(a.id)] = a
        except Exception:
            pass
        return list(results.values())

    def gets_by_pkg(self, pkg_id) -> list:
        """Return assessments for a package, querying DB then supplementing with in-memory."""
        if pkg_id is None:
            return []
        pkg_str = pkg_id if isinstance(pkg_id, str) else pkg_id.string_id
        results: dict[str, Assessment] = {}
        for a in self.assessments.values():
            if pkg_str in a.packages:
                results[str(a.id)] = a
        try:
            for a in Assessment.get_by_package(pkg_str):
                if str(a.id) not in results:
                    results[str(a.id)] = a
        except Exception:
            pass
        return list(results.values())

    def gets_by_vuln_pkg(self, vuln_id, pkg_id) -> list:
        """Return assessments for a (vulnerability, package) pair, querying DB then in-memory."""
        vuln_str = vuln_id if isinstance(vuln_id, str) else vuln_id.id
        pkg_str = pkg_id if isinstance(pkg_id, str) else pkg_id.string_id
        results: dict[str, Assessment] = {}
        for a in self.assessments.values():
            if a.vuln_id == vuln_str and pkg_str in a.packages:
                results[str(a.id)] = a
        try:
            from ..models.finding import Finding
            finding = Finding.get_by_package_and_vulnerability(pkg_str, vuln_str)
            if finding is not None:
                for a in Assessment.get_by_finding(finding.id):
                    if str(a.id) not in results:
                        results[str(a.id)] = a
        except Exception:
            pass
        return list(results.values())

    def add(self, assessment: Assessment):
        """Add an assessment to the list, merging it with an existing one if present, and persist to DB."""
        if assessment is None:
            return
        key = str(assessment.id)
        if key not in self.assessments:
            self.assessments[key] = assessment
        else:
            self.assessments[key].merge(assessment)
        _persist_assessment_to_db(
            self.assessments[key],
            pkg_id_cache=getattr(self.packagesCtrl, '_db_id_cache', None),
            finding_cache=getattr(self.packagesCtrl, '_finding_cache', None),
        )

    def remove(self, assess_id) -> bool:
        """Remove an assessment by id (str or UUID) and return True if removed, False if not found."""
        key = str(assess_id) if assess_id is not None else None
        if key in self.assessments:
            del self.assessments[key]
            return True
        return False

    def to_dict(self) -> dict:
        """Return all assessments preferring in-memory data when available."""
        if self.assessments:
            return {k: v.to_dict() for k, v in self.assessments.items()}
        try:
            from ..models.assessment import Assessment as DBAssessment
            return {str(a.id): a.to_dict() for a in DBAssessment.get_all()}
        except Exception:
            return {}

    @staticmethod
    def from_dict(pkgCtrl, vulnCtrl, data: dict):
        """Return a new instance of AssessmentsController from a dictionary."""
        item = AssessmentsController(pkgCtrl, vulnCtrl)
        for k, v in data.items():
            item.add(Assessment.from_dict(v))
        return item

    def __contains__(self, item) -> bool:
        """Check if an item (str or Assessment) is in the list of assessments."""
        if isinstance(item, str):
            return item in self.assessments
        elif isinstance(item, Assessment):
            return str(item.id) in self.assessments
        return False

    def __len__(self) -> int:
        """Return the number of assessments in the list."""
        return len(self.assessments)

    def __iter__(self):
        """Allow iteration over the list of assessments."""
        return iter(self.assessments.values())
