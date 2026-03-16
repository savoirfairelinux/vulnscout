# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.assessment import Assessment
from ..models.vulnerability import Vulnerability
from ..models.package import Package
from typing import Optional


def _persist_assessment_to_db(assessment: Assessment) -> None:
    """Silently persist an Assessment DTO to the DB."""
    try:
        from ..models.assessment import Assessment as DBAssessment
        from ..models.finding import Finding

        for pkg_string_id in (assessment.packages or []):
            db_pkg = Package.get_by_string_id(pkg_string_id)
            if db_pkg is None:
                continue
            finding = Finding.get_by_package_and_vulnerability(db_pkg.id, assessment.vuln_id)
            if finding is None:
                continue
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
        """Return a list of assessments by vulnerability id (str) or Vulnerability instance."""
        if isinstance(vuln_id, str):
            return [a for a in self.assessments.values() if a.vuln_id == vuln_id]
        if isinstance(vuln_id, Vulnerability):
            return [a for a in self.assessments.values() if a.vuln_id == vuln_id.id]
        return []

    def gets_by_pkg(self, pkg_id) -> list:
        """Return a list of assessments by package id (str) or Package instance."""
        if isinstance(pkg_id, str):
            return [a for a in self.assessments.values() if pkg_id in a.packages]
        if isinstance(pkg_id, Package):
            return [a for a in self.assessments.values() if pkg_id.string_id in a.packages]
        return []

    def gets_by_vuln_pkg(self, vuln_id, pkg_id) -> list:
        """Return a list of assessments by vulnerability id (str) and package id (str)."""
        vuln_str = vuln_id if isinstance(vuln_id, str) else vuln_id.id
        pkg_str = pkg_id if isinstance(pkg_id, str) else pkg_id.string_id
        return [a for a in self.assessments.values() if a.vuln_id == vuln_str and pkg_str in a.packages]

    def add(self, assessment: Assessment):
        """Add an assessment to the list, merging it with an existing one if present, and persist to DB."""
        if assessment is None:
            return
        key = str(assessment.id)
        if key not in self.assessments:
            self.assessments[key] = assessment
        else:
            self.assessments[key].merge(assessment)
        _persist_assessment_to_db(self.assessments[key])

    def remove(self, assess_id) -> bool:
        """Remove an assessment by id (str or UUID) and return True if removed, False if not found."""
        key = str(assess_id) if assess_id is not None else None
        if key in self.assessments:
            del self.assessments[key]
            return True
        return False

    def to_dict(self) -> dict:
        """Return all assessments preferring the DB as source of truth."""
        try:
            from ..models.assessment import Assessment as DBAssessment
            return {str(a.id): a.to_dict() for a in DBAssessment.get_all()}
        except Exception:
            return {k: v.to_dict() for k, v in self.assessments.items()}

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
