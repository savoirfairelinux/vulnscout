# -*- coding: utf-8 -*-
from ..models.assessment import VulnAssessment
from ..models.vulnerability import Vulnerability
from ..models.package import Package


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

    def get_by_id(self, assess_id: str) -> VulnAssessment:
        """Return an assessment by id (str) or None if not found."""
        if assess_id in self.assessments:
            return self.assessments[assess_id]

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
            return [a for a in self.assessments.values() if pkg_id.id in a.packages]
        return []

    def gets_by_vuln_pkg(self, vuln_id, pkg_id) -> list:
        """Return a list of assessments by vulnerability id (str) and package id (str)."""
        vuln_str = vuln_id if isinstance(vuln_id, str) else vuln_id.id
        pkg_str = pkg_id if isinstance(pkg_id, str) else pkg_id.id
        return [a for a in self.assessments.values() if a.vuln_id == vuln_str and pkg_str in a.packages]

    def add(self, assessment: VulnAssessment):
        """Add an assessment to the list, merging it with an existing one if present."""
        if assessment is None:
            return
        if assessment.id not in self.assessments:
            self.assessments[assessment.id] = assessment
        else:
            self.assessments[assessment.id].merge(assessment)

    def remove(self, assess_id: str) -> bool:
        """Remove an assessment by id (str) and return True if removed, False if not found."""
        if assess_id in self.assessments:
            del self.assessments[assess_id]
            return True
        return False

    def to_dict(self) -> dict:
        """Return a dictionary representation of the assessments."""
        return {k: v.to_dict() for k, v in self.assessments.items()}

    @staticmethod
    def from_dict(pkgCtrl, vulnCtrl, data: dict):
        """Return a new instance of AssessmentsController from a dictionary."""
        item = AssessmentsController(pkgCtrl, vulnCtrl)
        for k, v in data.items():
            item.add(VulnAssessment.from_dict(v))
        return item

    def __contains__(self, item) -> bool:
        """Check if an item (str or VulnAssessment) is in the list of assessments."""
        if isinstance(item, str):
            return item in self.assessments
        elif isinstance(item, VulnAssessment):
            return item.id in self.assessments
        return False

    def __len__(self) -> int:
        """Return the number of assessments in the list."""
        return len(self.assessments)

    def __iter__(self):
        """Allow iteration over the list of assessments."""
        return iter(self.assessments.values())
