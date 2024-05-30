# -*- coding: utf-8 -*-
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import VulnAssessment
from ..models.cvss import CVSS


class YoctoVulns:
    """GrypeVulns class to handle grype vulnerabilities and parse it"""
    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    def load_from_dict(self, data: dict):
        """Load the yoctoVulns object from a dictionary."""

        for pkg in data.get("package", []):
            if "name" not in pkg or "version" not in pkg:
                continue

            package = Package(pkg["name"], pkg["version"])
            package.generate_generic_cpe()
            package.generate_generic_purl()
            self.packagesCtrl.add(package)

            for issue in pkg.get("issue", []):

                vuln = Vulnerability(
                    issue.get("id").upper(),
                    "yocto",
                    issue.get("link", ""),
                    "other"
                )
                if "link" in issue:
                    vuln.add_url(issue.get("link"))
                if "summary" in issue:
                    vuln.add_text(issue.get("summary"), "summary")

                if "scorev3" in issue and issue["scorev3"] != "0.0":
                    cvss_item = CVSS(
                        "3.1",
                        "",
                        "unknown",
                        float(issue.get("scorev3")),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss_item)
                if "scorev2" in issue and issue["scorev2"] != "0.0":
                    cvss_item = CVSS(
                        "2.0",
                        "",
                        "unknown",
                        float(issue.get("scorev2")),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss_item)

                vuln.add_package(package.id)
                self.vulnerabilitiesCtrl.add(vuln)

                assessment = self.assessmentsCtrl.gets_by_vuln_pkg(vuln.id, package.id)
                if len(assessment) >= 1:
                    assessment = assessment[0]
                else:
                    assessment = VulnAssessment(vuln.id, [package.id])

                if "status" in issue:
                    if issue["status"] == "Patched":
                        assessment.set_status("fixed")
                        assessment.set_not_affected_reason("Yocto reported vulnerability as Patched")
                    elif issue["status"] == "Ignored":
                        assessment.set_status("not_affected")
                        assessment.set_justification("vulnerable_code_not_present")
                        assessment.set_not_affected_reason("Yocto reported vulnerability as Ignored")
                    elif issue["status"] == "Unpatched":
                        assessment.set_status("under_investigation")

                self.assessmentsCtrl.add(assessment)
