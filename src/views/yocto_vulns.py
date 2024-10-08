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

            package = Package(pkg["name"], pkg["version"], [], [])
            package.generate_generic_cpe()
            package.generate_generic_purl()
            self.packagesCtrl.add(package)

            for issue in pkg.get("issue", []):

                vuln = Vulnerability(
                    issue.get("id").upper(),
                    ["yocto"],
                    issue.get("link", ""),
                    "unknown"
                )
                if "link" in issue:
                    vuln.add_url(issue.get("link"))
                if "summary" in issue:
                    vuln.add_text(issue.get("summary"), "summary")

                if "scorev3" in issue and issue["scorev3"] != "0.0":
                    cvss_item = CVSS(
                        "3.1",
                        f"CVSS:3.1/AV:{issue['vector']}" if "vector" in issue else "",
                        "unknown",
                        float(issue.get("scorev3")),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss_item)
                if "scorev2" in issue and issue["scorev2"] != "0.0":
                    cvss_item = CVSS(
                        "2.0",
                        f"AV:{issue['vector']}" if "vector" in issue else "",
                        "unknown",
                        float(issue.get("scorev2")),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss_item)

                vuln.add_package(package.id)
                vuln = self.vulnerabilitiesCtrl.add(vuln)

                if "status" not in issue:
                    continue
                assessments = self.assessmentsCtrl.gets_by_vuln_pkg(vuln.id, package.id)

                found_corresponding_assessment = False
                for assessment in assessments:

                    if (
                            issue["status"] == "Patched"
                            and assessment.is_compatible_status("fixed")
                            and "Yocto reported vulnerability as Patched" in assessment.impact_statement
                    ):
                        found_corresponding_assessment = True
                    elif (
                            issue["status"] == "Ignored"
                            and assessment.is_compatible_status("not_affected")
                            and "Yocto reported vulnerability as Ignored" in assessment.impact_statement
                    ):
                        found_corresponding_assessment = True
                    elif (
                            issue["status"] == "Unpatched"
                            and assessment.is_compatible_status("under_investigation")
                    ):
                        found_corresponding_assessment = True

                if found_corresponding_assessment:
                    continue

                assessment = VulnAssessment(vuln.id, [package.id])

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
