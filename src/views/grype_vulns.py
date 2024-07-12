# -*- coding: utf-8 -*-
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import VulnAssessment
from ..models.cvss import CVSS


class GrypeVulns:
    """
    GrypeVulns class to handle grype vulnerabilities and parse it.
    Support only reading and parsing from JSON format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    def parse_artifact_section(self, artifact: dict) -> str:
        """Parse the `artifact` part of grype JSON output."""
        if "name" in artifact and "version" in artifact:
            package = Package(artifact["name"], artifact["version"], [], [])

            if "purl" in artifact:
                package.add_purl(artifact["purl"])
            if "cpes" in artifact:
                for cpe in artifact["cpes"]:
                    package.add_cpe(cpe)

            package.generate_generic_cpe()
            package.generate_generic_purl()

            self.packagesCtrl.add(package)
            return package.id

    def parse_match_details(self, match_details: list) -> list:
        """Parse the `matchDetails` part of grype JSON output."""
        packages = []

        for matchd in match_details:
            searchedby = matchd.get("searchedBy", {})
            if "Package" in searchedby:
                found_pkg = searchedby.get("Package", {})
                if "name" in found_pkg and "version" in found_pkg:
                    package = Package(found_pkg["name"], found_pkg["version"], [], [])

                    if "purl" in searchedby:
                        package.add_purl(searchedby["purl"])
                    if "cpes" in searchedby:
                        for cpe in searchedby["cpes"]:
                            package.add_cpe(cpe)

                    found_match = matchd.get("found", {})
                    if "purl" in found_match:
                        package.add_purl(found_match["purl"])
                    if "cpes" in found_match:
                        for cpe in found_match["cpes"]:
                            package.add_cpe(cpe)

                    package.generate_generic_cpe()
                    package.generate_generic_purl()

                    self.packagesCtrl.add(package)
                    packages.append(package.id)
        return packages

    def parse_vulnerability_section(self, vulnerability: dict):
        """Parse the `vulnerability` part of grype JSON output."""
        vuln_data = Vulnerability(
            vulnerability.get("id", "").upper(),
            ["grype"],
            vulnerability.get("dataSource", "unknown"),
            vulnerability.get("namespace", "unknown").lower()
        )

        for url in vulnerability.get("urls", []):
            vuln_data.add_url(url)

        vuln_data.add_text(vulnerability.get("description"), "description")

        for cvss_score in vulnerability.get("cvss", []):
            cvss_item = CVSS(
                cvss_score.get("version"),
                cvss_score.get("vector", ""),
                cvss_score.get("source", "unknown"),
                cvss_score.get("metrics", {}).get("baseScore", 0.0),
                cvss_score.get("metrics", {}).get("exploitabilityScore", 0.0),
                cvss_score.get("metrics", {}).get("impactScore", 0.0)
            )
            vuln_data.register_cvss(cvss_item)
        vuln_data.severity_without_cvss(vulnerability.get("severity", "unknown").lower(), None, False)
        return vuln_data

    def load_from_dict(self, data: dict):
        """Load the GrypeVulns object from a dictionary."""
        for match in data.get("matches", []):

            packages = []

            if "artifact" in match:
                pkg_id = self.parse_artifact_section(match["artifact"])
                if pkg_id is not None:
                    packages.append(pkg_id)

            if "matchDetails" in match:
                packages.extend(self.parse_match_details(match["matchDetails"]))

            if "vulnerability" not in match:
                continue

            vuln_data = self.parse_vulnerability_section(match["vulnerability"])

            if vuln_data.id == "" or len(packages) < 1:
                continue

            for package in packages:
                vuln_data.add_package(package)

            vuln_data = self.vulnerabilitiesCtrl.add(vuln_data)

            assessment = self.assessmentsCtrl.gets_by_vuln_pkg(vuln_data.id, packages[0])
            if len(assessment) < 1:
                assessment = VulnAssessment(vuln_data.id, packages)
                self.assessmentsCtrl.add(assessment)
