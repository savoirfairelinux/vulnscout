# -*- coding: utf-8 -*-
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.cvss import CVSS
from ..models.assessment import VulnAssessment
from cyclonedx.model.bom import Bom
import cyclonedx.output


class CycloneDx:
    """
    CycloneDx class to handle CycloneDx SBOM and parse it.
    Also support output to CycloneDx SBOM format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]
        self.ref_dict = {}

    def load_from_dict(self, cyclonedx: dict):
        """Read data from CycloneDx json parsed format."""
        try:
            self.sbom = Bom.from_json(data=cyclonedx)
        except Exception as e:
            print(f"Error parsing CycloneDx format: {e}")

    def merge_components_into_controller(self):
        """
        Internal method.
        Merge components from SBOM into controller.
        """
        if "sbom" not in self.__dict__ or not self.sbom:
            return

        for component in self.sbom.components:
            package = Package(component.name, component.version or "", [], [])
            if component.purl:
                package.add_purl(str(component.purl))
            if component.cpe:
                package.add_cpe(component.cpe)
            package.generate_generic_cpe()
            package.generate_generic_purl()

            if component.bom_ref.value:
                self.ref_dict[component.bom_ref.value] = package.id

            self.packagesCtrl.add(package)

    def merge_vulnerabilities_into_controller(self):
        """
        Internal method.
        Merge components from SBOM into controller.
        """
        if "sbom" not in self.__dict__ or not self.sbom:
            return

        for vulnerability in self.sbom.vulnerabilities:
            # TODO: use tools property to get the source of the vulnerability instead of CycloneDX
            if not vulnerability.source:
                vulnerability.source = {}
            vuln = Vulnerability(
                vulnerability.id,
                "CycloneDX",
                str(vulnerability.source.url) if vulnerability.source and vulnerability.source.url else 'unknown',
                vulnerability.source.name if vulnerability.source and vulnerability.source.name else 'unknown',
            )
            for reference in vulnerability.references:
                vuln.add_alias(reference.id)
            for rating in vulnerability.ratings:
                if rating.method and rating.score and rating.method.startswith('CVSSv'):
                    cvss = CVSS(
                        str(rating.method.replace("CVSSv", "").replace("31", "3.1")),
                        rating.vector,
                        rating.source.name if rating.source and rating.source.name else 'unknown',
                        float(rating.score),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss)
                elif rating.severity:
                    vuln.severity_without_cvss(rating.severity, rating.score, False)

            if vulnerability.description:
                vuln.add_text(vulnerability.description, "description")
            if vulnerability.detail:
                vuln.add_text(vulnerability.detail, "detail")
            if vulnerability.recommendation:
                vuln.add_text(vulnerability.recommendation, "recommendation")

            for advisory in vulnerability.advisories:
                vuln.add_url(str(advisory.url))

            for affect in vulnerability.affects:
                if self.ref_dict[affect.ref]:
                    vuln.add_package(self.ref_dict[affect.ref])

            if vulnerability.bom_ref.value:
                self.ref_dict[vulnerability.bom_ref.value] = vuln.id

            self.merge_assessments_into_controller(vulnerability, vuln.packages)
            self.vulnerabilitiesCtrl.add(vuln)

    def merge_assessments_into_controller(
        self,
        vulnerability: cyclonedx.model.vulnerability.Vulnerability,
        pkgs: list
    ):
        """
        Internal method.
        Merge assessments from SBOM into controller.
        """
        if "sbom" not in self.__dict__ or not self.sbom:
            return

        if vulnerability.analysis:
            analysis = vulnerability.analysis
            assess = VulnAssessment(vulnerability.id, pkgs)
            if analysis.state:
                assess.set_status(analysis.state)
            if analysis.justification:
                assess.set_justification(analysis.justification)
            for resp in analysis.responses:
                assess.add_response(resp)
            if analysis.detail:
                assess.set_status_notes(analysis.detail)
            if vulnerability.workaround:
                assess.set_workaround(vulnerability.workaround)
                assess.add_response("workaround_available")

            for assessment in self.assessmentsCtrl.gets_by_vuln(vulnerability.id):
                if (assessment.is_compatible_status(assess.status)
                   and assessment.is_compatible_justification(assess.justification)):

                    similar_status_notes = False

                    # search for at least one note from CDX which exist in this assessment
                    for note in assess.status_notes.split("\n"):
                        if note in assessment.status_notes:
                            similar_status_notes = True

                    if similar_status_notes:
                        assess.id = assessment.id  # same ID means it will merge them
                        break
            self.assessmentsCtrl.add(assess)

    def parse_and_merge(self):
        """Parse the SBOM and merge it into the controller."""
        self.merge_components_into_controller()
        self.merge_vulnerabilities_into_controller()

    def output_as_json(self) -> str:
        """Output the SBOM to JSON format."""
        if not self.sbom:
            return None
        return cyclonedx.output.get_instance(
            bom=self.sbom,
            output_format=cyclonedx.output.OutputFormat.JSON
        ).output_as_string()
