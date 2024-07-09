# -*- coding: utf-8 -*-
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.cvss import CVSS
from ..models.assessment import VulnAssessment
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot4, JsonV1Dot5, JsonV1Dot6
from cyclonedx.model.component import Component
import cyclonedx.model.vulnerability
from cyclonedx.model.impact_analysis import ImpactAnalysisState, ImpactAnalysisJustification
from uuid_extensions import uuid7
from packageurl import PackageURL


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

    def str_to_severity(severity: str) -> cyclonedx.model.vulnerability.VulnerabilitySeverity:
        """
        Internal method.
        Convert string to CycloneDx severity.
        """
        if severity.lower() == "low":
            return cyclonedx.model.vulnerability.VulnerabilitySeverity.LOW
        elif severity.lower() == "medium":
            return cyclonedx.model.vulnerability.VulnerabilitySeverity.MEDIUM
        elif severity.lower() == "high":
            return cyclonedx.model.vulnerability.VulnerabilitySeverity.HIGH
        elif severity.lower() == "critical":
            return cyclonedx.model.vulnerability.VulnerabilitySeverity.CRITICAL
        elif severity.lower() == "info":
            return cyclonedx.model.vulnerability.VulnerabilitySeverity.INFO
        return cyclonedx.model.vulnerability.VulnerabilitySeverity.UNKNOWN

    def str_to_vex_status(state: str) -> ImpactAnalysisState:
        """
        Internal method.
        Convert string to CycloneDx VEX status.
        """
        if state.lower() == "resolved":
            return ImpactAnalysisState.RESOLVED
        elif state.lower() == "resolved_with_pedigree":
            return ImpactAnalysisState.RESOLVED_WITH_PEDIGREE
        elif state.lower() == "exploitable":
            return ImpactAnalysisState.EXPLOITABLE
        elif state.lower() == "in_triage":
            return ImpactAnalysisState.IN_TRIAGE
        elif state.lower() == "false_positive":
            return ImpactAnalysisState.FALSE_POSITIVE
        elif state.lower() == "not_affected":
            return ImpactAnalysisState.NOT_AFFECTED
        return ImpactAnalysisState.IN_TRIAGE

    def str_to_vex_justification(justification: str) -> ImpactAnalysisJustification:
        """
        Internal method.
        Convert string to CycloneDx VEX justification.
        """
        if justification.lower() == "code_not_present":
            return ImpactAnalysisJustification.CODE_NOT_PRESENT
        elif justification.lower() == "code_not_reachable":
            return ImpactAnalysisJustification.CODE_NOT_REACHABLE
        elif justification.lower() == "protected_at_perimeter":
            try:
                return ImpactAnalysisJustification.PROTECTED_AT_PERIMETER
            except AttributeError:
                return ImpactAnalysisJustification.PROTECTED_AT_PERIMITER
        elif justification.lower() == "protected_at_runtime":
            return ImpactAnalysisJustification.PROTECTED_AT_RUNTIME
        elif justification.lower() == "protected_by_compiler":
            return ImpactAnalysisJustification.PROTECTED_BY_COMPILER
        elif justification.lower() == "protected_by_mitigating_control":
            return ImpactAnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL
        elif justification.lower() == "requires_configuration":
            return ImpactAnalysisJustification.REQUIRES_CONFIGURATION
        elif justification.lower() == "requires_dependency":
            return ImpactAnalysisJustification.REQUIRES_DEPENDENCY
        elif justification.lower() == "requires_environment":
            return ImpactAnalysisJustification.REQUIRES_ENVIRONMENT
        return None

    def cvss_to_rating_method(cvss: CVSS) -> cyclonedx.model.vulnerability.VulnerabilityScoreSource:
        if cvss.version == "4.0" or cvss.version == "4":
            return cyclonedx.model.vulnerability.VulnerabilityScoreSource.CVSS_V4
        elif cvss.version == "3.1":
            return cyclonedx.model.vulnerability.VulnerabilityScoreSource.CVSS_V3_1
        elif cvss.version == "3.0" or cvss.version == "3":
            return cyclonedx.model.vulnerability.VulnerabilityScoreSource.CVSS_V3
        elif cvss.version == "2.0" or cvss.version == "2":
            return cyclonedx.model.vulnerability.VulnerabilityScoreSource.CVSS_V2
        return cyclonedx.model.vulnerability.VulnerabilityScoreSource.get_from_vector(cvss.vector_string)

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

    def register_components(self):
        """
        Internal method.
        Copy components from controller into SBOM.
        """
        for pkg in self.packagesCtrl:
            if len(pkg.cpe) < 1:
                pkg.generate_generic_cpe()
            if len(pkg.purl) < 1:
                pkg.generate_generic_purl()
            group = pkg.cpe[0].split(":")[3]
            cmp = Component(
                type=cyclonedx.model.component.ComponentType.LIBRARY,
                name=pkg.name,
                version=pkg.version,
                bom_ref=pkg.purl[0],
                group=group if group != '*' else None,
                cpe=pkg.cpe[0],
                purl=PackageURL.from_string(pkg.purl[0]),
            )
            self.sbom.components.add(cmp)

    def register_vulnerabilities(self):
        """
        Internal method.
        Copy vulnerabilities from controller into SBOM.
        """
        for vuln in self.vulnerabilitiesCtrl:
            vuln_obj = cyclonedx.model.vulnerability.Vulnerability(
                id=vuln.id,
                bom_ref=vuln.id,
                source=cyclonedx.model.vulnerability.VulnerabilitySource(
                    name=vuln.namespace,
                    url=vuln.datasource
                ),
                description=vuln.texts.get("description", vuln.texts.get("summary", None)),
                detail=vuln.texts.get("detail", None),
                recommendation=vuln.texts.get("recommendation", None),
            )
            for alias in vuln.aliases:
                vuln_obj.references.add(
                    cyclonedx.model.vulnerability.VulnerabilityReference(
                        id=alias
                    )
                )
            have_custom_severity = vuln.severity["max_score"] is not None
            for cvss in vuln.severity["cvss"]:
                if (cvss.severity().lower() == vuln.severity["severity"].lower()
                   and cvss.base_score == vuln.severity["max_score"]):
                    have_custom_severity = False

                vuln_obj.ratings.add(
                    cyclonedx.model.vulnerability.VulnerabilityRating(
                        method=CycloneDx.cvss_to_rating_method(cvss),
                        vector=cvss.vector_string,
                        score=float(cvss.base_score),
                        source=cyclonedx.model.vulnerability.VulnerabilitySource(
                            name=cvss.author,
                        ),
                        severity=CycloneDx.str_to_severity(cvss.severity())
                    )
                )

            if have_custom_severity:
                vuln_obj.ratings.add(
                    cyclonedx.model.vulnerability.VulnerabilityRating(
                        method=cyclonedx.model.vulnerability.VulnerabilityScoreSource.OTHER,
                        score=float(vuln.severity["max_score"]),
                        severity=CycloneDx.str_to_severity(vuln.severity["severity"])
                    )
                )

            for url in vuln.urls:
                vuln_obj.advisories.add(
                    cyclonedx.model.vulnerability.VulnerabilityAdvisory(
                        url=cyclonedx.model.XsUri(uri=url)
                    )
                )
            for pkg in vuln.packages:
                package = self.packagesCtrl.get(pkg)
                if len(package.purl) < 1:
                    package.generate_generic_purl()
                vuln_obj.affects.add(
                    cyclonedx.model.vulnerability.BomTarget(
                        ref=package.purl[0]
                    )
                )
            self.register_assessment(vuln_obj)
            self.sbom.vulnerabilities.add(vuln_obj)

    def register_assessment(self, vuln_obj: cyclonedx.model.vulnerability.Vulnerability):
        """
        Internal method.
        Copy assessments from controller into SBOM.
        """
        last_assessment = None
        for assessment in self.assessmentsCtrl.gets_by_vuln(vuln_obj.id):
            if last_assessment is None or last_assessment.timestamp < assessment.timestamp:
                last_assessment = assessment

        if last_assessment:
            assess = last_assessment.to_cdx_vex_dict()
            vuln_obj.analysis = cyclonedx.model.vulnerability.VulnerabilityAnalysis(
                state=CycloneDx.str_to_vex_status(assess["analysis"]["state"]),
                justification=CycloneDx.str_to_vex_justification(assess["analysis"]["justification"]),
                responses=assess["analysis"]["response"],
                detail=assess["analysis"]["detail"]
            )
            if assess["workaround"]:
                vuln_obj.workaround = assess["workaround"]

    def output_as_json(self, version=6) -> str:
        """Output the SBOM to JSON format."""
        if "sbom" not in self.__dict__ or not self.sbom:
            self.sbom = Bom()
            self.sbom.serial_number = uuid7()

        self.sbom.components = []
        self.register_components()
        self.sbom.vulnerabilities = []
        self.register_vulnerabilities()

        if version == 4:
            return JsonV1Dot4(self.sbom).output_as_string(indent=2)
        elif version == 5:
            return JsonV1Dot5(self.sbom).output_as_string(indent=2)
        return JsonV1Dot6(self.sbom).output_as_string(indent=2)
