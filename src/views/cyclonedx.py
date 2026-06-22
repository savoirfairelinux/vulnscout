# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from decimal import Decimal
from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.cvss import CVSS
from ..models.assessment import Assessment
from ..controllers import ControllersCache, PackagesController, VulnerabilitiesController, AssessmentsController
from ..helpers.datetime_utils import normalize_timestamp_for_sort
from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot4, JsonV1Dot5, JsonV1Dot6
from cyclonedx.model.component import Component
import cyclonedx.model.vulnerability
from cyclonedx.model.impact_analysis import ImpactAnalysisState, ImpactAnalysisJustification
from uuid_extensions import uuid7
from datetime import datetime, timezone
from packageurl import PackageURL
from typing import Optional


class CycloneDx:
    """
    CycloneDx class to handle CycloneDx SBOM and parse it.
    Also support output to CycloneDx SBOM format.
    """

    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments
        self.ref_dict: dict = {}  # TODO exact type

    _SEVERITY_MAP = {
        "low": cyclonedx.model.vulnerability.VulnerabilitySeverity.LOW,
        "medium": cyclonedx.model.vulnerability.VulnerabilitySeverity.MEDIUM,
        "high": cyclonedx.model.vulnerability.VulnerabilitySeverity.HIGH,
        "critical": cyclonedx.model.vulnerability.VulnerabilitySeverity.CRITICAL,
        "info": cyclonedx.model.vulnerability.VulnerabilitySeverity.INFO,
    }

    _VEX_STATUS_MAP = {
        "resolved": ImpactAnalysisState.RESOLVED,
        "resolved_with_pedigree": ImpactAnalysisState.RESOLVED_WITH_PEDIGREE,
        "exploitable": ImpactAnalysisState.EXPLOITABLE,
        "in_triage": ImpactAnalysisState.IN_TRIAGE,
        "false_positive": ImpactAnalysisState.FALSE_POSITIVE,
        "not_affected": ImpactAnalysisState.NOT_AFFECTED,
    }

    # Resolve the "perimeter" typo that exists in some cyclonedx-python-lib versions.
    try:
        _PERIMETER = ImpactAnalysisJustification.PROTECTED_AT_PERIMETER  # type: ignore
    except AttributeError:
        _PERIMETER = ImpactAnalysisJustification.PROTECTED_AT_PERIMITER

    _VEX_JUSTIFICATION_MAP = {
        "code_not_present": ImpactAnalysisJustification.CODE_NOT_PRESENT,
        "code_not_reachable": ImpactAnalysisJustification.CODE_NOT_REACHABLE,
        "protected_at_perimeter": _PERIMETER,
        "protected_at_runtime": ImpactAnalysisJustification.PROTECTED_AT_RUNTIME,
        "protected_by_compiler": ImpactAnalysisJustification.PROTECTED_BY_COMPILER,
        "protected_by_mitigating_control": ImpactAnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL,
        "requires_configuration": ImpactAnalysisJustification.REQUIRES_CONFIGURATION,
        "requires_dependency": ImpactAnalysisJustification.REQUIRES_DEPENDENCY,
        "requires_environment": ImpactAnalysisJustification.REQUIRES_ENVIRONMENT,
    }

    @staticmethod
    def str_to_severity(severity: str) -> cyclonedx.model.vulnerability.VulnerabilitySeverity:
        """Convert string to CycloneDx severity."""
        return CycloneDx._SEVERITY_MAP.get(
            severity.lower(), cyclonedx.model.vulnerability.VulnerabilitySeverity.UNKNOWN
        )

    @staticmethod
    def str_to_vex_status(state: str) -> ImpactAnalysisState:
        """Convert string to CycloneDx VEX status."""
        return CycloneDx._VEX_STATUS_MAP.get(state.lower(), ImpactAnalysisState.IN_TRIAGE)

    @staticmethod
    def str_to_vex_justification(justification: str) -> Optional[ImpactAnalysisJustification]:
        """Convert string to CycloneDx VEX justification."""
        return CycloneDx._VEX_JUSTIFICATION_MAP.get(justification.lower())

    @staticmethod
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

    # Add function to delete the "justification:"null" from the cyclonedx files
    def clean_sbom(self, cyclonedx):
        if isinstance(cyclonedx, dict):
            new_dict = {}
            for k, v in cyclonedx.items():
                # Remove 'justification' if it's invalid
                if k == "justification" and (v is None or str(v).lower() == "null"):
                    continue  # drop the key entirely
                if isinstance(v, (dict, list)):
                    new_dict[k] = self.clean_sbom(v)
                else:
                    new_dict[k] = v
            return new_dict
        elif isinstance(cyclonedx, list):
            return [self.clean_sbom(item) for item in cyclonedx if item is not None]
        else:
            return cyclonedx

    def load_from_dict(self, cyclonedx: dict):
        """Read data from CycloneDx json parsed format."""
        try:
            cyclonedx = self.clean_sbom(cyclonedx)
            self.sbom = Bom.from_json(data=cyclonedx)  # type: ignore
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
                self.ref_dict[component.bom_ref.value] = package.string_id

            self.packagesCtrl.add(package)

    def merge_vulnerabilities_into_controller(self):
        """
        Internal method.
        Merge components from SBOM into controller.
        """
        if "sbom" not in self.__dict__ or not self.sbom:
            return

        for vulnerability in self.sbom.vulnerabilities:
            # Skip vulnerabilities without an ID
            if vulnerability.id is None:
                continue
            # TODO: use tools property to get the source of the vulnerability instead of CycloneDX
            if not vulnerability.source:
                vulnerability.source = {}
            vuln = Vulnerability(
                vulnerability.id,
                ["cyclonedx"],
                str(vulnerability.source.url) if vulnerability.source and vulnerability.source.url else 'unknown',
                vulnerability.source.name if vulnerability.source and vulnerability.source.name else 'unknown',
            )
            for reference in vulnerability.references:
                vuln.add_alias(reference.id)
            for rating in vulnerability.ratings:
                method_value = rating.method.value if rating.method else ""
                if rating.method and rating.score and method_value.startswith('CVSSv'):
                    version = method_value.replace("CVSSv", "").replace("31", "3.1")
                    # The library normalises the vector by stripping the
                    # "CVSS:X.X/" prefix – reconstruct the full form.
                    vector = rating.vector or ""
                    if vector and not vector.startswith("CVSS:"):
                        if version in ("3.0", "3", "3.1"):
                            vector = f"CVSS:{version}/{vector}"
                        elif version in ("4.0", "4"):
                            vector = f"CVSS:{version}/{vector}"
                    cvss = CVSS(
                        version,
                        vector,
                        rating.source.name if rating.source and rating.source.name else 'unknown',
                        float(rating.score),
                        0.0,
                        0.0
                    )
                    vuln.register_cvss(cvss)
                elif rating.severity:
                    vuln.severity_without_cvss(rating.severity, rating.score, False)

            desc: str = vulnerability.description
            if vulnerability.detail:
                self.vulnerabilitiesCtrl.record_sbom_observation(
                    vuln,
                    key="CycloneDX Details",
                    description=vulnerability.detail,
                )
            if vulnerability.recommendation:
                self.vulnerabilitiesCtrl.record_sbom_observation(
                    vuln,
                    key="CycloneDX Recommendation",
                    description=vulnerability.recommendation,
                )
            vuln.description = desc

            for advisory in vulnerability.advisories:
                vuln.add_url(str(advisory.url))

            for affect in vulnerability.affects:
                ref = affect.ref
                # Check is the ref in file exist in the dictionnary, if not skip it
                if ref in self.ref_dict:
                    vuln.add_package(self.ref_dict[ref])

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
            if vulnerability.id is None:
                return
            assess = Assessment.new_dto(vulnerability.id, pkgs)
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
                   and assessment.is_compatible_justification(assess.justification)
                   and assess.status_notes is not None):

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
                    url=cyclonedx.model.XsUri(uri=vuln.datasource)
                ),
                description=vuln.description,
            )
            for alias in vuln.aliases:
                vuln_obj.references.add(
                    cyclonedx.model.vulnerability.VulnerabilityReference(
                        id=alias,
                        source=cyclonedx.model.vulnerability.VulnerabilitySource(
                            name=vuln.namespace,
                        )
                    )
                )
            have_custom_severity = vuln.severity_max_score is not None
            for cvss in vuln.severity_cvss:
                if (cvss.severity().lower() == vuln.severity_label.lower()
                   and cvss.base_score == vuln.severity_max_score):
                    have_custom_severity = False

                vuln_obj.ratings.add(
                    cyclonedx.model.vulnerability.VulnerabilityRating(
                        method=CycloneDx.cvss_to_rating_method(cvss),
                        vector=cvss.vector_string,
                        score=Decimal(str(cvss.base_score)),
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
                        score=Decimal(str(vuln.severity_max_score)),
                        severity=CycloneDx.str_to_severity(vuln.severity_label)
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
                if package is None:
                    continue
                if not package.purl:
                    package.generate_generic_purl()
                if package.purl:
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
            if last_assessment is None or (
                normalize_timestamp_for_sort(last_assessment.timestamp)
                < normalize_timestamp_for_sort(assessment.timestamp)
            ):
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

    def output_as_json(self, version=6, author=None) -> str:
        """Output the SBOM to JSON format."""
        if "sbom" not in self.__dict__ or not self.sbom:
            self.sbom = Bom()
            self.sbom.serial_number = uuid7()  # type: ignore

        self.sbom.metadata.timestamp = datetime.now(timezone.utc)
        if author is not None:
            self.sbom.metadata.manufacturer = cyclonedx.model.contact.OrganizationalEntity(
                name=author
            )
        self.sbom.components = []
        self.register_components()
        self.sbom.vulnerabilities = []
        self.register_vulnerabilities()

        if version == 4:
            return JsonV1Dot4(self.sbom).output_as_string(indent=2)
        elif version == 5:
            return JsonV1Dot5(self.sbom).output_as_string(indent=2)
        return JsonV1Dot6(self.sbom).output_as_string(indent=2)
