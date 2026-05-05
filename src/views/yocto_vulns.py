# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from datetime import datetime, timezone
import logging

from ..controllers import PackagesController, VulnerabilitiesController, AssessmentsController
from ..models import Package, Vulnerability, Assessment, CVSS, Finding, Observation
from ..extensions import batch_session
from ..helpers.env_vars import get_bool_env


_logger = logging.getLogger(__name__)


class YoctoVulns:
    """GrypeVulns class to handle grype vulnerabilities and parse it"""
    def __init__(self, controllers):
        self.packagesCtrl: PackagesController = controllers["packages"]
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers["vulnerabilities"]
        self.assessmentsCtrl: AssessmentsController = controllers["assessments"]

    def get_last_assessment(self, assessments):
        if not assessments:
            return None

        def _ts_key(a):
            ts = a.timestamp
            if ts is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    return datetime.min.replace(tzinfo=timezone.utc)
            if hasattr(ts, 'tzinfo') and ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts

        return max(assessments, key=_ts_key)

    def load_from_dict(self, data: dict):
        """Load the yoctoVulns object from a dictionary."""

        skip_patched = get_bool_env('CVE_CHECK_EXCLUDE_PATCHED')

        with batch_session():
            for pkg in data.get("package", []):
                if "name" not in pkg or "version" not in pkg:
                    continue

                package = Package(pkg["name"], pkg["version"], [], [])
                package.generate_generic_cpe()
                package.generate_generic_purl()
                self.packagesCtrl.add(package)

                # Pre-warm the in-memory index with DB assessments for this
                # package in one query. After this, gets_by_vuln_pkg hits only
                # the in-memory _by_vuln_pkg index — no DB query per issue.
                # Only index assessments that belong to the current variant (or
                # have no variant) so that a different variant's records do not
                # fool the deduplication check below.
                _current_vid = getattr(self.assessmentsCtrl, 'current_variant_id', None)
                for a in Assessment.get_by_package(package.string_id):
                    if _current_vid is None or a.variant_id is None or a.variant_id == _current_vid:
                        self.assessmentsCtrl._index_existing(a)
                self.assessmentsCtrl._db_queried_pkgs.add(package.string_id)

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
                        vuln.add_text(issue.get("summary"), "description")

                    vector_string = issue.get("vectorString", "")

                    if "scorev4" in issue and issue["scorev4"] != "0.0":
                        v4_vector = vector_string if vector_string.startswith("CVSS:4") else ""
                        cvss_item = CVSS(
                            "4.0",
                            v4_vector,
                            "unknown",
                            float(issue.get("scorev4")),
                            0.0,
                            0.0
                        )
                        vuln.register_cvss(cvss_item)
                    if "scorev3" in issue and issue["scorev3"] != "0.0":
                        v3_vector = vector_string if vector_string.startswith("CVSS:3") else ""
                        cvss_item = CVSS(
                            "3.1",
                            v3_vector,
                            "unknown",
                            float(issue.get("scorev3")),
                            0.0,
                            0.0
                        )
                        vuln.register_cvss(cvss_item)
                    if "scorev2" in issue and issue["scorev2"] != "0.0":
                        v2_vector = vector_string if (
                            vector_string and not vector_string.startswith("CVSS:")
                        ) else ""
                        cvss_item = CVSS(
                            "2.0",
                            v2_vector,
                            "unknown",
                            float(issue.get("scorev2")),
                            0.0,
                            0.0
                        )
                        vuln.register_cvss(cvss_item)

                    vuln.add_package(package.string_id)
                    vuln = self.vulnerabilitiesCtrl.add(vuln)

                    if "status" not in issue:
                        continue
                    assessments = self.assessmentsCtrl.gets_by_vuln_pkg(vuln.id, package.string_id)

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

                    assessment = Assessment.new_dto(vuln.id, [package.string_id])

                    if issue["status"] == "Patched":
                        if skip_patched:
                            last = self.get_last_assessment(assessments)

                            if last is None:
                                # remove associated vuln (as this will be last input to be processed)
                                self.vulnerabilitiesCtrl.remove(vuln.id)
                                continue

                            if not last.is_compatible_status("fixed"):
                                assessment.set_status("fixed")
                                assessment.set_not_affected_reason(
                                    "Yocto reported vulnerability as Patched"
                                )
                            else:
                                continue
                        else:
                            assessment.set_status("fixed")
                            assessment.set_not_affected_reason(
                                "Yocto reported vulnerability as Patched"
                            )
                    elif issue["status"] == "Ignored":
                        assessment.set_status("not_affected")
                        assessment.set_justification("vulnerable_code_not_present")
                        assessment.set_not_affected_reason("Yocto reported vulnerability as Ignored")
                    elif issue["status"] == "Unpatched":
                        assessment.set_status("under_investigation")

                    self.assessmentsCtrl.add(assessment)

                    if "description" in issue:
                        # Need the SBOM Document to know in which scan to make the observation
                        if self.packagesCtrl.current_sbom_document is None:
                            _logger.warning("Cannot add Yocto-specific observation if no scan is ongoing")
                        else:
                            finding = Finding.get_by_package_and_vulnerability(package.string_id, vuln.id)
                            assert finding is not None

                            Observation.create(
                                finding.id,
                                self.packagesCtrl.current_sbom_document.scan_id,
                                yocto_description=issue.get("description"),
                            )
