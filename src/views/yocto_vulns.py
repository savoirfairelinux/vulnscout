# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import Assessment
from ..models.cvss import CVSS
from ..extensions import batch_session
from ..helpers.env_vars import get_bool_env
from datetime import datetime, timezone


class YoctoVulns:
    """GrypeVulns class to handle grype vulnerabilities and parse it"""
    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

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
                    if "description" in issue:
                        vuln.add_text(issue.get("description"), "yocto description")

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
