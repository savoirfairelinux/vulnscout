# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..controllers import (
    ControllersCache,
    PackagesController,
    VulnerabilitiesController,
    AssessmentsController,
)
from ..models import Package, Vulnerability, Assessment, CVSS
from ..extensions import batch_session
from ..helpers.env_vars import get_bool_env
from ..helpers.datetime_utils import normalize_timestamp_for_sort


class YoctoBase:
    """Shared parser skeleton for Yocto CVE JSON formats.

    Subclasses must declare the four class-level string constants and
    implement :meth:`_build_package`.

    Class-level constants
    ---------------------
    _SOURCE_TAG     : scanner tag stored in ``Vulnerability.found_by``.
    _PATCHED_LABEL  : substring written into ``Assessment.impact_statement``
                      for "Patched" issues; also used to detect existing ones.
    _IGNORED_LABEL  : same as above for "Ignored" issues.
    _SBOM_KEY       : observation key passed to ``record_sbom_observation``.
    """

    _SOURCE_TAG: str = ""
    _PATCHED_LABEL: str = ""
    _IGNORED_LABEL: str = ""
    _SBOM_KEY: str = ""

    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments

    def get_last_assessment(self, assessments):
        if not assessments:
            return None
        return max(assessments, key=lambda a: normalize_timestamp_for_sort(a.timestamp))

    @staticmethod
    def _parse_cvss_score(value) -> float | None:
        """Return *value* as a float, or None if it is not a valid numeric string."""
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def _build_package(self, pkg: dict) -> Package:
        """Build and return a :class:`Package` from a raw package dict.

        Must be implemented by each subclass; ``packagesCtrl.add`` is called
        by the base class after this method returns.
        """
        raise NotImplementedError

    def _register_cvss_scores(self, vuln: Vulnerability, issue: dict) -> None:
        """Parse all CVSS score fields from *issue* and register them on *vuln*."""
        vector_string = issue.get("vectorString", "")

        if issue.get("scorev4", "0.0") not in ("0.0", "", None):
            score = self._parse_cvss_score(issue["scorev4"])
            if score is not None:
                v4_vector = vector_string if vector_string.startswith("CVSS:4") else ""
                vuln.register_cvss(CVSS("4.0", v4_vector, "unknown", score, 0.0, 0.0))

        if issue.get("scorev3", "0.0") not in ("0.0", "", None):
            score = self._parse_cvss_score(issue["scorev3"])
            if score is not None:
                v3_vector = vector_string if vector_string.startswith("CVSS:3") else ""
                vuln.register_cvss(CVSS("3.1", v3_vector, "unknown", score, 0.0, 0.0))

        if issue.get("scorev2", "0.0") not in ("0.0", "", None):
            score = self._parse_cvss_score(issue["scorev2"])
            if score is not None:
                v2_vector = (
                    vector_string
                    if (vector_string and not vector_string.startswith("CVSS:"))
                    else ""
                )
                vuln.register_cvss(CVSS("2.0", v2_vector, "unknown", score, 0.0, 0.0))

    def load_from_dict(self, data: dict):
        """Load packages and vulnerabilities from a Yocto CVE JSON dictionary.

        Expected top-level structure::

            {
              "version": "1",
              "package": [ <package-entry>, ... ]
            }

        Each ``<package-entry>`` must contain at least ``name`` and
        ``version``; the ``issue`` list is optional.  See the subclass
        docstrings for the full field reference.
        """
        skip_patched = get_bool_env('CVE_CHECK_EXCLUDE_PATCHED')

        with batch_session():
            for pkg in data.get("package", []):
                if "name" not in pkg or "version" not in pkg:
                    continue

                package = self._build_package(pkg)
                package = self.packagesCtrl.add(package)

                # Pre-warm the in-memory index with DB assessments for this
                # package so that gets_by_vuln_pkg hits only the in-memory
                # index — no DB query per issue.
                self.assessmentsCtrl.warm_packages([package.string_id])

                for issue in pkg.get("issue", []):
                    vuln = Vulnerability(
                        issue.get("id", "").upper(),
                        [self._SOURCE_TAG],
                    )
                    if "link" in issue:
                        vuln.add_url(issue["link"])
                    if "summary" in issue:
                        vuln.description = issue["summary"]
                    # Optional VEX-only fields — silently ignored when absent.
                    if "vector" in issue:
                        vuln.attack_vector = issue["vector"]
                    if "patch-file" in issue:
                        vuln.add_advisory(issue["patch-file"])

                    self._register_cvss_scores(vuln, issue)

                    vuln.add_package(package.string_id)
                    vuln = self.vulnerabilitiesCtrl.add(vuln)

                    if "status" not in issue:
                        continue
                    assessments = self.assessmentsCtrl.gets_by_vuln_pkg(
                        vuln.id, package.string_id
                    )

                    found_corresponding_assessment = False
                    for existing in assessments:
                        if (
                            issue["status"] == "Patched"
                            and existing.is_compatible_status("fixed")
                            and self._PATCHED_LABEL in (existing.impact_statement or "")
                        ):
                            found_corresponding_assessment = True
                        elif (
                            issue["status"] == "Ignored"
                            and existing.is_compatible_status("not_affected")
                            and self._IGNORED_LABEL in (existing.impact_statement or "")
                        ):
                            found_corresponding_assessment = True
                        elif (
                            issue["status"] == "Unpatched"
                            and existing.is_compatible_status("under_investigation")
                        ):
                            found_corresponding_assessment = True

                    if found_corresponding_assessment:
                        continue

                    assessment = Assessment.new_dto(vuln.id, [package.string_id])

                    # ``detail`` carries a human-readable status detail string
                    # (Yocto VEX format).  No-op for formats that lack it.
                    if "detail" in issue:
                        assessment.set_status_notes(issue["detail"])
                    detail_reason = issue.get("detail", "")

                    if issue["status"] == "Patched":
                        if skip_patched:
                            last = self.get_last_assessment(assessments)

                            if last is None:
                                self.vulnerabilitiesCtrl.remove(vuln.id)
                                continue

                            if not last.is_compatible_status("fixed"):
                                assessment.set_status("fixed")
                                reason = self._PATCHED_LABEL
                                if detail_reason:
                                    reason = f"{reason}: {detail_reason}"
                                assessment.set_not_affected_reason(reason)
                            else:
                                continue
                        else:
                            assessment.set_status("fixed")
                            reason = self._PATCHED_LABEL
                            if detail_reason:
                                reason = f"{reason}: {detail_reason}"
                            assessment.set_not_affected_reason(reason)

                    elif issue["status"] == "Ignored":
                        assessment.set_status("not_affected")
                        assessment.set_justification("vulnerable_code_not_present")
                        reason = self._IGNORED_LABEL
                        if detail_reason:
                            reason = f"{reason}: {detail_reason}"
                        assessment.set_not_affected_reason(reason)

                    elif issue["status"] == "Unpatched":
                        assessment.set_status("under_investigation")
                        if detail_reason:
                            assessment.set_not_affected_reason(detail_reason)

                    self.assessmentsCtrl.add(assessment)

                    if "description" in issue:
                        self.vulnerabilitiesCtrl.record_sbom_observation(
                            vuln,
                            key=self._SBOM_KEY,
                            description=issue["description"],
                            package=package,
                        )
