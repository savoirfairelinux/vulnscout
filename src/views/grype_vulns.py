# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import Assessment
from ..models.cvss import CVSS
from typing import Optional


class GrypeVulns:
    """
    GrypeVulns class to handle grype vulnerabilities and parse it.
    Support only reading and parsing from JSON format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    @staticmethod
    def _normalize_artifact_name(name: str, purl: Optional[str] = None) -> str:
        """Extract the canonical package name, avoiding namespace duplication.

        When Grype reads a CycloneDX SBOM that has a ``group`` field, it
        concatenates ``group/name`` in the artifact name.  If that combined
        name is later re-exported as CycloneDX (with a ``group`` derived from
        the CPE vendor), a second Grype scan ends up with
        ``group/group/name``, growing indefinitely.

        To break this cycle we prefer the package name from the PURL (which
        never carries the group prefix) and fall-back to stripping repeated
        namespace prefixes from *name*.
        """
        # 1. Try to extract the name from the PURL — it's always canonical.
        if purl and "/" in purl:
            try:
                # PURLs look like  pkg:<type>/<namespace>/<name>@<version>
                #              or  pkg:<type>/<name>@<version>
                path_part = purl.split("://", 1)[-1] if "://" in purl else purl
                # Remove 'pkg:' prefix
                if path_part.startswith("pkg:"):
                    path_part = path_part[4:]
                # Remove type/  (e.g. "apk/", "generic/")
                if "/" in path_part:
                    path_part = path_part.split("/", 1)[1]
                # Strip version (@...)
                if "@" in path_part:
                    path_part = path_part.rsplit("@", 1)[0]
                # path_part may now be "namespace/name" or just "name"
                # Take the last component as the package name
                purl_name = path_part.rsplit("/", 1)[-1] if "/" in path_part else path_part
                if purl_name:
                    return purl_name
            except Exception:
                pass

        # 2. Fallback: strip repeated leading namespace segments.
        #    e.g. "openssl/openssl/openssl-foo" → "openssl-foo"
        #         "openssl/openssl-foo" → "openssl-foo"
        if "/" in name:
            parts = name.split("/")
            # Remove leading segments that are a prefix of the last segment
            base = parts[-1]
            return base

        return name

    def parse_artifact_section(self, artifact: dict) -> Optional[str]:
        """Parse the `artifact` part of grype JSON output."""
        if "name" in artifact and "version" in artifact:
            raw_name = artifact["name"]
            purl_str = artifact.get("purl")
            name = self._normalize_artifact_name(raw_name, purl_str)

            package = Package(name, artifact["version"], [], [])

            if purl_str:
                package.add_purl(purl_str)
            if "cpes" in artifact:
                for cpe in artifact["cpes"]:
                    package.add_cpe(cpe)

            package.generate_generic_cpe()
            package.generate_generic_purl()

            self.packagesCtrl.add(package)
            return package.string_id
        return None

    def parse_match_details(self, match_details: list) -> list[str]:
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
                    packages.append(package.string_id)
        return packages

    def parse_vulnerability_section(self, vulnerability: dict) -> Vulnerability:
        """Parse the `vulnerability` part of grype JSON output."""
        vuln_data = Vulnerability(
            vulnerability.get("id", "").upper(),
            ["grype"],
            vulnerability.get("dataSource", "unknown"),
            vulnerability.get("namespace", "unknown").lower()
        )

        for url in vulnerability.get("urls", []):
            vuln_data.add_url(url)

        description = vulnerability.get("description")
        if isinstance(description, str):
            vuln_data.add_text(description, "description")

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
        matches = data.get("matches", [])

        # Single pass: resolve packages, pre-warm the assessment index per
        # unique package, then process vulnerabilities — all without a second
        # iteration over `matches` or a second call to parse_artifact_section.
        resolved: list[tuple[dict, list[str]]] = []  # (match, [pkg_id, ...])
        seen_pkg_ids: set[str] = set()

        for match in matches:
            packages: list[str] = []

            if "artifact" in match:
                pkg_id = self.parse_artifact_section(match["artifact"])
                if pkg_id is not None:
                    packages.append(pkg_id)
                    if pkg_id not in seen_pkg_ids:
                        seen_pkg_ids.add(pkg_id)
                        # Bulk-fetch all existing assessments for this package
                        # so the in-memory index is complete before we start
                        # checking for assessments below.
                        _current_vid = getattr(self.assessmentsCtrl, 'current_variant_id', None)
                        for a in Assessment.get_by_package(pkg_id):
                            if _current_vid is None or a.variant_id is None or a.variant_id == _current_vid:
                                self.assessmentsCtrl._index_existing(a)
                        self.assessmentsCtrl._db_queried_pkgs.add(pkg_id)

            if "matchDetails" in match:
                packages.extend(self.parse_match_details(match["matchDetails"]))

            resolved.append((match, packages))

        for match, packages in resolved:
            if "vulnerability" not in match:
                continue

            vuln_data = self.parse_vulnerability_section(match["vulnerability"])

            if vuln_data.id == "" or len(packages) < 1:
                continue

            for package in packages:
                vuln_data.add_package(package)

            vuln_data = self.vulnerabilitiesCtrl.add(vuln_data)

            pkg0 = packages[0]
            if pkg0 in self.assessmentsCtrl._db_queried_pkgs:
                # Package was pre-warmed: all existing assessments are already
                # in the in-memory index. Consult it directly — no DB query.
                existing = self.assessmentsCtrl._by_vuln_pkg.get((vuln_data.id, pkg0), [])
                if not existing:
                    assessment = Assessment.new_dto(vuln_data.id, packages)
                    self.assessmentsCtrl.add(assessment)
            else:
                # Fallback for packages that came only from matchDetails
                # (no artifact section), which bypass the pre-warm above.
                existing_assessments = self.assessmentsCtrl.gets_by_vuln_pkg(vuln_data.id, pkg0)
                if len(existing_assessments) < 1:
                    assessment = Assessment.new_dto(vuln_data.id, packages)
                    self.assessmentsCtrl.add(assessment)
