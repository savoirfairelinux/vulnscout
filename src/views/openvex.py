# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package
from ..models.vulnerability import Vulnerability
from ..models.assessment import VulnAssessment
from uuid_extensions import uuid7
from datetime import datetime, timezone
import re
from typing import Optional


class OpenVex:
    """
    OpenVex class to handle OpenVex file format and parse it.
    Support reading, parsing and writing from/to JSON format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    def parse_package_section(self, product: dict) -> Optional[Package]:
        pkg = None
        identifiers = product["identifiers"] if "identifiers" in product else {}

        if "cpe23" in identifiers:
            cpe_parts = identifiers["cpe23"].split(":")
            if len(cpe_parts) >= 6:
                pkg = Package(cpe_parts[4], cpe_parts[5], [identifiers["cpe23"]], [])

        if "purl" in identifiers:
            if pkg is None:
                match = re.search(r"([^\/\s]+)@([0-9\.]+)", identifiers["purl"])
                if match:
                    pkg = Package(match.group(1), match.group(2), [], [identifiers["purl"]])
            else:
                pkg.add_purl(identifiers["purl"])

        if pkg is None:
            match = re.search(r"([^\/\s]+)@([0-9\.]+)", product["@id"])
            if match:
                pkg = Package(match.group(1), match.group(2), [], [])
        return pkg

    def load_from_dict(self, data: dict):
        if "statements" in data:
            for statement in data["statements"]:
                if "vulnerability" not in statement or "name" not in statement["vulnerability"]:
                    continue
                vuln = Vulnerability(statement["vulnerability"]["name"], ["openvex"], "unknown", "unknown")
                if "description" in statement["vulnerability"]:
                    vuln.add_text(statement["vulnerability"]["description"], "description")
                if "aliases" in statement["vulnerability"]:
                    for alias in statement["vulnerability"]["aliases"]:
                        vuln.add_alias(alias)
                if "@id" in statement["vulnerability"] and statement["vulnerability"]["@id"].startswith("http"):
                    vuln.add_url(statement["vulnerability"]["@id"])
                    vuln.datasource = statement["vulnerability"]["@id"]
                # scanners is not part of OpenVex standard
                if "scanners" in statement:
                    for scanner in statement["scanners"]:
                        if "openvex" not in scanner:
                            vuln.add_found_by(scanner)

                assess = VulnAssessment(vuln.id)
                if "products" in statement:
                    for product in statement["products"]:
                        pkg = self.parse_package_section(product)
                        if pkg is None:
                            continue
                        self.packagesCtrl.add(pkg)
                        vuln.add_package(pkg)
                        assess.add_package(pkg)

                self.vulnerabilitiesCtrl.add(vuln)

                if "status" not in statement:
                    continue
                assess.set_status(statement["status"])
                if "status_notes" in statement:
                    assess.set_status_notes(statement["status_notes"])
                if "justification" in statement:
                    assess.set_justification(statement["justification"])
                if "impact_statement" in statement:
                    assess.set_not_affected_reason(statement["impact_statement"])
                if "action_statement" in statement:
                    if "action_statement_timestamp" in statement:
                        assess.set_workaround(statement["action_statement"], statement["action_statement_timestamp"])
                    else:
                        assess.set_workaround(statement["action_statement"])
                if "timestamp" in statement:
                    assess.timestamp = statement["timestamp"]
                if "last_updated" in statement:
                    assess.last_update = statement["last_updated"]

                self.assessmentsCtrl.add(assess)

    def to_dict(self, strict_export=False, author=None) -> dict:
        output = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://savoirfairelinux.com/sbom/openvex/{}".format(uuid7(as_type='str')),
            "author": author if author is not None else "Savoir-faire Linux",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "statements": []
        }
        for (assess_id, assess) in self.assessmentsCtrl.assessments.items():
            stmt = assess.to_openvex_dict()
            # Check if the dict is empty, if so skip it.
            if stmt is None:
                continue
            vuln = self.vulnerabilitiesCtrl.get(assess.vuln_id)
            if vuln is not None:
                # Check if there is vulnerability in the dict and if it's "none". If so set a empty dict.
                if "vulnerability" not in stmt or stmt["vulnerability"] is None:
                    stmt["vulnerability"] = {}
                if "description" in vuln.texts:
                    stmt["vulnerability"]["description"] = vuln.texts["description"]
                elif "summary" in vuln.texts:
                    stmt["vulnerability"]["description"] = vuln.texts["summary"]
                stmt["vulnerability"]["aliases"] = vuln.aliases
                if vuln.datasource.startswith("http"):
                    stmt["vulnerability"]["@id"] = vuln.datasource
                if not strict_export:
                    stmt["scanners"] = list(filter(lambda x: x != "openvex", vuln.found_by))

            pkg_list = []
            for pkg_id in assess.packages:
                product = {
                    "@id": pkg_id
                }
                pkg = self.packagesCtrl.get(pkg_id)

                if pkg is not None:
                    if len(pkg.cpe) < 1:
                        pkg.generate_generic_cpe()
                    if len(pkg.purl) < 1:
                        pkg.generate_generic_purl()
                    product["identifiers"] = {
                        "cpe23": pkg.cpe[0],
                        "purl": pkg.purl[0]
                    }

                pkg_list.append(product)
            stmt["products"] = pkg_list

            output["statements"].append(stmt)  # type: ignore
        return output
