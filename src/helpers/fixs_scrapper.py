# -*- coding: utf-8 -*-
from ..models.vulnerability import Vulnerability
import re
from typing import Optional


class FixSolution:
    """
    Represent a list of vulnerable and fixed versions associated to a package
    """

    def __init__(self, package: str, scrapper: str):
        self.package: str = package
        self.fixed: list[str] = []
        self.vulnerables: list[str] = []
        self.scrapper: str = scrapper


class FixsScrapper:
    """
    A serie of methods for scrapping data in Vulnerabilities content, NVD API, ...
    Main goal is to find information to help fixing vulnerability, like version where it's fixed
    """

    semver_regex = re.compile(r"""
        (before|through|until|after|from|prior\sto)?  # context keywords (\s = space)
        \s*                                # optional whitespace
        v?                                 # optional v
        (\d+)                              # major
        \.(\d+|x)                          # minor (number or x)
        (\.(\d+|x))?                       # patch (optional, number or x)
        """, re.VERBOSE | re.IGNORECASE)
    """
    Regex to parse version and their context in a string
    first group contain context keywords if any, second major, third minor, and patch is eventualy in five
    """

    def __init__(self):
        self.solutions: list[FixSolution] = []

    def search_in_vulnerability(self, vulnerability: Vulnerability):
        """
        Search in a vulnerability description / texts to find a fix or solution
        """
        for title in vulnerability.texts:
            matchs = re.findall(self.semver_regex, vulnerability.texts[title])
            for match in matchs:
                context = match[0]
                new_version = f"{match[1]}.{match[2]}"
                if len(match) >= 5 and match[4] != '':
                    new_version += f".{match[4]}"
                for pkg in vulnerability.packages:
                    pkg_parts = pkg.split("@")
                    artifact = FixSolution(pkg_parts[0], "local-description-regex")
                    if context == "before" or context == "prior to":
                        artifact.fixed.append(f">=? {new_version}")
                        artifact.vulnerables.append(f"<? {new_version}")
                    elif context == "through":
                        artifact.fixed.append(f">? {new_version}")
                        artifact.vulnerables.append(f"<=? {new_version}")
                    elif context == "after" or context == "from":
                        artifact.fixed.append(f"<? {new_version}")
                        artifact.vulnerables.append(f">=? {new_version}")
                    else:
                        artifact.fixed.append(f"{context}? {new_version}")
                        artifact.vulnerables.append(f"{context}? {new_version}")
                    self.solutions.append(artifact)

    def _extract_from_criteria(self, criteria: str) -> Optional[tuple[str, str]]:
        """
        Return package name and version from a CPE string, or None
        Internal use only
        """
        if criteria.startswith("cpe:2.3"):
            parts = criteria.split(":")
            if len(parts) >= 7:
                return parts[4], parts[5]
        return None

    def _search_in_nvd_node(self, node: dict, negate: bool = False):
        """
        Generate a list of FixSolution from a NVD node
        Internal use only
        """
        is_negated = negate
        if "nodes" in node:
            for child in node["nodes"]:
                self._search_in_nvd_node(child, negate)
            return
        if "negate" in node and node["negate"]:
            is_negated = not is_negated
        if "cpeMatch" in node:
            for match in node["cpeMatch"]:
                res = self._extract_from_criteria(match["criteria"])
                if res is None:
                    continue
                pkg_name, pkg_version = res
                artifact = FixSolution(pkg_name, "nvd-cpe-match")
                store_as_fixed = is_negated  # False by default, unless we are negated
                if "vulnerable" in match and not match["vulnerable"]:
                    store_as_fixed = not store_as_fixed

                if "versionEndIncluding" in match:
                    if not store_as_fixed:
                        artifact.fixed.append(f">? {match['versionEndIncluding']}")
                        artifact.vulnerables.append(f"<= {match['versionEndIncluding']}")
                    else:
                        artifact.fixed.append(f"<= {match['versionEndIncluding']}")
                        artifact.vulnerables.append(f">? {match['versionEndIncluding']}")

                if "versionEndExcluding" in match:
                    if not store_as_fixed:
                        artifact.fixed.append(f">=? {match['versionEndExcluding']}")
                        artifact.vulnerables.append(f"< {match['versionEndExcluding']}")
                    else:
                        artifact.fixed.append(f"< {match['versionEndExcluding']}")
                        artifact.vulnerables.append(f">=? {match['versionEndExcluding']}")

                if "versionStartIncluding" in match:
                    if not store_as_fixed:
                        artifact.fixed.append(f"<? {match['versionStartIncluding']}")
                        artifact.vulnerables.append(f">= {match['versionStartIncluding']}")
                    else:
                        artifact.fixed.append(f">= {match['versionStartIncluding']}")
                        artifact.vulnerables.append(f"<? {match['versionStartIncluding']}")

                if "versionStartExcluding" in match:
                    if not store_as_fixed:
                        artifact.fixed.append(f"<=? {match['versionStartExcluding']}")
                        artifact.vulnerables.append(f"> {match['versionStartExcluding']}")
                    else:
                        artifact.fixed.append(f"> {match['versionStartExcluding']}")
                        artifact.vulnerables.append(f"<=? {match['versionStartExcluding']}")

                if pkg_version != "*" and pkg_version != "-" and pkg_version != "":
                    if store_as_fixed:
                        artifact.fixed.append(f"= {pkg_version}")
                    else:
                        artifact.vulnerables.append(f"= {pkg_version}")
                self.solutions.append(artifact)

    def search_in_nvd(self, nvd_results: dict):
        """
        Generate a list of FixSolution from a result from NVD API
        """
        if "vulnerabilities" in nvd_results:
            for vuln in nvd_results["vulnerabilities"]:
                self.search_in_nvd(vuln)
            return
        if "cve" in nvd_results and "configurations" in nvd_results["cve"]:
            childs = nvd_results["cve"]["configurations"]
            for child in childs:
                self._search_in_nvd_node(child)

    def list_fixing_versions(self) -> list[str]:
        """
        Return a list of all fixing contraint from solutions
        """
        constrains = list(set([f"{solution.package} {x}" for solution in self.solutions for x in solution.fixed]))
        sorted_constrains = sorted(constrains, key=lambda x: x.split()[-1])
        return sorted_constrains

    def list_vulnerables_versions(self) -> list[str]:
        """
        Return a list of all affected versions from solutions
        """
        constrains = list(set([f"{solution.package} {x}" for solution in self.solutions for x in solution.vulnerables]))
        sorted_constrains = sorted(constrains, key=lambda x: x.split()[-1])
        return sorted_constrains

    def list_per_packages(self) -> dict[str, dict[str, list[str]]]:
        """
        Return a dict with fix and affected versions from solutions, sorted by package and scrapper
        """
        solutions: dict = {}
        for solution in self.solutions:
            key = f"{solution.package} ({solution.scrapper})"
            if key not in solutions:
                solutions[key] = {"fix": [], "affected": []}
            for fixed in solution.fixed:
                if fixed not in solutions[key]["fix"]:
                    solutions[key]["fix"].append(fixed)
            for vulnerable in solution.vulnerables:
                if vulnerable not in solutions[key]["affected"]:
                    solutions[key]["affected"].append(vulnerable)
        return solutions
