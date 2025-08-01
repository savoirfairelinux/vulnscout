# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.vulnerability import Vulnerability
from ..controllers.packages import PackagesController
import time
from typing import Optional
from ..controllers.epss_db import EPSS_DB


class VulnerabilitiesController:
    """
    A class to handle a list of vulnerabilities, de-duplicating them and handling low-level stuff.
    Vulnerabilities can be added, removed, retrieved and exported or imported as dictionaries.
    """

    safe_url_regex = r"[^a-zA-Z0-9_\-\.]"
    """Regex to remove unsafe characters from URLs."""

    def __init__(self, pkgCtrl: PackagesController):
        """Take an instance of PackagesController to resolve package dependencies as parameter."""
        self.packagesCtrl = pkgCtrl
        self.vulnerabilities: dict[str, Vulnerability] = {}
        """A dictionary of vulnerabilities, indexed by their id."""
        self.alias_registered: dict[str, str] = {}
        self.epss_db = EPSS_DB("/cache/vulnscout/epss.db")

    def get(self, vuln_id: str):
        """Return a vulnerability by id (str) or None if not found. Also look for aliases."""
        if vuln_id in self.vulnerabilities:
            return self.vulnerabilities[vuln_id]
        if vuln_id in self.alias_registered:
            return self.vulnerabilities[self.alias_registered[vuln_id]]

    def add(self, vulnerability: Vulnerability) -> Optional[Vulnerability]:
        """
        Add a vulnerability to the list, merging it with an existing one if present.
        Return the vulnerability as is if added, or the merged vulnerability if already existing.
        """
        if vulnerability is None:
            return
        if vulnerability.id in self.vulnerabilities:
            self.vulnerabilities[vulnerability.id].merge(vulnerability)
            return self.vulnerabilities[vulnerability.id]
        if vulnerability.id in self.alias_registered:
            self.vulnerabilities[self.alias_registered[vulnerability.id]].merge(vulnerability)
            return self.vulnerabilities[self.alias_registered[vulnerability.id]]

        for alias in vulnerability.aliases:
            if alias in self.vulnerabilities:
                self.register_alias(vulnerability.aliases, alias)
                self.register_alias([vulnerability.id], alias)
                self.vulnerabilities[alias].merge(vulnerability)
                return self.vulnerabilities[alias]
            if alias in self.alias_registered:
                self.register_alias(vulnerability.aliases, self.alias_registered[alias])
                self.register_alias([vulnerability.id], self.alias_registered[alias])
                self.vulnerabilities[self.alias_registered[alias]].merge(vulnerability)
                return self.vulnerabilities[self.alias_registered[alias]]

        self.register_alias(vulnerability.aliases, vulnerability.id)
        self.vulnerabilities[vulnerability.id] = vulnerability
        return self.vulnerabilities[vulnerability.id]

    def register_alias(self, alias: list, vuln_id: str):
        """Allow to register an list of alias pointing to a vulnerability id."""
        for a in alias:
            if a not in self.alias_registered and a != vuln_id:
                self.alias_registered[a] = vuln_id

    def remove(self, vuln_id: str) -> bool:
        """Remove a vulnerability by id (str) and return True if removed, False if not found."""
        if vuln_id in self.vulnerabilities:
            del self.vulnerabilities[vuln_id]
            aliases_to_remove = []
            for alias, id in self.alias_registered.items():
                if id == vuln_id:
                    aliases_to_remove.append(alias)

            for alias in aliases_to_remove:
                del self.alias_registered[alias]
            return True
        return False

    def fetch_epss_scores(self):
        start_time = time.time()
        nb_vuln = 0

        for vuln in self.vulnerabilities.values():
            result = self.epss_db.get_score(vuln.id)
            if result:
                vuln.set_epss(result['score'], result['percentile']),
                nb_vuln += 1

        print(f"Fetched EPSS data for {nb_vuln} vulnerabilities from local DB in {time.time() - start_time} seconds.")

    def to_dict(self) -> dict:
        """Export the list of vulnerabilities as a dictionary of dictionaries."""
        return {k: v.to_dict() for k, v in self.vulnerabilities.items()}

    @staticmethod
    def from_dict(pkgCtrl, data: dict):
        """
        Import a list of vulnerabilities from a dictionary of dictionaries.
        Require a PackagesController instance.
        Return a new instance of VulnerabilitiesController.
        """
        item = VulnerabilitiesController(pkgCtrl)
        for k, v in data.items():
            item.add(Vulnerability.from_dict(v))
        return item

    def resolve_id(self, vuln_id: str) -> dict:
        """Return a dictionary with the id of the vulnerability and a boolean to indicate if it is an alias."""
        if vuln_id in self.vulnerabilities:
            return {"is_alias": False, "id": vuln_id}
        if vuln_id in self.alias_registered:
            return {"is_alias": True, "id": self.alias_registered[vuln_id]}
        return {"is_alias": False, "id": None}

    def __contains__(self, item):
        """
        Check if the item is in the vulnerabilities list.
        The item can be a Vulnerability class or a string representation of Vulnerability.id.
        """
        if isinstance(item, str):
            if item in self.vulnerabilities:
                return True
            if item in self.alias_registered:
                return True
        elif isinstance(item, Vulnerability):
            if item.id in self.vulnerabilities:
                return True
            if item.id in self.alias_registered:
                return True
        return False

    def __len__(self):
        """Return the number of vulnerabilities in the list."""
        return len(self.vulnerabilities)

    def __iter__(self):
        """Allow iteration over the list of vulnerabilities."""
        return iter(self.vulnerabilities.values())
