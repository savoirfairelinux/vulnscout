# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .vulnerability import Vulnerability
from .package import Package
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional


VALID_STATUS_OPENVEX = ["under_investigation", "not_affected", "affected", "fixed"]
VALID_STATUS_CDX_VEX = ["in_triage", "false_positive", "not_affected", "exploitable",
                        "resolved", "resolved_with_pedigree"]
STATUS_CDX_VEX_TO_OPENVEX = {
    "in_triage": "under_investigation",
    "false_positive": "not_affected",
    "not_affected": "not_affected",
    "exploitable": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed"
}
STATUS_OPENVEX_TO_CDX_VEX = {
    "under_investigation": "in_triage",
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved"
}

VALID_JUSTIFICATION_OPENVEX = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist"
]
VALID_JUSTIFICATION_CDX_VEX = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control"
]
JUSTIFICATION_CDX_VEX_TO_OPENVEX = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "component_not_present",
    "requires_environment": "vulnerable_code_not_present",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist"
}
JUSTIFICATION_OPENVEX_TO_CDX_VEX = {
    "component_not_present": "requires_dependency",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",
    "inline_mitigations_already_exist": "protected_by_mitigating_control"
}

RESPONSES_CDX_VEX = [
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available"
]


class VulnAssessment:
    """
    Represent the assessment of a vulnerability for a specific set of packages.
    An assessment can be used to track the status of a vulnerability like pending, active, resolved, ...
    A vulnerability can have multiple assessments because assessments are specific to a timestamp.
    """

    def __init__(self, vuln_id: str, packages: Optional[list[str]] = None):
        """Create a new assesment for the given vulnerability (str) and packages (optional)."""
        if isinstance(vuln_id, Vulnerability):
            vuln_id = vuln_id.id
        self.vuln_id = vuln_id
        self.packages: list[str] = []
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.last_update = datetime.now(timezone.utc).isoformat()
        self.id = str(uuid4())

        self.status = "under_investigation"
        self.status_notes = ""
        self.justification = ""
        self.impact_statement = ""
        self.responses: list[str] = []
        self.workaround = ""
        self.workaround_timestamp = ""

        for p in packages or []:
            self.add_package(p)

    def add_package(self, package) -> bool:
        """
        Add a package to the list of packages affected by this vulnerability.
        Can be a string (package.id) or a Package object.
        Return True if the package was added, False if it was already in the list or invalid.
        """
        if isinstance(package, str):
            if package not in self.packages:
                self.packages.append(package)
            return True
        elif isinstance(package, Package):
            if package.id not in self.packages:
                self.packages.append(package.id)
            return True
        return False

    def set_status(self, status: str) -> bool:
        """
        Define status of the vulnerability, using either openVEX or CDX status.
        Return True if the status was set, False if it is invalid.
        """
        if status in VALID_STATUS_OPENVEX or status in VALID_STATUS_CDX_VEX:
            self.status = status
            return True
        return False

    def get_status_openvex(self) -> Optional[str]:
        """Return the status of the vulnerability in OpenVEX format."""
        if self.status in VALID_STATUS_OPENVEX:
            return self.status
        if self.status in STATUS_CDX_VEX_TO_OPENVEX:
            return STATUS_CDX_VEX_TO_OPENVEX[self.status]
        return None

    def get_status_cdx_vex(self) -> Optional[str]:
        """Return the status of the vulnerability in CDX VEX format."""
        if self.status in VALID_STATUS_CDX_VEX:
            return self.status
        if self.status in STATUS_OPENVEX_TO_CDX_VEX:
            return STATUS_OPENVEX_TO_CDX_VEX[self.status]
        return None

    def is_compatible_status(self, status: str) -> bool:
        """Check if the given status is already set or equivalent to the current status."""
        if status == self.status:
            return True
        if status in VALID_STATUS_OPENVEX and self.status in STATUS_CDX_VEX_TO_OPENVEX:
            if STATUS_CDX_VEX_TO_OPENVEX[self.status] == status:
                return True
            return False
        if status in VALID_STATUS_CDX_VEX and self.status in STATUS_OPENVEX_TO_CDX_VEX:
            if STATUS_OPENVEX_TO_CDX_VEX[self.status] == status:
                return True
            return False
        return False

    def set_status_notes(self, notes: str, append: bool = False):
        """Set an arbitrary note about the status of the vulnerability. Replace by default or append if specified."""
        if append and self.status_notes != "":
            if notes not in self.status_notes:
                self.status_notes += '\n' + notes
        else:
            self.status_notes = notes

    def is_justification_required(self) -> bool:
        """Return True if the status requires a justification."""
        return self.status == "not_affected"

    def set_justification(self, justification: str) -> bool:
        """
        Define justification for the status of the vulnerability.
        Return True if the justification was set, False if it is invalid.
        """
        if justification in VALID_JUSTIFICATION_OPENVEX or justification in VALID_JUSTIFICATION_CDX_VEX:
            self.justification = justification
            return True
        return False

    def get_justification_openvex(self) -> Optional[str]:
        """Return the justification of the vulnerability in OpenVEX format."""
        if self.justification in VALID_JUSTIFICATION_OPENVEX:
            return self.justification
        if self.justification in JUSTIFICATION_CDX_VEX_TO_OPENVEX:
            return JUSTIFICATION_CDX_VEX_TO_OPENVEX[self.justification]
        return None

    def get_justification_cdx_vex(self) -> Optional[str]:
        """Return the justification of the vulnerability in CDX VEX format."""
        if self.justification in VALID_JUSTIFICATION_CDX_VEX:
            return self.justification
        if self.justification in JUSTIFICATION_OPENVEX_TO_CDX_VEX:
            return JUSTIFICATION_OPENVEX_TO_CDX_VEX[self.justification]
        return None

    def is_compatible_justification(self, justification: str) -> bool:
        """Check if the given justification is already set or equivalent to the current justification."""
        if justification == self.justification:
            return True
        if justification in VALID_JUSTIFICATION_OPENVEX and self.justification in JUSTIFICATION_CDX_VEX_TO_OPENVEX:
            if JUSTIFICATION_CDX_VEX_TO_OPENVEX[self.justification] == justification:
                return True
            return False
        if justification in VALID_JUSTIFICATION_CDX_VEX and self.justification in JUSTIFICATION_OPENVEX_TO_CDX_VEX:
            if JUSTIFICATION_OPENVEX_TO_CDX_VEX[self.justification] == justification:
                return True
            return False
        return False

    def set_not_affected_reason(self, reason: str, append: bool = False):
        """Set the reason why the vulnerability is not affected. Replace by default or append if specified."""
        if append and self.impact_statement != "":
            if reason not in self.impact_statement:
                self.impact_statement += '\n' + reason
        else:
            self.impact_statement = reason

    def add_response(self, response: str) -> bool:
        """Add a response to the vulnerability assessment and return True if added, False if was already present."""
        if response in RESPONSES_CDX_VEX:
            if response not in self.responses:
                self.responses.append(response)
            return True
        return False

    def remove_response(self, response: str) -> bool:
        """Remove a response from the vulnerability assessment and return True if removed, False if not present."""
        if response in self.responses:
            self.responses.remove(response)
            return True
        return False

    def set_workaround(self, workaround: str, timestamp: Optional[str] = None):
        """
        Set the workaround for the vulnerability and the timestamp of the last update.
        If no timestamp is provided, the current time is used.
        """
        self.workaround = workaround
        self.workaround_timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        """Return a dict representation of this assessment."""
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "packages": self.packages,
            "timestamp": self.timestamp,
            "last_update": self.last_update,
            "status": self.status,
            "status_notes": self.status_notes,
            "justification": self.justification,
            "impact_statement": self.impact_statement,
            "responses": self.responses,
            "workaround": self.workaround,
            "workaround_timestamp": self.workaround_timestamp
        }

    @staticmethod
    def from_dict(data: dict):
        """Create a new assessment from a dict representation."""
        assessment = VulnAssessment(data["vuln_id"], data["packages"])
        assessment.id = data["id"]
        assessment.timestamp = data["timestamp"]
        assessment.last_update = data["last_update"]
        assessment.status = data["status"]
        assessment.status_notes = data["status_notes"] if "status_notes" in data else ""
        assessment.justification = data["justification"] if "justification" in data else ""
        assessment.impact_statement = data["impact_statement"] if "impact_statement" in data else ""
        assessment.responses = data["responses"] if "responses" in data else []
        assessment.workaround = data["workaround"] if "workaround" in data else ""
        assessment.workaround_timestamp = data["workaround_timestamp"] if "workaround_timestamp" in data else ""
        return assessment

    def to_openvex_dict(self) -> Optional[dict]:
        """Return a dict representation of this assessment in OpenVEX format."""
        # OpenVEX must have a valid status
        openvex_status = self.get_status_openvex()
        if openvex_status is None:
            return None
        openvex_justif: Optional[str] = ""

        # If justification set, it must be valid
        if self.justification != "":
            openvex_justif = self.get_justification_openvex()

        # CDX VEX status "false_positive" is equivalent to OpenVEX justification "component_not_present"
        if self.status == "false_positive" and self.justification not in VALID_JUSTIFICATION_OPENVEX:
            openvex_justif = "component_not_present"

        # OpenVEX status "not_affected" must have a justification or impact statement
        if (openvex_status == "not_affected"
           and openvex_justif not in VALID_JUSTIFICATION_OPENVEX
           and self.impact_statement == ""):
            return None

        openvex_impact = self.impact_statement
        # if no user defined impact statement, use CD VEX justification which is more precise
        if self.justification in VALID_JUSTIFICATION_CDX_VEX and self.impact_statement == "":
            openvex_impact = self.justification

        return {
            "vulnerability": {
                "name": self.vuln_id
            },
            "products": [{"@id": p} for p in self.packages],
            "timestamp": self.timestamp,
            "last_updated": self.last_update,

            "status": openvex_status,
            "status_notes": self.status_notes,
            "justification": openvex_justif,
            "impact_statement": openvex_impact,
            "action_statement": self.workaround,
            "action_statement_timestamp": self.workaround_timestamp
        }

    def to_cdx_vex_dict(self) -> Optional[dict]:
        """Return a dict representation of this assessment in CDX VEX format."""
        # CDX VEX must have a valid status
        cdx_state = self.get_status_cdx_vex()
        if cdx_state is None:
            return None

        cdx_justif: Optional[str] = ""
        # If justification set, it must be valid
        if self.justification != "":
            cdx_justif = self.get_justification_cdx_vex()

        # OpenVEX status "not_affected" with justification "component_not_present"
        # is equivalent to CDX VEX status "false_positive"
        if self.status == "not_affected" and self.justification == "component_not_present":
            cdx_state = "false_positive"
            cdx_justif = ""

        cdx_response = self.responses
        if self.workaround in RESPONSES_CDX_VEX:
            cdx_response.append(self.workaround)
        if len(cdx_response) < 1 and self.workaround != "":
            cdx_response = ["workaround_available"]

        detail = self.status_notes
        if self.impact_statement != "" and detail != "":
            detail += "\n" + self.impact_statement
        elif self.impact_statement != "":
            detail = self.impact_statement

        return {
            "workaround": self.workaround,
            "analysis": {
                "state": cdx_state,
                "detail": detail,
                "justification": cdx_justif,
                "response": cdx_response,
                "firstIssued": self.timestamp,
                "lastUpdated": self.last_update
            }
        }

    def merge(self, assessment) -> bool:
        """Merge the given assessment into this one if they are compatible."""
        if assessment.id != self.id:
            return False
        if assessment.vuln_id != self.vuln_id:
            return False
        for p in assessment.packages:
            self.add_package(p)
        if assessment.timestamp > self.timestamp:
            self.timestamp = assessment.timestamp
        if assessment.last_update > self.last_update:
            self.last_update = assessment.last_update
        if not self.is_compatible_status(assessment.status):
            self.set_status(assessment.status)
        if assessment.status_notes != "":
            for note in assessment.status_notes.split('\n'):
                if note not in self.impact_statement:
                    self.set_status_notes(note, True)

        if not self.is_compatible_justification(assessment.justification):
            self.set_justification(assessment.justification)
        if assessment.impact_statement != "":
            for reason in assessment.impact_statement.split('\n'):
                self.set_not_affected_reason(reason, True)

        for r in assessment.responses:
            self.add_response(r)
        if assessment.workaround != "":
            if self.workaround == "":
                self.set_workaround(assessment.workaround, assessment.workaround_timestamp)
            elif self.workaround != assessment.workaround:
                if assessment.workaround_timestamp > self.workaround_timestamp:
                    self.set_workaround(assessment.workaround, assessment.workaround_timestamp)
        return True
