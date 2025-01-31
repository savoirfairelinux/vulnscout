# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

class CVSS:
    """
    CVSS class to represent the CVSS score of a vulnerability.
    The CVSS score is composed of a base score, an exploitability score, and an impact score.
    Scores are derived from vector strings that describe the severity of the vulnerability.
    This class doesn't include calculations for the scores, only parsing and representation.
    """

    def __init__(self, version: str, vector_string: str, author: str,
                 base_score: float, exploitability_score: float, impact_score: float):
        """Create a new CVSS score with the given parameters."""
        self.version = version
        self.vector_string = vector_string
        self.parse_vector_string()
        self.author = author
        self.base_score = base_score
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score

    def __str__(self) -> str:
        """Return a string representation of the CVSS score, using it's 3 scores as identifier."""
        return (f"CVSS(base_score={self.base_score}, "
                + f"exploitability_score={self.exploitability_score}, "
                + f"impact_score={self.impact_score})")

    def __eq__(self, other) -> bool:
        """Check if the CVSS score is equal to another CVSS score, comparing the 3 scores."""
        if not isinstance(other, CVSS):
            return False
        return (self.base_score == other.base_score
                and self.exploitability_score == other.exploitability_score
                and self.impact_score == other.impact_score)

    def __hash__(self):
        """Return a hash of the CVSS score, using it's 3 scores as identifier."""
        return hash((self.base_score, self.exploitability_score, self.impact_score))

    def parse_vector_string(self):
        """Parse the CVSS vector string and set the long/explicit values for each part."""
        parts = self.vector_string.split("/")
        for part in parts:
            if part.startswith("AV:"):
                self.attack_vector = part
                match part:
                    case "AV:N":
                        self.attack_vector_long = "Network"
                    case "AV:A":
                        self.attack_vector_long = "Adjacent Network"
                    case "AV:L":
                        self.attack_vector_long = "Local"
                    case "AV:P":
                        self.attack_vector_long = "Physical"
                    case _:
                        self.attack_vector_long = "Unknown"

            if part.startswith("AC:"):
                self.attack_complexity = part
                match part:
                    case "AC:L":
                        self.attack_complexity_long = "Low"
                    case "AC:M":
                        self.attack_complexity_long = "Medium"
                    case "AC:H":
                        self.attack_complexity_long = "High"
                    case _:
                        self.attack_complexity_long = "Unknown"

            if part.startswith("Au:"):
                self.authentication = part
                match part:
                    case "Au:N":
                        self.authentication_long = "None"
                    case "Au:S":
                        self.authentication_long = "Single"
                    case "Au:M":
                        self.authentication_long = "Multiple"
                    case _:
                        self.authentication_long = "Unknown"

            if part.startswith("PR:"):
                self.privileges_required = part
                match part:
                    case "PR:N":
                        self.privileges_required_long = "None"
                    case "PR:L":
                        self.privileges_required_long = "Low"
                    case "PR:H":
                        self.privileges_required_long = "High"
                    case _:
                        self.privileges_required_long = "Unknown"

            if part.startswith("UI:"):
                self.user_interaction = part
                match part:
                    case "UI:N":
                        self.user_interaction_long = "None"
                    case "UI:R":
                        self.user_interaction_long = "Required"
                    case _:
                        self.user_interaction_long = "Unknown"

            if part.startswith("S:"):
                self.scope = part
                match part:
                    case "S:C":
                        self.scope_long = "Changed"
                    case "S:U":
                        self.scope_long = "Unchanged"
                    case _:
                        self.scope_long = "Unknown"

            if part.startswith("C:"):
                self.confidentiality_impact = part
                match part:
                    case "C:N":
                        self.confidentiality_impact_long = "None"
                    case "C:L":
                        self.confidentiality_impact_long = "Low"
                    case "C:P":
                        self.confidentiality_impact_long = "Partial"
                    case "C:H":
                        self.confidentiality_impact_long = "High"
                    case "C:C":
                        self.confidentiality_impact_long = "Complete"
                    case _:
                        self.confidentiality_impact_long = "Unknown"

            if part.startswith("I:"):
                self.integrity_impact = part
                match part:
                    case "I:N":
                        self.integrity_impact_long = "None"
                    case "I:L":
                        self.integrity_impact_long = "Low"
                    case "I:P":
                        self.integrity_impact_long = "Partial"
                    case "I:H":
                        self.integrity_impact_long = "High"
                    case "I:C":
                        self.integrity_impact_long = "Complete"
                    case _:
                        self.integrity_impact_long = "Unknown"

            if part.startswith("A:"):
                self.availability_impact = part
                match part:
                    case "A:N":
                        self.availability_impact_long = "None"
                    case "A:L":
                        self.availability_impact_long = "Low"
                    case "A:P":
                        self.availability_impact_long = "Partial"
                    case "A:H":
                        self.availability_impact_long = "High"
                    case "A:C":
                        self.availability_impact_long = "Complete"
                    case _:
                        self.availability_impact_long = "Unknown"

    def severity(self) -> str:
        """Return the severity of the CVSS score as text."""
        if self.base_score < 4:
            return "Low"
        elif self.base_score < 7:
            return "Medium"
        elif self.base_score < 9:
            return "High"
        else:
            return "Critical"

    def to_dict(self) -> dict:
        """Export the CVSS score as a dictionary."""
        return {
            "version": self.version,
            "vector_string": self.vector_string,
            "author": self.author,
            "base_score": self.base_score,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "severity": self.severity(),
        }

    @staticmethod
    def from_dict(data: dict):
        """Import a CVSS score from a dictionary."""
        return CVSS(
            data["version"],
            data["vector_string"],
            data["author"],
            data["base_score"],
            data["exploitability_score"],
            data["impact_score"]
        )
