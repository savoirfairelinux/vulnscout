# -*- coding: utf-8 -*-
from datetime import datetime, timezone


class TimeEstimates:
    """
    TimeEstimates class to handle custom JSON file format and parse it.
    Support reading, parsing and writing from/to JSON format.
    """

    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

    def load_from_dict(self, data: dict):
        if "tasks" in data:
            for (task_id, task) in data["tasks"].items():

                vuln = self.vulnerabilitiesCtrl.get(task_id)
                if vuln is not None:
                    vuln.set_effort(task["optimistic"], task["likely"], task["pessimistic"])
                    self.vulnerabilitiesCtrl.add(vuln)  # will merge

    def to_dict(self) -> dict:
        output = {
            "author": "Savoir-faire Linux",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "tasks": {}
        }
        for (vuln_id, vuln) in self.vulnerabilitiesCtrl.vulnerabilities.items():
            if not (vuln.effort["optimistic"] is None
               or vuln.effort["likely"] is None
               or vuln.effort["pessimistic"] is None):

                output["tasks"][vuln_id] = {  # type: ignore
                    "optimistic": str(vuln.effort["optimistic"]),
                    "likely": str(vuln.effort["likely"]),
                    "pessimistic": str(vuln.effort["pessimistic"])
                }
        return output
