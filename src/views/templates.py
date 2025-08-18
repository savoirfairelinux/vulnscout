# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from jinja2 import sandbox, FileSystemLoader, ChoiceLoader
import subprocess
import os
import random
import string
from datetime import datetime, timezone
from typing import Any, List
from ..models.iso8601_duration import Iso8601Duration


class Templates:
    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.internal_loader = FileSystemLoader([
            template_dir,
            "views/templates"
        ])
        self.external_loader = FileSystemLoader([
            ".vulnscout/templates",
            "templates",
            "/scan/templates"
        ])

        self.env = sandbox.ImmutableSandboxedEnvironment(
            loader=ChoiceLoader([
                self.external_loader,
                self.internal_loader
            ]),
            autoescape=False
        )
        self.extensions = TemplatesExtensions(self.env)

    def render(self, template_name, **kwargs):
        template = self.env.get_template(template_name)
        kwargs["packages"] = self.packagesCtrl.to_dict()
        kwargs["unfiltered_vulnerabilities"] = self.vulnerabilitiesCtrl.to_dict()
        kwargs["vulnerabilities"] = {}
        kwargs["unfiltered_assessments"] = self.assessmentsCtrl.to_dict()
        kwargs["assessments"] = {}
        filter_date = None
        if "ignore_before" in kwargs and kwargs["ignore_before"] != "1970-01-01T00:00":
            filter_date = datetime.fromisoformat(kwargs["ignore_before"]).astimezone(timezone.utc)
        filter_epss = None
        if "only_epss_greater" in kwargs and kwargs["only_epss_greater"] >= 0.01:
            filter_epss = kwargs["only_epss_greater"] / 100

        if "scan_date" not in kwargs:
            kwargs["scan_date"] = "unknown date"  # don't use actual datetime by default.

        for vuln_obj in kwargs["unfiltered_vulnerabilities"].values():
            vuln_assessments = []
            for assessment in self.assessmentsCtrl.gets_by_vuln(vuln_obj['id']):
                vuln_assessments.append(assessment.to_dict())

            vuln_assessments = sorted(vuln_assessments, key=lambda x: x["timestamp"], reverse=True)  # type: ignore
            if len(vuln_assessments) >= 1:
                vuln_obj['unfiltered_assessments'] = vuln_assessments
                vuln_obj['assessments'] = []
                if filter_date is not None:
                    for assessment in vuln_assessments:
                        assess_date = datetime.fromisoformat(assessment["timestamp"]).astimezone(timezone.utc)
                        if assess_date >= filter_date:
                            vuln_obj['assessments'].append(assessment)
                else:
                    vuln_obj['assessments'] = vuln_assessments

                vuln_obj['last_assessment'] = vuln_assessments[0]
                vuln_obj['status'] = vuln_assessments[0]['status']

            if len(vuln_obj['assessments']) > 0:
                try:
                    epss_score = float((vuln_obj.get("epss", {}).get("score")) or 0.0)
                    if (filter_epss is None or epss_score >= filter_epss):
                        kwargs["vulnerabilities"][vuln_obj['id']] = vuln_obj
                except Exception:
                    pass

        if filter_date is not None:
            for assessment in kwargs["unfiltered_assessments"].values():
                assess_date = datetime.fromisoformat(assessment["timestamp"]).astimezone(timezone.utc)
                if assess_date >= filter_date:
                    kwargs['assessments'][assessment["id"]] = assessment
        else:
            kwargs["assessments"] = kwargs["unfiltered_assessments"]

        return template.render(**kwargs)

    def adoc_to_pdf(self, adoc: str) -> bytes:
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        with open(f"{random_name}.adoc", "w+") as f:
            f.write(adoc)

        execution = subprocess.run(["asciidoctor-pdf", f"{random_name}.adoc"], capture_output=True)
        if execution.returncode != 0:
            print(execution.stdout)
            print(execution.stderr)
            try:
                os.remove(f"{random_name}.adoc")
                os.remove(f"{random_name}.pdf")
            finally:
                raise Exception("Error converting adoc to pdf: asciidoctor returned non-zero exit code")

        with open(f"{random_name}.pdf", "rb") as f:
            pdf = f.read()
        os.remove(f"{random_name}.adoc")
        os.remove(f"{random_name}.pdf")
        return pdf

    def adoc_to_html(self, adoc: str) -> bytes:
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        adoc_path = f"{random_name}.adoc"
        html_path = f"{random_name}.html"
        with open(adoc_path, "w+") as f:
            f.write(adoc)

        # Use asciidoctor to render HTML
        execution = subprocess.run(["asciidoctor", adoc_path], capture_output=True)
        if execution.returncode != 0:
            print(execution.stdout)
            print(execution.stderr)
            try:
                if os.path.exists(adoc_path):
                    os.remove(adoc_path)
                if os.path.exists(html_path):
                    os.remove(html_path)
            finally:
                raise Exception("Error converting adoc to html: asciidoctor returned non-zero exit code")

        with open(html_path, "rb") as f:
            html = f.read()
        os.remove(adoc_path)
        os.remove(html_path)
        return html

    def list_documents(self):
        docs = []
        try:
            internal = self.internal_loader.list_templates()
            docs.extend([{"id": doc, "is_template": True, "category": ["built-in"]} for doc in internal])
            external = self.external_loader.list_templates()
            docs.extend([{"id": doc, "is_template": True, "category": ["custom"]} for doc in external])
        except Exception as e:
            print(e)
        return docs


class TemplatesExtensions:
    def __init__(self, jinjaEnv):
        jinjaEnv.filters["status"] = TemplatesExtensions.filter_status
        jinjaEnv.filters["status_pending"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["under_investigation", "in_triage"]
        )
        jinjaEnv.filters["status_fixed"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["fixed", "resolved", "resolved_with_pedigree"]
        )
        jinjaEnv.filters["status_ignored"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["not_affected", "false_positive"]
        )
        jinjaEnv.filters["status_affected"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["affected", "exploitable"]
        )

        jinjaEnv.filters["status_active"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["affected", "exploitable", "under_investigation", "in_triage"]
        )
        jinjaEnv.filters["status_inactive"] = lambda value: TemplatesExtensions.filter_status(
            value,
            ["not_affected", "false_positive", "fixed", "resolved", "resolved_with_pedigree"]
        )
        jinjaEnv.filters["severity"] = TemplatesExtensions.filter_severity
        jinjaEnv.filters["as_list"] = TemplatesExtensions.filter_as_list
        jinjaEnv.filters["limit"] = TemplatesExtensions.filter_limit
        jinjaEnv.filters["sort_by_epss"] = TemplatesExtensions.sort_by_epss
        jinjaEnv.filters["epss_score"] = TemplatesExtensions.filter_epss_score
        jinjaEnv.filters["sort_by_effort"] = TemplatesExtensions.sort_by_effort
        jinjaEnv.filters["print_iso8601"] = TemplatesExtensions.print_iso8601
        jinjaEnv.filters["sort_by_last_modified"] = TemplatesExtensions.sort_by_last_modified

    @staticmethod
    def filter_status(value: list, status: str | list[str]) -> list:
        if type(status) is str:
            return [v for v in value if v["status"] == status]
        if type(status) is list:
            return [v for v in value if v["status"] in status]
        return []

    @staticmethod
    def filter_severity(value: list, severity: str | list[str]) -> list:
        if type(severity) is str:
            return [v for v in value if v["severity"]["severity"].lower() == severity.lower()]
        if type(severity) is list:
            return [v for v in value if v["severity"]["severity"].lower() in map(lambda x: x.lower(), severity)]
        return []

    @staticmethod
    def filter_as_list(value: dict) -> list:
        return list(value.values())

    @staticmethod
    def filter_limit(value: list, limit: int) -> list:
        return value[:limit]

    @staticmethod
    def sort_by_epss(value: dict[str, dict[str, Any]] | list[dict[str, Any]]) -> list[dict[str, Any]]:
        vals: List[dict[str, Any]]
        if isinstance(value, dict):
            vals = list(value.values())
        else:
            vals = list(value)
        return sorted(
            vals,
            key=lambda x: float(((x.get("epss") or {}).get("score")) or 0.0),
            reverse=True
        )

    @staticmethod
    def filter_epss_score(value: dict[str, dict[str, Any]] | list[dict[str, Any]], minimum: float
                          ) -> list[dict[str, Any]]:
        vals: List[dict[str, Any]]
        if isinstance(value, dict):
            vals = list(value.values())
        else:
            vals = list(value)
        result: List[dict[str, Any]] = []
        for v in vals:
            score = 0.0
            try:
                epss_raw = (v.get("epss") or {}).get("score")
                score = float(epss_raw or 0.0) * 100
            except Exception:
                score = 0.0
            if score >= minimum:
                result.append(v)
        return result

    @staticmethod
    def sort_by_effort(value: dict[str, dict] | list[dict]) -> list[dict]:
        if type(value) is dict:
            value = list(value.values())
        return sorted(
            value,  # type: ignore
            key=lambda x: Iso8601Duration(x["effort"]["likely"] or "P0D").total_seconds,
            reverse=True
        )

    @staticmethod
    def print_iso8601(value: str) -> str:
        if type(value) is not str:
            return "N/A"
        if value.startswith("P"):
            return Iso8601Duration(value).human_readable()
        return datetime.fromisoformat(value).strftime("%Y %b %d - %H:%M")

    @staticmethod
    def sort_by_last_modified(value: dict[str, dict] | list[dict]) -> list[dict]:
        if type(value) is dict:
            value = list(value.values())
        return sorted(value, key=lambda x: x["last_assessment"]["timestamp"] or "", reverse=True)  # type: ignore
