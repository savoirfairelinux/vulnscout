# -*- coding: utf-8 -*-
from jinja2 import sandbox, FileSystemLoader, ChoiceLoader
import subprocess
import os
import random
import string


class Templates:
    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]

        self.internal_loader = FileSystemLoader([
            "src/views/templates",
            "views/templates"
        ])
        self.external_loader = FileSystemLoader([
            ".vulnscout/templates",
            "templates"
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
        kwargs["vulnerabilities"] = self.vulnerabilitiesCtrl.to_dict()
        kwargs["assessments"] = self.assessmentsCtrl.to_dict()

        for vuln_obj in kwargs["vulnerabilities"].values():
            last_assessment = None
            for assessment in self.assessmentsCtrl.gets_by_vuln(vuln_obj['id']):
                if last_assessment is None or last_assessment.timestamp < assessment.timestamp:
                    last_assessment = assessment
            if last_assessment:
                vuln_obj['status'] = last_assessment.status
                vuln_obj['last_assessment'] = last_assessment

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

    def filter_status(value, status):
        if type(status) is str:
            return [v for v in value if v["status"] == status]
        if type(status) is list:
            return [v for v in value if v["status"] in status]
        return []

    def filter_severity(value, severity):
        if type(severity) is str:
            return [v for v in value if v["severity"]["severity"].lower() == severity.lower()]
        if type(severity) is list:
            return [v for v in value if v["severity"]["severity"].lower() in map(lambda x: x.lower(), severity)]
        return []

    def filter_as_list(value: dict):
        return value.values()

    def filter_limit(value: list, limit: int):
        return value[:limit]

    def sort_by_epss(value: list):
        if type(value) is dict:
            value = value.values()
        return sorted(value, key=lambda x: x["epss"]["score"], reverse=True)

    def filter_epss_score(value: dict, minimum: float):
        if type(value) is dict:
            value = value.values()
        return [v for v in value if float(v["epss"]["score"]) * 100 >= minimum]
