# -*- coding: utf-8 -*-
from jinja2 import sandbox, FileSystemLoader


class Templates:
    def __init__(self, controllers):
        self.packagesCtrl = controllers["packages"]
        self.vulnerabilitiesCtrl = controllers["vulnerabilities"]
        self.assessmentsCtrl = controllers["assessments"]
        self.env = sandbox.ImmutableSandboxedEnvironment(
            loader=FileSystemLoader([
                ".vulnscout/templates",
                "templates",
                "src/views/templates",
                "views/templates"
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
