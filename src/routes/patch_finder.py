#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
import re

from ..models.vulnerability import Vulnerability
from ..extensions import db


def init_app(app):

    safe_url_regex = r"[^a-zA-Z0-9_\-\.]"
    """Regex to remove unsafe characters from URLs."""

    @app.route('/api/patch-finder/status', methods=['GET'])
    def get_status():
        vuln_count = db.session.query(Vulnerability).count()
        return {
            "db_ready": True,
            "vulns_count": vuln_count,
        }, 200

    @app.route('/api/patch-finder/scan', methods=['POST'])
    def run_scan():
        if request.method != 'POST':
            return "Only POST requests are accepted", 405
        payload_data = request.get_json()
        if not isinstance(payload_data, list):
            return "Invalid payload, require a list of string", 400
        safe_cve = [re.sub(safe_url_regex, '', s) for s in payload_data]

        response = {}
        for cve in safe_cve:
            rec = Vulnerability.get_by_id(cve)
            if rec is None or not rec.versions_data:
                continue
            versions_data: dict = rec.versions_data
            for (package, data) in versions_data.items():
                pkg_name = package.split(" (")[0]
                scanner = package.split(" ")[-1]
                if pkg_name not in response:
                    response[pkg_name] = {}
                key = f"{cve} {scanner}"
                if key not in response[pkg_name]:
                    response[pkg_name][key] = {"fix": [], "affected": []}
                if "fix" in data:
                    response[pkg_name][key]["fix"].extend(data["fix"])
                if "affected" in data:
                    response[pkg_name][key]["affected"].extend(data["affected"])
        return response, 200
