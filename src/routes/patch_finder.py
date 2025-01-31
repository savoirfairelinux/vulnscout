#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from flask import request
import json
import re
import sqlite3

NVD_DB_PATH = "/cache/vulnscout/nvd.db"
DB_MODEL_VERSION = "nvd2.0-vulnscout1.1"


def init_app(app):

    safe_url_regex = r"[^a-zA-Z0-9_\-\.]"
    """Regex to remove unsafe characters from URLs."""

    if "NVD_DB_PATH" not in app.config:
        app.config["NVD_DB_PATH"] = NVD_DB_PATH

    @app.route('/api/patch-finder/status', methods=['GET'])
    def get_status():
        conn = sqlite3.connect(app.config["NVD_DB_PATH"])
        cursor = conn.cursor()
        version = cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'version';").fetchone()
        write_flag = cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'writing_flag';").fetchone()
        last_index = cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'last_index';").fetchone()
        last_modified = cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'last_modified';").fetchone()
        conn.close()
        return {
            "api_version": DB_MODEL_VERSION,
            "db_version": version[0] if version is not None else None,
            "db_ready": write_flag[0] == "false" if write_flag is not None else False,
            "vulns_count": int(last_index[0]) if last_index is not None else 0,
            "last_modified": last_modified[0] if last_modified is not None else None
        }, 200

    @app.route('/api/patch-finder/scan', methods=['POST'])
    def run_scan():
        if request.method != 'POST':
            return "Only POST requests are accepted", 405
        payload_data = request.get_json()
        if not isinstance(payload_data, list):
            return "Invalid payload, require a list of string", 400
        safe_cve = [re.sub(safe_url_regex, '', s) for s in payload_data]

        conn = sqlite3.connect(app.config["NVD_DB_PATH"])
        cursor = conn.cursor()
        res = cursor.execute("SELECT value FROM nvd_metadata WHERE key = 'version';").fetchone()
        if res is None or res[0] != DB_MODEL_VERSION:
            return "DB version mismatch", 500

        response = {}
        for cve in safe_cve:
            res = cursor.execute("SELECT versions_data FROM nvd_vulns WHERE id = ?;", (cve,)).fetchone()
            if res is None:
                continue
            versions_data: dict = json.loads(res[0])
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
