# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import re
from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.nvd_db import NVD_DB

_CONFIG_FILE_DEFAULT = '/etc/vulnscout/config.env'
_NVD_API_KEY_PATTERN = re.compile(r'^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$')


def _config_file_path() -> str:
    return os.environ.get('VULNSCOUT_CONFIG', _CONFIG_FILE_DEFAULT)


def _write_config_key(key: str, value: str | None) -> None:
    """Write or remove *key* in the persistent config.env file.

    If *value* is ``None`` or an empty string the key is removed; otherwise
    it is written as ``KEY=value``.  Silently ignores OS errors (e.g. the
    file is on a read-only mount).
    """
    config_file = _config_file_path()
    try:
        dirname = os.path.dirname(config_file)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        existing_lines: list[str] = []
        if os.path.exists(config_file):
            with open(config_file, 'r') as fh:
                existing_lines = [ln for ln in fh.readlines() if not ln.startswith(f'{key}=')]
        with open(config_file, 'w') as fh:
            fh.writelines(existing_lines)
            if value:
                fh.write(f'{key}={value}\n')
    except OSError:
        pass


def init_app(app):

    @app.route('/api/config')
    def get_config():
        project_name = os.environ.get('PROJECT_NAME', '')
        variant_name = os.environ.get('VARIANT_NAME', 'default')
        author_name = os.environ.get('AUTHOR_NAME', 'vulnscout')

        project = None
        variant = None

        if project_name:
            projects = ProjectController.get_all()
            project = next((p for p in projects if p.name == project_name), None)
            if project:
                variants = VariantController.get_by_project(project.id)
                variant = next((v for v in variants if v.name == variant_name), None)

        if not project:
            all_projects = ProjectController.get_all()
            project = all_projects[0] if all_projects else None

        return jsonify({
            "project": ProjectController.serialize(project) if project else None,
            "variant": VariantController.serialize(variant) if variant else None,
            "author": author_name,
        })

    @app.route('/api/config/nvd-api-key', methods=['GET'])
    def get_nvd_api_key():
        key = os.environ.get('NVD_API_KEY', '')
        if not key:
            return jsonify({"has_key": False, "masked_key": ""})
        # Return masked version: show first 4 and last 4 chars only
        if len(key) <= 8:
            masked = '*' * len(key)
        else:
            masked = key[:4] + '*' * (len(key) - 8) + key[-4:]
        return jsonify({"has_key": True, "masked_key": masked})

    @app.route('/api/config/nvd-api-key', methods=['PUT'])
    def set_nvd_api_key():
        data = request.get_json(silent=True)
        if data is None or "api_key" not in data:
            return {"error": "Missing 'api_key' field"}, 400
        api_key = data["api_key"].strip()
        validation_warning = None

        if api_key:
            if not _NVD_API_KEY_PATTERN.fullmatch(api_key):
                return jsonify(
                    {"error": "Invalid NVD API key format. Expected 32 hex chars in 8-4-4-4-12 form."}
                ), 400

            # Validate the key with a single, non-retrying NVD probe call.
            # CVE-2021-44228 (Log4Shell) is a well-known CVE that will always
            # be present in the NVD database and requires no special access.
            nvd = NVD_DB(nvd_api_key=api_key)
            try:
                status_code, _, probe_headers = nvd.api_probe_cve("CVE-2021-44228")
            except Exception:
                return jsonify(
                    {"error": "Could not reach the NVD API to validate the key. "
                              "Check network connectivity and try again."}
                ), 503
            if status_code in {401, 403}:
                return jsonify({"error": "Invalid NVD API key: rejected by the NVD API."}), 400
            header_message = (probe_headers.get("message") or "").lower()
            if "invalid" in header_message and "api" in header_message:
                return jsonify({"error": "Invalid NVD API key: rejected by the NVD API."}), 400

            # When available, rate-limit headers provide stronger confirmation
            # that NVD accepted the key (keyed traffic is higher than anonymous).
            limit_header = probe_headers.get("x-ratelimit-limit")
            if limit_header is not None:
                try:
                    if int(limit_header) <= 5:
                        return jsonify(
                            {"error": "NVD API key appears invalid (anonymous rate limit detected)."}
                        ), 400
                except ValueError:
                    pass
            if status_code != 200:
                # NVD may sporadically return proxy/gateway responses (for example
                # HTTP 404) even when the API key is valid. Only explicit auth
                # failures should block saving the key.
                validation_warning = (
                    f"NVD API key saved, but confirmation probe returned HTTP {status_code}. "
                    "The key will be used for subsequent NVD requests."
                )

        # Persist to config.env so the key survives container restarts.
        _write_config_key('NVD_API_KEY', api_key if api_key else None)

        # Also update the current process environment so running NVD calls
        # (e.g. single-CVE refresh) pick up the key immediately.
        if api_key:
            os.environ['NVD_API_KEY'] = api_key
        else:
            os.environ.pop('NVD_API_KEY', None)
        response_payload = {"status": "ok", "has_key": bool(api_key)}
        if validation_warning:
            response_payload["warning"] = validation_warning
        return jsonify(response_payload)
