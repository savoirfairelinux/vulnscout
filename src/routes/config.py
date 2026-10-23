# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import re
import fcntl
import shlex
from flask import jsonify, request

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.nvd_db import NVD_DB
from ..helpers.verbose import verbose
from ..helpers.scan_configuration import (
    read_scan_configuration, validate_scan_configuration, write_scan_configuration,
)

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
# Accepts: off | disabled | plain-bytes | <digits><unit>
# Units: B, KiB/MiB/GiB/TiB/PiB/EiB  and their SI equivalents KB/MB/…
_GRYPE_MEMLIMIT_RE = re.compile(
    r'^(?:off|disabled|\d+(?:[KMGTPE]iB|[KMGTPE]B|B)?)$',
    re.IGNORECASE,
)


def _config_file_path() -> str:
    config_home = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
    return os.environ.get('VULNSCOUT_CONFIG', os.path.join(config_home, 'vulnscout', 'config.env'))


def _has_control_characters(value: str) -> bool:
    return any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)


def _mask_nvd_api_key(key: str) -> str:
    if not key:
        return ''
    if len(key) <= 8:
        return '*' * len(key)
    return key[:4] + '*' * (len(key) - 8) + key[-4:]


def _write_config_key(key: str, value: str | None) -> bool:
    """Write or remove *key* in the persistent config.env file.

    If *value* is ``None`` or an empty string the key is removed; otherwise
    it is written as a shell-quoted assignment.
    """
    config_file = _config_file_path()
    try:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) or (
            value is not None and _has_control_characters(value)
        ):
            return False
        dirname = os.path.dirname(config_file)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(config_file, 'a+', opener=lambda path, flags: os.open(path, flags, 0o600)) as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                os.fchmod(fh.fileno(), 0o600)
                fh.seek(0)
                existing_lines = [ln for ln in fh.readlines() if not ln.startswith(f'{key}=')]
                fh.seek(0)
                fh.truncate(0)
                fh.writelines(existing_lines)
                if value:
                    fh.write(f'{key}={shlex.quote(value)}\n')
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return True
    except Exception as e:
        verbose(f"[_write_config_key {key!r}] {e}")
        return False


def persist_env_keys(updates: dict[str, str | None]) -> tuple[bool, str | None]:
    """Persist environment updates to config.env and os.environ atomically."""
    snapshot: dict[str, str | None] = {
        env_key: os.environ.get(env_key)
        for env_key in updates
    }
    written_env_keys: list[str] = []
    for env_key, persisted_value in updates.items():
        if not _write_config_key(env_key, persisted_value):
            for prev_env_key in written_env_keys:
                prev_val = snapshot[prev_env_key]
                _write_config_key(prev_env_key, prev_val if prev_val else None)
                if prev_val is None:
                    os.environ.pop(prev_env_key, None)
                else:
                    os.environ[prev_env_key] = prev_val
            return False, env_key
        if persisted_value is None:
            os.environ.pop(env_key, None)
        else:
            os.environ[env_key] = persisted_value
        written_env_keys.append(env_key)
    return True, None


def init_app(app):

    @app.route('/api/config/native-packages', methods=['GET', 'PUT'])
    def native_package_configuration():
        """Read or replace global native-package scan defaults.

        OpenAPI:
        PUT body ScanConfiguration required Global exclude_native and native_package_exceptions.
        response 200 ScanConfiguration Global native-package scan defaults.
        response 400 Error Invalid scan configuration.
        response 500 Error Configuration could not be accessed.
        """
        configuration = None
        if request.method == 'PUT':
            try:
                configuration = validate_scan_configuration(request.get_json(silent=True))
            except ValueError as error:
                return jsonify({"error": str(error)}), 400
        try:
            if request.method == 'PUT':
                return jsonify(write_scan_configuration(None, configuration))
            return jsonify(read_scan_configuration())
        except (OSError, ValueError):
            app.logger.exception("Unable to access global native-package configuration")
            return jsonify({"error": "Unable to access global native-package configuration"}), 500

    @app.route('/api/config', methods=['GET'])
    def get_config():
        """Return active UI and scanning configuration values.

        OpenAPI:
        response 200 Config Active configuration payload.
        """
        project_name = os.environ.get('PROJECT_NAME', '')
        variant_name = os.environ.get('VARIANT_NAME', 'default')
        author_name = os.environ.get('AUTHOR_NAME', 'vulnscout')
        product_name = os.environ.get('PRODUCT_NAME', '')
        client_name = os.environ.get('CLIENT_NAME', '')
        contact_email = os.environ.get('CONTACT_EMAIL', '')

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

        grype_memlimit = os.environ.get('GRYPE_MEMLIMIT', '')
        return jsonify({
            "project": ProjectController.serialize(project) if project else None,
            "variant": VariantController.serialize(variant) if variant else None,
            "product_name": product_name,
            "author_name": author_name,
            "client_name": client_name,
            "contact_email": contact_email,
            "grype_memlimit": grype_memlimit,
        })

    @app.route('/api/config', methods=['PATCH'])
    def patch_config():
        """Update mutable configuration keys and persist them to config.env.

        OpenAPI:
        body ConfigUpdate required Mutable configuration keys.
        response 200 Config Updated configuration payload.
        response 400 Error Invalid request payload.
        """
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Expected a JSON object body."}), 400

        allowed_keys = {
            "product_name": "PRODUCT_NAME",
            "author_name": "AUTHOR_NAME",
            "client_name": "CLIENT_NAME",
            "contact_email": "CONTACT_EMAIL",
            "grype_memlimit": "GRYPE_MEMLIMIT",
        }

        for key in data.keys():
            if key not in allowed_keys:
                return jsonify({"error": f"Unsupported config key: {key}"}), 400

        # First pass: validate all values before writing anything.
        validated: dict[str, tuple[str, str | None]] = {}
        for key, env_key in allowed_keys.items():
            if key not in data:
                continue
            value = data[key]
            if value is None:
                value = ""
            if not isinstance(value, str):
                return jsonify({"error": f"Invalid value for '{key}': expected string."}), 400

            normalized_value = value.strip()

            if key == "contact_email" and normalized_value:
                if not _EMAIL_RE.match(normalized_value):
                    return jsonify({"error": "Invalid email address format for 'contact_email'."}), 400

            if key == "grype_memlimit" and normalized_value:
                if not _GRYPE_MEMLIMIT_RE.match(normalized_value):
                    return jsonify({
                        "error": "Invalid GRYPE_MEMLIMIT value. "
                                 "Use a Go memory string (e.g. 4GiB, 512MiB, 1073741824) "
                                 "or 'off' / 'disabled' to remove the cap."
                    }), 400
            validated[key] = (env_key, normalized_value if normalized_value else None)

        updates = {
            env_key: persisted_value
            for _, (env_key, persisted_value) in validated.items()
        }
        ok, failed_key = persist_env_keys(updates)
        if not ok:
            key = next((cfg_key for cfg_key, env_key in allowed_keys.items() if env_key == failed_key), failed_key)
            return jsonify({"error": f"Failed to persist '{key}' to config.env."}), 500

        return get_config()

    @app.route('/api/config/nvd-api-key', methods=['GET'])
    def get_nvd_api_key():
        """Return NVD API key presence and masked representation.

        OpenAPI:
        response 200 NvdKeyStatus Masked NVD API key status.
        """
        key = os.environ.get('NVD_API_KEY', '')
        if not key:
            return jsonify({"has_key": False, "masked_key": ""})
        return jsonify({"has_key": True, "masked_key": _mask_nvd_api_key(key)})

    @app.route('/api/config/nvd-api-key', methods=['PUT'])
    def set_nvd_api_key():
        """Validate and store a new NVD API key.

        OpenAPI:
        body NvdKeyUpdate required API key to validate and store.
        response 200 NvdKeyStatus Stored NVD API key status.
        response 400 Error Invalid NVD API key payload.
        response 503 Error NVD API unavailable for validation.
        """
        data = request.get_json(silent=True)
        if data is None or "api_key" not in data:
            return {"error": "Missing 'api_key' field"}, 400

        if not isinstance(data["api_key"], str):
            return jsonify({"error": "Field 'api_key' must be a string."}), 400

        api_key = data["api_key"].strip()
        validation_warning = None

        if api_key:
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
        if not _write_config_key('NVD_API_KEY', api_key if api_key else None):
            return jsonify({"error": "Failed to persist NVD API key to config.env."}), 500

        # Also update the current process environment so running NVD calls
        # (e.g. single-CVE refresh) pick up the key immediately.
        if api_key:
            os.environ['NVD_API_KEY'] = api_key
        else:
            os.environ.pop('NVD_API_KEY', None)
        response_payload = {
            "status": "ok",
            "has_key": bool(api_key),
            "masked_key": _mask_nvd_api_key(api_key),
        }
        if validation_warning:
            response_payload["warning"] = validation_warning
        return jsonify(response_payload)
