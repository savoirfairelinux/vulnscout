# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Host folders attached read-only to a variant through the host folder helper."""

import logging

from flask import jsonify, request

from ..controllers import host_mounts
from ..controllers.host_mounts import HostMountConflict
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..routes._scan_helpers import parse_uuid_or_400
from ..models.variant import Variant
from .agent import _access_error as _operator_access_error

logger = logging.getLogger(__name__)


def _helper_error(exc: Exception):
    if isinstance(exc, HostHelperUnavailable):
        return jsonify({"error": exc.message, "helper_available": False}), 503
    assert isinstance(exc, HostHelperError)
    return jsonify({"error": exc.message, "code": exc.code}), exc.http_status


def _variant_or_error(variant_id: str):
    variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
    if err or variant_uuid is None:
        return None, err
    if Variant.get_by_id(variant_uuid) is None:
        return None, (jsonify({"error": "Variant not found"}), 404)
    return variant_uuid, None


def init_app(app):

    @app.route('/api/context/host-roots', methods=['GET'])
    def get_host_roots():
        """Report whether the host folder helper runs and which host roots the operator approved.

        OpenAPI:
        response 200 HostHelperStatus Helper availability and approved host roots.
        """
        if error := _operator_access_error():
            return error
        return jsonify(host_mounts.helper_status())

    @app.route('/api/context/host-roots/browse', methods=['GET'])
    def browse_host_roots():
        """List the subfolders of a host folder inside an approved root, for the folder picker.

        Without path, lists the approved roots. Hidden/sensitive names and links are not listed.

        OpenAPI:
        query path string optional Absolute host folder inside an approved root.
        response 200 HostFolderListing Approved roots or subfolders of the requested folder.
        response 400 Error Invalid path.
        response 403 Error Path is outside the approved roots.
        response 404 Error Folder not found.
        response 409 Error Folder is not readable by the helper.
        response 503 Error Host folder helper is not running.
        """
        if error := _operator_access_error():
            return error
        try:
            return jsonify(host_mounts.helper.call("browse", path=request.args.get("path", "")))
        except (HostHelperUnavailable, HostHelperError) as exc:
            return _helper_error(exc)

    @app.route('/api/variants/<variant_id>/context/mounts', methods=['GET'])
    def list_host_mounts(variant_id):
        """List the host folders attached to a variant with their availability.

        OpenAPI:
        response 200 HostMountList Attached folders and helper availability.
        response 400 Error Invalid variant identifier.
        response 404 Error Variant not found.
        """
        if error := _operator_access_error():
            return error
        variant_uuid, err = _variant_or_error(variant_id)
        if err:
            return err
        assert variant_uuid is not None
        mounts = host_mounts.list_mounts(variant_uuid)
        helper_state, statuses = host_mounts.availability(variant_uuid, mounts)
        return jsonify({
            "helper": helper_state,
            "mounts": [{**mount.to_dict(), **statuses[mount.alias]} for mount in mounts],
        })

    @app.route('/api/variants/<variant_id>/context/mounts', methods=['POST'])
    def attach_host_mount(variant_id):
        """Attach a host folder inside an approved root to a variant under an alias.

        Nothing is copied: agents browse the folder read-only through the host folder helper.

        OpenAPI:
        body alias string required Short identifier, unique per variant (lowercase letters, digits, _ or -).
        body host_path string required Absolute host folder inside an operator-approved root.
        response 200 HostMount The alias was already attached to this folder.
        response 201 HostMount Folder attached.
        response 400 Error Invalid alias or path.
        response 403 Error Path is outside the approved roots.
        response 404 Error Variant or folder not found.
        response 409 Error Alias already attached to another folder, or folder unavailable.
        response 503 Error Host folder helper is not running.
        """
        if error := _operator_access_error():
            return error
        variant_uuid, err = _variant_or_error(variant_id)
        if err:
            return err
        assert variant_uuid is not None
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Expected a JSON object body."}), 400
        alias, host_path = data.get("alias"), data.get("host_path")
        if not isinstance(alias, str):
            return jsonify({"error": "alias must be a string."}), 400
        if not isinstance(host_path, str):
            return jsonify({"error": "host_path must be an absolute host path."}), 400
        try:
            mount, created = host_mounts.attach(variant_uuid, alias, host_path)
        except HostMountConflict as exc:
            return jsonify({"error": str(exc)}), 409
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except (HostHelperUnavailable, HostHelperError) as exc:
            return _helper_error(exc)
        body = {**mount.to_dict(), "status": "available", "message": "Folder is available read-only."}
        return jsonify(body), 201 if created else 200

    @app.route('/api/variants/<variant_id>/context/mounts/<alias>', methods=['DELETE'])
    def detach_host_mount(variant_id, alias):
        """Detach a host folder from a variant; agents lose access immediately.

        OpenAPI:
        path alias string required Alias of the attached folder.
        response 200 HostMountDetached Folder detached; warning reports a helper cleanup problem.
        response 400 Error Invalid variant identifier or alias.
        response 404 Error Variant or alias not found.
        """
        if error := _operator_access_error():
            return error
        variant_uuid, err = _variant_or_error(variant_id)
        if err:
            return err
        assert variant_uuid is not None
        try:
            existed, warning = host_mounts.detach(variant_uuid, alias)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not existed:
            return jsonify({"error": f"No folder is attached as '{alias}' for this variant."}), 404
        return jsonify({"alias": alias, "detached": True, "warning": warning})
