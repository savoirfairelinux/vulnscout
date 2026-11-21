# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Host folders attached read-only to a variant through the host folder helper."""

from flask import jsonify

from ..controllers import host_mounts
from ..routes._scan_helpers import parse_uuid_or_400
from ..models.variant import Variant
from .agent import _access_error


def _variant_or_error(variant_id: str):
    variant_uuid, err = parse_uuid_or_400(variant_id, 'variant_id')
    if err or variant_uuid is None:
        return None, err
    if Variant.get_by_id(variant_uuid) is None:
        return None, (jsonify({"error": "Variant not found"}), 404)
    return variant_uuid, None


def init_app(app):

    @app.route('/api/variants/<variant_id>/context/mounts', methods=['GET'])
    def list_host_mounts(variant_id):
        """List the host folders attached to a variant with their availability.

        OpenAPI:
        response 200 HostMountList Attached folders and helper availability.
        response 400 Error Invalid variant identifier.
        response 403 Error Local operator access required.
        response 404 Error Variant not found.
        """
        if error := _access_error():
            return error
        variant_uuid, err = _variant_or_error(variant_id)
        if err:
            return err
        assert variant_uuid is not None
        helper_state, mounts = host_mounts.list_mounts(variant_uuid)
        return jsonify({"helper": helper_state, "mounts": mounts})

    @app.route('/api/variants/<variant_id>/context/mounts/<alias>', methods=['DELETE'])
    def detach_host_mount(variant_id, alias):
        """Detach a host folder from a variant; agents lose access immediately.

        OpenAPI:
        path alias string required Alias of the attached folder.
        response 200 HostMountDetached Folder detached; warning reports a helper cleanup problem.
        response 400 Error Invalid variant identifier or alias.
        response 403 Error Local operator access required.
        response 404 Error Variant or alias not found.
        """
        if error := _access_error():
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
