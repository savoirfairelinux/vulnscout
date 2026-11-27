# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Create the same one-shot host-only permits as the launcher."""

import os
import uuid
from pathlib import Path
from types import SimpleNamespace

from src.helpers.host_mount_helper import request


def host_permit(helper, variant_id, **folders):
    directory = Path(helper.state_dir) / f"permit.{uuid.uuid4().hex[:12]}"
    directory.mkdir(mode=0o700)
    for alias, path in folders.items():
        (directory / alias).write_bytes(b"\0".join((helper.permit_epoch.encode(), str(variant_id).encode(),
                                                   os.fsencode(path))))
    return directory.name


def approve_mount(helper, source, dispatch, variant_id):
    attachment = str(uuid.uuid4())
    staged = dispatch({"op": "stage", "variant_id": variant_id, "alias": "src", "path": str(source),
                       "attachment_id": attachment, "host_permit": host_permit(helper, variant_id, src=source)})
    assert staged["ok"], staged
    activated = dispatch({"op": "activate", **staged["result"], "attachment_id": attachment})
    assert activated["ok"], activated


def approve_on_socket(state, socket, source, variant_id):
    helper = SimpleNamespace(state_dir=str(state), permit_epoch=(state / "permit.epoch").read_text().strip())
    approve_mount(helper, source, lambda payload: request(str(socket), payload), variant_id)
