# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Create the same one-shot host-only permits as the launcher."""

import os
import uuid
from pathlib import Path


def host_permit(helper, variant_id, **folders):
    directory = Path(helper.state_dir) / f"permit.{uuid.uuid4().hex[:12]}"
    directory.mkdir(mode=0o700)
    for alias, path in folders.items():
        (directory / alias).write_bytes(str(variant_id).encode() + b"\0" + os.fsencode(path))
    return directory.name
