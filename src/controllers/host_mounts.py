# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Attach, list and detach host folders for a variant.

The database is the source of truth for attachments; the host folder helper validates
each folder against the operator-approved roots and serves its content read-only.
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..helpers import host_mounts as helper
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..models.host_mount import MOUNT_FILE_ID_PREFIX, HostMount
from ..models.variant_context import VariantContext

logger = logging.getLogger(__name__)

MAX_MOUNTS_PER_VARIANT = helper.protocol.MAX_ATTACHMENTS_PER_VARIANT


class HostMountConflict(ValueError):
    """The alias is already attached to another folder, or the variant has too many folders."""


def mount_alias(file_id: str) -> str | None:
    """The alias of a ``mount:<alias>`` source ID, else None."""
    if not file_id.startswith(MOUNT_FILE_ID_PREFIX):
        return None
    return helper.validate_alias(file_id[len(MOUNT_FILE_ID_PREFIX):])


def list_mounts(variant_id: uuid.UUID) -> list[HostMount]:
    return HostMount.get_by_variant(variant_id)


def attach(variant_id: uuid.UUID, alias: str, host_path: str) -> tuple[HostMount, bool]:
    """Register a folder with the helper, then store it; returns (mount, created).

    Re-attaching the same folder under the same alias is a no-op.
    """
    helper.validate_alias(alias)
    if not isinstance(host_path, str) or not host_path.strip():
        raise ValueError("host_path must be a non-empty absolute host path.")
    existing = HostMount.get(variant_id, alias)
    if existing is None and len(HostMount.get_by_variant(variant_id)) >= MAX_MOUNTS_PER_VARIANT:
        raise HostMountConflict(f"A variant can have at most {MAX_MOUNTS_PER_VARIANT} attached folders.")
    if existing is not None:
        if host_path == existing.host_path:
            # Revalidate the stored path without following a moved folder to a new target.
            helper.call("attach", variant_id=str(variant_id), alias=alias, path=existing.host_path, exact=True)
        elif helper.call("browse", path=host_path)["path"] != existing.host_path:
            raise HostMountConflict(
                f"Alias '{alias}' is already attached to {existing.host_path}; detach it first."
            )
        return existing, False
    result = helper.call("attach", variant_id=str(variant_id), alias=alias, path=host_path)
    mount = HostMount(variant_id=variant_id, alias=alias, host_path=result["path"],
                      created_at=datetime.now(timezone.utc))
    try:
        db.session.add(mount)
        VariantContext.touch(variant_id, commit=False)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raced = HostMount.get(variant_id, alias)
        if raced is not None and raced.host_path == result["path"]:
            return raced, False
        _forget(variant_id, alias)
        raise HostMountConflict(f"Alias '{alias}' is already attached for this variant.") from None
    except Exception:
        db.session.rollback()
        _forget(variant_id, alias)
        raise
    return mount, True


def _forget(variant_id: uuid.UUID, alias: str) -> None:
    try:
        helper.call("detach", variant_id=str(variant_id), alias=alias)
    except (HostHelperError, HostHelperUnavailable):
        logger.warning("Could not remove host folder alias %s from the helper registry", alias)


def detach(variant_id: uuid.UUID, alias: str) -> tuple[bool, str | None]:
    """Delete the attachment; returns (existed, helper warning).

    Access is revoked as soon as the row is deleted, because every request is checked
    against the database first. The helper registry is cleaned up best-effort and
    reconciled on the next availability check.
    """
    helper.validate_alias(alias)
    mount = HostMount.get(variant_id, alias)
    if mount is None:
        return False, None
    db.session.delete(mount)
    VariantContext.touch(variant_id, commit=False)
    db.session.commit()
    try:
        helper.call("detach", variant_id=str(variant_id), alias=alias)
    except HostHelperUnavailable as exc:
        return True, exc.message
    except HostHelperError as exc:
        return True, exc.message
    return True, None


def availability(variant_id: uuid.UUID, mounts: list[HostMount]) -> tuple[dict, dict[str, dict]]:
    """Reconcile the helper registry with the stored mounts and report each mount's status.

    Returns ({"available": bool, "message": str | None}, {alias: {"status", "message"}}).
    """
    try:
        result = helper.call("sync", variant_id=str(variant_id),
                             attachments={mount.alias: mount.host_path for mount in mounts})
    except (HostHelperUnavailable, HostHelperError) as exc:
        message = exc.message
        return ({"available": False, "message": message},
                {mount.alias: {"status": "unavailable", "message": message} for mount in mounts})
    reported = result.get("attachments") or {}
    statuses = {}
    for mount in mounts:
        entry = reported.get(mount.alias) or {}
        status = "available" if entry.get("status") == "available" else "unavailable"
        statuses[mount.alias] = {"status": status, "message": str(entry.get("message") or "")}
    return {"available": True, "message": None}, statuses


def helper_status() -> dict:
    """The helper's availability and approved roots, for the UI's folder picker."""
    try:
        result = helper.call("status", timeout=5.0)
    except (HostHelperUnavailable, HostHelperError) as exc:
        return {"available": False, "message": exc.message, "roots": []}
    roots = [root for root in result.get("roots") or [] if isinstance(root, str)]
    return {"available": True, "message": None, "roots": roots}


def browse(variant_id: uuid.UUID, alias: str, operation: str, params: dict) -> dict:
    """Browse the exact database-authorized folder through one helper request."""
    mount = HostMount.get(variant_id, alias)
    if mount is None:
        raise LookupError(f"No folder is attached as '{alias}' for this variant.")
    if operation not in ("list", "read", "search"):
        raise ValueError("Operation must be list, read, or search.")
    return helper.call(
        "source", variant_id=str(variant_id), alias=alias, mount_path=mount.host_path,
        source_operation=operation, **params,
    )
