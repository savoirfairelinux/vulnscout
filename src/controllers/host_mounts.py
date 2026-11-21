# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Attach, list and detach host folders for a variant.

The database is the source of truth for attachments; the host folder helper validates
each folder against the operator-approved roots and serves its content read-only.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..extensions import db, hold_write_lock
from ..helpers import host_mounts as helper
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..models.host_mount import MOUNT_FILE_ID_PREFIX, HostMount, HostMountDetach
from ..models.variant_context import VariantContext

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


def _drain(variant_id: uuid.UUID | None = None) -> None:
    """Acknowledge only after RPC success. Concurrent delivery of the same ID is harmless."""
    table = HostMountDetach
    query = db.select(table.attachment_id, table.variant_id, table.alias)
    if variant_id is not None:
        query = query.where(table.variant_id == variant_id)
    pending = db.session.execute(query).all()
    for attachment_id, owner, alias in pending:
        helper.call("detach", variant_id=str(owner), alias=alias, attachment_id=str(attachment_id))
        if db.session.get_bind().dialect.name == "sqlite":
            hold_write_lock()
        db.session.execute(db.delete(table).where(table.attachment_id == attachment_id))
        db.session.commit()


def _binding(mount: HostMount) -> dict:
    return dict(variant_id=str(mount.variant_id), alias=mount.alias, attachment_id=str(mount.id),
                path=mount.host_path, approval_proof=mount.approval_proof)


def attach(variant_id: uuid.UUID, alias: str, host_path: str, *, host_permit: str | None = None
           ) -> tuple[HostMount, bool]:
    """Stage without granting access; publish the exact binding before activating it."""
    helper.validate_alias(alias)
    if not isinstance(host_path, str) or not host_path.strip():
        raise ValueError("host_path must be a non-empty absolute host path.")
    _drain(variant_id)
    existing = HostMount.get(variant_id, alias)
    if existing is None and len(HostMount.get_by_variant(variant_id)) >= MAX_MOUNTS_PER_VARIANT:
        raise HostMountConflict(f"A variant can have at most {MAX_MOUNTS_PER_VARIANT} attached folders.")
    attachment_id = existing.id if existing is not None else uuid.uuid4()
    scope: dict = dict(variant_id=str(variant_id), alias=alias, attachment_id=str(attachment_id))
    if existing is not None:
        binding = _binding(existing)
        if host_path != binding["path"] and helper.call("browse", path=host_path)["path"] != binding["path"]:
            raise HostMountConflict(
                f"Alias '{alias}' is already attached to {binding['path']}; detach it first."
            )
        host_path = binding["path"]
        if host_permit is None:
            helper.call("activate", **binding, check_only=True)
            return existing, False
    result = helper.call("stage", **scope, path=host_path, host_permit=host_permit, exact=existing is not None)
    proof = result.get("approval_proof")
    if host_permit is not None and not proof:
        raise HostHelperError("internal", "Host helper did not return an attachment approval.")
    binding = dict(**scope, path=result["path"], approval_proof=proof)
    try:
        if existing is None:
            mount = HostMount(id=attachment_id, variant_id=variant_id, alias=alias, host_path=binding["path"],
                              approval_proof=proof, created_at=datetime.now(timezone.utc))
            db.session.add(mount)
            db.session.flush()
            VariantContext.touch(variant_id, commit=False)
            if len(HostMount.get_by_variant(variant_id)) > MAX_MOUNTS_PER_VARIANT:
                raise HostMountConflict(f"A variant can have at most {MAX_MOUNTS_PER_VARIANT} attached folders.")
        else:
            mount = existing
            # The alias may have been detached and recreated while the host checked the permit.
            if db.session.get_bind().dialect.name == "sqlite":
                hold_write_lock()
            if not db.session.query(HostMount).filter_by(id=attachment_id).update({"approval_proof": proof}):
                raise HostMountConflict(f"Alias '{alias}' was detached or replaced.")
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        if host_permit is None and HostMount.get(variant_id, alias) is not None:
            return attach(variant_id, alias, host_path)
        raise HostMountConflict(f"Alias '{alias}' is already attached for this variant.") from None
    except Exception:
        db.session.rollback()
        raise
    helper.call("activate", **binding)
    return mount, existing is None


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
        _drain(variant_id)
    except (HostHelperUnavailable, HostHelperError) as exc:
        return True, exc.message
    return True, None


def availability(variant_id: uuid.UUID, mounts: list[HostMount]) -> tuple[dict, dict[str, dict]]:
    """Reconcile the helper registry with the stored mounts and report each mount's status.

    Returns ({"available": bool, "message": str | None}, {alias: {"status", "message"}}).
    """
    bindings = [_binding(mount) for mount in mounts]
    statuses = {}
    try:
        _drain(variant_id)
        if not bindings:
            helper.call("sync", variant_id=str(variant_id), attachments={})
        for binding in bindings:
            try:
                helper.call("activate", **binding)
                statuses[binding["alias"]] = {"status": "available", "message": "Folder is available read-only."}
            except HostHelperError as exc:
                statuses[binding["alias"]] = {"status": "unavailable", "message": exc.message}
    except (HostHelperUnavailable, HostHelperError) as exc:
        message = exc.message
        return ({"available": False, "message": message},
                {mount.alias: {"status": "unavailable", "message": message} for mount in mounts})
    return {"available": True, "message": None}, statuses


def helper_status() -> dict:
    """The helper's availability and approved roots, for the UI's folder picker."""
    try:
        _drain()
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
    if mount.approval_proof:
        helper.call("activate", **_binding(mount))
    return helper.call(
        "source", variant_id=str(variant_id), alias=alias, mount_path=mount.host_path,
        source_operation=operation, **params,
    )
