# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Attach, list and detach host folders for a variant.

The database is the source of truth for attachments; the host folder helper validates
the host CLI permit for each exact folder and serves its content read-only.
"""

import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..extensions import db, hold_write_lock
from ..helpers import host_mounts as helper
from ..helpers.host_mounts import HostHelperError, HostHelperUnavailable
from ..models.host_mount import MOUNT_FILE_ID_PREFIX, HostMount, HostMountDetach
from ..models.variant_context import VariantContext

MAX_MOUNTS_PER_VARIANT = helper.protocol.MAX_ATTACHMENTS_PER_VARIANT
_DRAIN_SECONDS = 2.0
_DRAIN_LIMIT = 32


class HostMountConflict(ValueError):
    """The alias is already attached to another folder, or the variant has too many folders."""


def mount_alias(file_id: str) -> str | None:
    """The alias of a ``mount:<alias>`` source ID, else None."""
    if not file_id.startswith(MOUNT_FILE_ID_PREFIX):
        return None
    return helper.validate_alias(file_id[len(MOUNT_FILE_ID_PREFIX):])


def _drain(variant_id: uuid.UUID | None = None, *, attachment_id: uuid.UUID | None = None) -> None:
    """Acknowledge only after RPC success. Concurrent delivery of the same ID is harmless."""
    table = HostMountDetach
    query = db.select(table.attachment_id, table.variant_id, table.alias)
    if variant_id is not None:
        query = query.where(table.variant_id == variant_id)
    if attachment_id is not None:
        query = query.where(table.attachment_id == attachment_id)
    deadline = time.monotonic() + _DRAIN_SECONDS
    pending = db.session.execute(query.order_by(table.attachment_id).limit(_DRAIN_LIMIT)).all()
    for attachment_id, owner, alias in pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        helper.call("detach", timeout=remaining, variant_id=str(owner), alias=alias, attachment_id=str(attachment_id))
        if db.session.get_bind().dialect.name == "sqlite":
            hold_write_lock()
        db.session.execute(db.delete(table).where(table.attachment_id == attachment_id))
        db.session.commit()


def _binding(mount: HostMount) -> dict:
    return dict(variant_id=str(mount.variant_id), alias=mount.alias, attachment_id=str(mount.id),
                path=mount.host_path, approval_proof=mount.approval_proof)


def attach(variant_id: uuid.UUID, alias: str, host_path: str, *, host_permit: str
           ) -> tuple[dict, bool, str | None]:
    """Stage without granting access; publish the exact binding before activating it."""
    if not host_permit:
        raise ValueError("Attach folders using the host CLI to authorize an exact folder.")
    helper.validate_alias(alias)
    if not isinstance(host_path, str) or not host_path.strip():
        raise ValueError("host_path must be a non-empty absolute host path.")
    _drain(variant_id)
    existing = HostMount.get(variant_id, alias)
    if existing is None and len(HostMount.get_by_variant(variant_id)) >= MAX_MOUNTS_PER_VARIANT:
        raise HostMountConflict(f"A variant can have at most {MAX_MOUNTS_PER_VARIANT} attached folders.")
    attachment_id = existing.id if existing is not None else uuid.uuid4()
    scope: dict = dict(variant_id=str(variant_id), alias=alias, attachment_id=str(attachment_id))
    if existing is not None and host_path != existing.host_path:
        raise HostMountConflict(f"Alias '{alias}' is already attached to {existing.host_path}; detach it first.")
    result = helper.call("stage", **scope, path=host_path, host_permit=host_permit)
    proof = result.get("approval_proof")
    if not proof or result.get("path") != host_path:
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
            row = db.session.query(HostMount).filter_by(id=attachment_id)
            if row.filter(HostMount.approval_proof.is_distinct_from(proof)).update({"approval_proof": proof}):
                VariantContext.touch(variant_id, commit=False)
            elif not row.count():
                raise HostMountConflict(f"Alias '{alias}' was detached or replaced.")
        response = mount.to_dict()
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise HostMountConflict(f"Alias '{alias}' is already attached for this variant.") from None
    except Exception:
        db.session.rollback()
        raise
    try:
        helper.call("activate", **binding)
    except (HostHelperUnavailable, HostHelperError) as exc:
        return response, existing is None, f"Attachment saved; activation pending. {exc.message}"
    return response, existing is None, None


def detach(variant_id: uuid.UUID, alias: str, *, expected_id: uuid.UUID | None = None,
           expected_revision: uuid.UUID | None = None) -> tuple[bool, str | None]:
    """Delete the matching attachment; returns (deleted, helper warning).

    Access is revoked as soon as the row is deleted, because every request is checked
    against the database first. The helper registry is cleaned up best-effort and
    reconciled on the next availability check.
    """
    helper.validate_alias(alias)
    if db.session.get_bind().dialect.name == "sqlite":
        hold_write_lock()
    delete = db.delete(HostMount).where(HostMount.variant_id == variant_id, HostMount.alias == alias)
    if expected_id is not None:
        delete = delete.where(HostMount.id == expected_id)
    if expected_revision is not None:
        mount = HostMount.get(variant_id, alias)
        if mount is None or mount.approval_revision != expected_revision:
            db.session.rollback()
            return False, None
        # A concurrent reapproval can change the proof between this read and the DELETE.
        delete = delete.where(HostMount.id == mount.id, HostMount.approval_proof == mount.approval_proof)
    attachment_id = db.session.execute(delete.returning(HostMount.id)).scalar_one_or_none()
    if attachment_id is None:
        db.session.rollback()
        return False, None
    db.session.add(HostMountDetach(attachment_id=attachment_id, variant_id=variant_id, alias=alias))
    VariantContext.touch(variant_id, commit=False)
    db.session.commit()
    try:
        _drain(variant_id, attachment_id=attachment_id)
    except (HostHelperUnavailable, HostHelperError) as exc:
        return True, exc.message
    return True, None


def _retry_outbox() -> None:
    # Include deleted variants, which can no longer receive scoped requests.
    try:
        _drain()
    except (HostHelperUnavailable, HostHelperError) as exc:
        logging.getLogger(__name__).warning("Deferred host mount cleanup: %s", exc.message)


def list_mounts(variant_id: uuid.UUID) -> tuple[dict, list[dict]]:
    """Snapshot public rows and their private helper bindings before cleanup can expire them."""
    mounts = HostMount.get_by_variant(variant_id)
    rows = [mount.to_dict() for mount in mounts]
    bindings = [_binding(mount) for mount in mounts]
    try:
        _drain(variant_id)
        helper.call("status")
        for row, binding in zip(rows, bindings):
            try:
                _activate(binding)
                row.update(status="available", message="Folder is available read-only.")
            except HostHelperError as exc:
                row.update(status="unavailable", message=exc.message)
    except (HostHelperUnavailable, HostHelperError) as exc:
        for row in rows:
            row.update(status="unavailable", message=exc.message)
        return {"available": False, "message": exc.message}, rows
    _retry_outbox()
    return {"available": True, "message": None}, rows


def _activate(binding: dict) -> None:
    if not binding["approval_proof"]:
        raise HostHelperError("forbidden", "No host approval; reattach this folder with the host CLI.")
    helper.call("activate", **binding)


def browse(variant_id: uuid.UUID, alias: str, operation: str, params: dict) -> dict:
    """Recover and browse only the exact host-approved database binding."""
    mount = HostMount.get(variant_id, alias)
    if mount is None:
        raise LookupError(f"No folder is attached as '{alias}' for this variant.")
    if operation not in ("list", "read"):
        raise ValueError("Operation must be list or read.")
    _activate(_binding(mount))
    return helper.call(
        "source", variant_id=str(variant_id), alias=alias, mount_path=mount.host_path,
        source_operation=operation, **params,
    )
