# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import shutil
import logging
import typing
from datetime import datetime, timezone

from ..extensions import db, Base, hold_write_lock
from ..helpers.datetime_utils import ensure_utc_iso
from ..helpers.stride_model import (
    SYSTEM_KEYS,
    StrideValidationError,
    empty_stride_model,
    normalize_stride_model,
    normalize_system,
    render_risks,
    render_threat_model,
)
import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, Text, event
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from .variant import Variant

logger = logging.getLogger(__name__)

# Editor payload key -> column for the four system-description fields.
_SYSTEM_COLUMNS: dict[str, str] = {key: f"system_{key}" for key in SYSTEM_KEYS}
# Top-level editor payload keys stored as nullable text in the same-named column.
_EDITOR_TEXT_KEYS = ("variant_description", "environment", "other_info")


def default_editor_block() -> dict:
    """Editor block for a variant that has no context row yet."""
    return {
        "system": {key: None for key in SYSTEM_KEYS},
        "stride": empty_stride_model(),
        "files": [],
        "updated_at": None,
    }


def _blank_to_none(value: str | None) -> str | None:
    return value if value is not None and value.strip() else None


def _optional_text(value: object, path: str, errors: dict[str, str]) -> str | None:
    if value is not None and not isinstance(value, str):
        errors.setdefault(path, "must be a string")
        return None
    return _blank_to_none(value)


def _validated(call: typing.Callable[[object], typing.Any], raw: object, errors: dict[str, str]) -> typing.Any:
    try:
        return call(raw)
    except StrideValidationError as exc:
        for path, message in exc.fields.items():
            errors.setdefault(path, message)
        return None


def _editor_values(payload: object) -> dict[str, typing.Any]:
    """Validate an editor-shape payload and return the column values to store."""
    if not isinstance(payload, dict):
        raise StrideValidationError({"body": "must be an object"})
    errors: dict[str, str] = {}
    values: dict[str, typing.Any] = {
        key: _optional_text(payload.get(key), key, errors) for key in _EDITOR_TEXT_KEYS
    }
    system = _validated(normalize_system, payload.get("system"), errors) or {}
    for key, column in _SYSTEM_COLUMNS.items():
        values[column] = _blank_to_none(system.get(key))
    values["stride_model"] = _validated(normalize_stride_model, payload.get("stride"), errors)
    if errors:
        raise StrideValidationError(errors)
    return values


def _get_cache_dir() -> str:
    return os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")


def _delete_context_dir(variant_context_id: uuid.UUID) -> None:
    """Best-effort deletion of the context file directory for a VariantContext."""
    dir_path = os.path.join(_get_cache_dir(), "context-files", str(variant_context_id))
    try:
        if os.path.isdir(dir_path):
            shutil.rmtree(dir_path)
    except OSError as exc:
        logger.warning("Could not delete context dir %s: %s", dir_path, exc)


class ContextFile(Base):
    """Uploaded codebase reference attached to a variant's context."""

    __tablename__ = "context_files"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    variant_context_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("variant_context.id", ondelete="CASCADE"), nullable=False
    )
    original_name: Mapped[str]
    file_path: Mapped[str]
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    variant_context: Mapped["VariantContext"] = relationship(back_populates="files")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "original_name": self.original_name,
            "description": self.description,
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        variant_context_id: uuid.UUID, original_name: str, file_path: str,
        description: str | None = None, id: uuid.UUID | None = None
    ) -> "ContextFile":
        cf = ContextFile(
            id=id or uuid.uuid4(),
            variant_context_id=variant_context_id,
            original_name=original_name,
            file_path=file_path,
            description=description,
        )
        db.session.add(cf)
        db.session.commit()
        return cf

    @staticmethod
    def count_for_variant_context(variant_context_id: uuid.UUID) -> int:
        return db.session.execute(
            db.select(db.func.count()).select_from(ContextFile).where(
                ContextFile.variant_context_id == variant_context_id
            )
        ).scalar_one()

    @staticmethod
    def get_by_id_and_variant_context(
        file_id: uuid.UUID, variant_context_id: uuid.UUID
    ) -> "ContextFile | None":
        return db.session.execute(
            db.select(ContextFile).where(
                ContextFile.id == file_id,
                ContextFile.variant_context_id == variant_context_id,
            )
        ).scalar_one_or_none()


class VariantContext(Base):
    """Stores AI assessment context tied to a variant."""

    __tablename__ = "variant_context"
    __table_args__ = (
        UniqueConstraint("variant_id", name="uq_variant_context_variant"),
        sa.Index("uq_variant_context_codebase_directory", "codebase_directory", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    variant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("variants.id", ondelete="CASCADE"), nullable=False
    )
    variant_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    codebase_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(Text, nullable=True)
    other_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Bumped only when a field's value actually changes; AI assessments older
    # than this were written against a previous context.  NULL = never modified.
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    system_scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_actors: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_entry_points: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_trust_boundaries: Mapped[str | None] = mapped_column(Text, nullable=True)
    stride_model: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)

    variant: Mapped["Variant"] = relationship(back_populates="context")
    files: Mapped[list["ContextFile"]] = relationship(
        back_populates="variant_context",
        cascade="all, delete-orphan",
    )

    def _system(self) -> dict[str, str | None]:
        return {key: getattr(self, column) for key, column in _SYSTEM_COLUMNS.items()}

    def agent_threat_model(self) -> str | None:
        """Threat model text the agent sees: the rendering of the system and STRIDE model."""
        return render_threat_model(self._system(), self.stride_model)

    def agent_risks(self) -> str | None:
        """Risks text the agent sees: the rendering of the STRIDE model's risks."""
        return render_risks(self.stride_model)

    def to_dict(self) -> dict:
        updated_at = ensure_utc_iso(self.updated_at) if self.updated_at else None
        files = [f.to_dict() for f in self.files]
        return {
            "variant_id": str(self.variant_id),
            "variant_description": self.variant_description,
            "codebase_directory": self.directory_metadata(),
            "environment": self.environment,
            "threat_model": self.agent_threat_model(),
            "risks": self.agent_risks(),
            "other_info": self.other_info,
            "updated_at": updated_at,
            "files": files,
            "editor": {
                "system": self._system(),
                "stride": self.stride_model if self.stride_model is not None else empty_stride_model(),
                "files": files,
                "updated_at": updated_at,
            },
        }

    def directory_metadata(self) -> dict | None:
        if self.codebase_directory is None:
            return None
        from ..helpers.codebase_directory import directory_path
        return {"file_id": "directory", "path": directory_path(_get_cache_dir(), self.codebase_directory)}

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID) -> "VariantContext | None":
        return db.session.execute(
            db.select(VariantContext).where(VariantContext.variant_id == variant_id)
        ).scalar_one_or_none()

    @staticmethod
    def get_or_create(variant_id: uuid.UUID) -> "VariantContext":
        """Create an empty context without changing a row created by another request."""
        existing = VariantContext.get_by_variant(variant_id)
        if existing is not None:
            return existing
        try:
            with db.session.begin_nested():
                vc = VariantContext(variant_id=variant_id)
                db.session.add(vc)
                db.session.flush()
            db.session.commit()
            return vc
        except IntegrityError:
            return db.session.execute(
                db.select(VariantContext).where(VariantContext.variant_id == variant_id)
            ).scalar_one()

    @staticmethod
    def upsert(
        variant_id: uuid.UUID,
        variant_description: str | None = None,
        environment: str | None = None,
        other_info: str | None = None,
        commit: bool = True,
    ) -> "VariantContext":
        """Full replacement of the text fields; the threat model and risks come from STRIDE."""
        existing = VariantContext.get_by_variant(variant_id)
        if existing is not None:
            new_values: dict[str, typing.Any] = {
                "variant_description": variant_description,
                "environment": environment,
                "other_info": other_info,
            }
            existing._apply(new_values)
            if commit:
                db.session.commit()
            return existing
        has_content = any(
            v is not None
            for v in (variant_description, environment, other_info)
        )
        vc = VariantContext(
            variant_id=variant_id,
            variant_description=variant_description,
            environment=environment,
            other_info=other_info,
            updated_at=datetime.now(timezone.utc) if has_content else None,
        )
        db.session.add(vc)
        if commit:
            db.session.commit()
        return vc

    def _apply(self, values: dict[str, typing.Any]) -> None:
        """Assign only the values that differ; bump ``updated_at`` if any did."""
        changed = False
        for name, value in values.items():
            if getattr(self, name) != value:
                setattr(self, name, value)
                changed = True
        if changed:
            self.updated_at = datetime.now(timezone.utc)

    @staticmethod
    def save_editor(variant_id: uuid.UUID, payload: dict, commit: bool = True) -> "VariantContext":
        """Store an editor-shape payload; raises ``StrideValidationError``."""
        values = _editor_values(payload)
        existing = VariantContext.get_by_variant(variant_id)
        if existing is None:
            vc = VariantContext(variant_id=variant_id, updated_at=datetime.now(timezone.utc), **values)
            db.session.add(vc)
        else:
            # Persist even an explicit empty model to distinguish it from a never-configured row on export.
            existing._apply(values)
            vc = existing
        if commit:
            db.session.commit()
        return vc

    @staticmethod
    def touch(variant_id: uuid.UUID, commit: bool = True) -> "VariantContext":
        """Mark a variant context as changed, creating its revision row if needed.

        Used by callers that mutate context outside the text-field set covered by
        `upsert` (e.g. supplemental context files), so `context_outdated` still
        reflects the change.
        """
        is_sqlite = db.session.get_bind().dialect.name == "sqlite"
        if is_sqlite:
            hold_write_lock()
        insert = (sqlite.insert if is_sqlite else postgresql.insert)(VariantContext)
        # On PostgreSQL, sample the clock after any conflict wait, not at transaction start.
        revision = datetime.now(timezone.utc) if is_sqlite else sa.func.clock_timestamp()
        statement = insert.values(variant_id=variant_id, updated_at=revision).on_conflict_do_update(
            index_elements=[VariantContext.variant_id], set_={"updated_at": revision},
        )
        existing = db.session.scalars(
            statement.returning(VariantContext), execution_options={"populate_existing": True},
        ).one()
        if commit:
            db.session.commit()
        return existing


# ---------------------------------------------------------------------------
# SQLAlchemy events — post-commit filesystem cleanup
# ---------------------------------------------------------------------------
# We use a two-step pattern to guarantee DB is committed before FS cleanup:
#   1. after_delete mapper event: record the context dir path in Session.info
#   2. after_commit session event: perform the actual FS deletion
# This avoids deleting files before the commit finalises.

@event.listens_for(VariantContext, "after_delete")
def _on_variant_context_deleted(mapper, connection, target: VariantContext) -> None:
    from ..extensions import db
    session = db.session
    if 'pending_context_cleanups' not in session.info:
        session.info['pending_context_cleanups'] = []
    dir_path = os.path.join(_get_cache_dir(), "context-files", str(target.id))
    session.info['pending_context_cleanups'].append(dir_path)


@event.listens_for(db.session, "after_commit")
def _cleanup_after_commit(session) -> None:
    paths = session.info.pop('pending_context_cleanups', [])
    for dir_path in paths:
        try:
            if os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
        except OSError as exc:
            logger.warning("Could not delete context dir %s: %s", dir_path, exc)
