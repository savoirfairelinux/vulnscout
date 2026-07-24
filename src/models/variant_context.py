# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import uuid
import shutil
import logging
import typing

from ..extensions import db, Base
from sqlalchemy import ForeignKey, UniqueConstraint, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from .variant import Variant

logger = logging.getLogger(__name__)


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
    """Supplemental file attached to a variant's context.

    NOTE: The AI-context UI for managing these files was removed, so this model
    and its ``context_files`` table are currently unused by the app. They are
    intentionally retained for potential future reuse (see the file endpoints
    in ``src/routes/context.py``). Remove this model and drop the table via a
    migration only if the feature is confirmed dead.
    """

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
    __table_args__ = (UniqueConstraint("variant_id", name="uq_variant_context_variant"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    variant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("variants.id", ondelete="CASCADE"), nullable=False
    )
    variant_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    codebase_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    risks: Mapped[str | None] = mapped_column(Text, nullable=True)
    other_info: Mapped[str | None] = mapped_column(Text, nullable=True)

    variant: Mapped["Variant"] = relationship(back_populates="context")
    files: Mapped[list["ContextFile"]] = relationship(
        back_populates="variant_context",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        return {
            "variant_id": str(self.variant_id),
            "variant_description": self.variant_description,
            "codebase_path": self.codebase_path,
            "environment": self.environment,
            "threat_model": self.threat_model,
            "risks": self.risks,
            "other_info": self.other_info,
            "files": [f.to_dict() for f in self.files],
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID) -> "VariantContext | None":
        return db.session.execute(
            db.select(VariantContext).where(VariantContext.variant_id == variant_id)
        ).scalar_one_or_none()

    @staticmethod
    def upsert(
        variant_id: uuid.UUID,
        variant_description: str | None = None,
        codebase_path: str | None = None,
        environment: str | None = None,
        threat_model: str | None = None,
        risks: str | None = None,
        other_info: str | None = None,
        commit: bool = True,
    ) -> "VariantContext":
        existing = VariantContext.get_by_variant(variant_id)
        if existing is not None:
            existing.variant_description = variant_description
            existing.codebase_path = codebase_path
            existing.environment = environment
            existing.threat_model = threat_model
            existing.risks = risks
            existing.other_info = other_info
            if commit:
                db.session.commit()
            return existing
        vc = VariantContext(
            variant_id=variant_id,
            variant_description=variant_description,
            codebase_path=codebase_path,
            environment=environment,
            threat_model=threat_model,
            risks=risks,
            other_info=other_info,
        )
        db.session.add(vc)
        if commit:
            db.session.commit()
        return vc


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
