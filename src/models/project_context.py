# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing
from datetime import datetime, timezone

from ..extensions import db, Base
from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from .project import Project


class ProjectContext(Base):
    """Stores AI assessment context tied to a project."""

    __tablename__ = "project_context"
    __table_args__ = (UniqueConstraint("project_id", name="uq_project_context_project"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Bumped only when the description actually changes; AI assessments older
    # than this were written against a previous context.  NULL = never modified.
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="context")

    def to_dict(self) -> dict:
        return {
            "project_id": str(self.project_id),
            "description": self.description,
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_by_project(project_id: uuid.UUID) -> "ProjectContext | None":
        return db.session.execute(
            db.select(ProjectContext).where(ProjectContext.project_id == project_id)
        ).scalar_one_or_none()

    @staticmethod
    def upsert(
        project_id: uuid.UUID, description: str | None = None, commit: bool = True
    ) -> "ProjectContext":
        existing = ProjectContext.get_by_project(project_id)
        if existing is not None:
            if existing.description != description:
                existing.description = description
                existing.updated_at = datetime.now(timezone.utc)
            if commit:
                db.session.commit()
            return existing
        pc = ProjectContext(
            project_id=project_id,
            description=description,
            updated_at=datetime.now(timezone.utc) if description is not None else None,
        )
        db.session.add(pc)
        if commit:
            db.session.commit()
        return pc
