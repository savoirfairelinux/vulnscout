# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing
from datetime import datetime, timezone

from ..extensions import db, Base
import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from .project import Project


class _Keep:
    """Marker for an upsert argument that leaves the stored value unchanged."""

    def __repr__(self) -> str:
        return "KEEP"


KEEP: typing.Final = _Keep()


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
    # Presentation of AI assessment text (see helpers.assessment_format); NULL = skill default.
    # It does not bump updated_at: it never changes a verdict, so assessments stay current.
    assessment_format: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)
    review_format: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)

    project: Mapped["Project"] = relationship(back_populates="context")

    def to_dict(self) -> dict:
        return {
            "project_id": str(self.project_id),
            "description": self.description,
            "assessment_format": self.assessment_format,
            "review_format": self.review_format,
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
        project_id: uuid.UUID,
        description: "str | None | _Keep" = None,
        commit: bool = True,
        assessment_format: "dict | None | _Keep" = KEEP,
        review_format: "dict | None | _Keep" = KEEP,
    ) -> "ProjectContext":
        """Create or update the row; a ``KEEP`` argument leaves that field as stored.

        *assessment_format* must already be normalized
        (``helpers.assessment_format.normalize_assessment_format``).
        """
        existing = ProjectContext.get_by_project(project_id)
        if existing is not None:
            if not isinstance(description, _Keep) and existing.description != description:
                existing.description = description
                existing.updated_at = datetime.now(timezone.utc)
            if not isinstance(assessment_format, _Keep):
                existing.assessment_format = assessment_format
            if not isinstance(review_format, _Keep):
                existing.review_format = review_format
            if commit:
                db.session.commit()
            return existing
        new_description = None if isinstance(description, _Keep) else description
        pc = ProjectContext(
            project_id=project_id,
            description=new_description,
            assessment_format=None if isinstance(assessment_format, _Keep) else assessment_format,
            review_format=None if isinstance(review_format, _Keep) else review_format,
            updated_at=datetime.now(timezone.utc) if new_description is not None else None,
        )
        db.session.add(pc)
        if commit:
            db.session.commit()
        return pc
