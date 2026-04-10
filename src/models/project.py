# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing

from ..extensions import db, Base

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped

if typing.TYPE_CHECKING:
    from .variant import Variant


class Project(Base):
    """Represents a project that groups one or more variants."""

    __tablename__ = "projects"
    __table_args__ = (db.UniqueConstraint("name", name="uq_projects_name"),)

    id: Mapped[uuid.UUID] = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = db.Column(db.String, nullable=False)

    variants: Mapped[list["Variant"]] = db.relationship(  # type: ignore
        "Variant",
        back_populates="project",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Project id={self.id} name={self.name!r}>"

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "variants": [{
                "id": str(variant.id),
                "name": variant.name
            } for variant in self.variants],
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(name: str) -> "Project":
        """Create a new project with the given *name*, persist it and return it."""
        project = Project(name=name)
        db.session.add(project)
        db.session.commit()
        return project

    @staticmethod
    def get_by_id(project_id: uuid.UUID) -> "Project | None":
        """Return the project matching *project_id*, or ``None`` if not found."""
        return db.session.get(Project, project_id)

    @staticmethod
    def get_all() -> list["Project"]:
        """Return all projects ordered by name."""
        return list(db.session.execute(
            db.select(Project).order_by(Project.name)
        ).scalars().all())

    @staticmethod
    def get_or_create(name: str) -> "Project":
        """Return an existing project by *name*, or create and persist a new one."""

        existing = db.session.execute(
            db.select(Project).where(Project.name == name)
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        try:
            with db.session.begin_nested():
                project = Project(name=name)
                db.session.add(project)
                db.session.flush()
            db.session.commit()
            return project
        except IntegrityError:
            return db.session.execute(
                db.select(Project).where(Project.name == name)
            ).scalar_one()

    def update(self, name: str) -> "Project":
        """Update the project's *name* in place, persist the change and return ``self``."""
        self.name = name
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this project (and its variants via cascade) from the database."""
        db.session.delete(self)
        db.session.commit()
