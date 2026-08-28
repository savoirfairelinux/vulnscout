# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import typing
from typing import cast

from ..extensions import db, Base

from sqlalchemy import ForeignKey, Table, UniqueConstraint, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column, relationship

if typing.TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.orm import Mapper

    from ..models import Project, Scan, TimeEstimate, Metrics
    from .variant_context import VariantContext


class Variant(Base):
    """Represents a named variant (e.g. board configuration) belonging to a project."""

    __tablename__ = "variants"
    __table_args__ = (
        UniqueConstraint("name", "project_id", name="uq_variants_name_project"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str]
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))

    project: Mapped["Project"] = relationship(
        back_populates="variants"
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    time_estimates: Mapped[list["TimeEstimate"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    metrics: Mapped[list["Metrics"]] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan"
    )
    context: Mapped["VariantContext | None"] = relationship(
        back_populates="variant",
        cascade="all, delete-orphan",
        uselist=False,
    )

    def __repr__(self) -> str:
        return f"<Variant id={self.id} name={self.name!r}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(name: str, project_id: uuid.UUID) -> "Variant":
        """Create a new variant with the given *name* under *project_id*, persist it and return it."""
        variant = Variant(name=name, project_id=project_id)
        db.session.add(variant)
        db.session.commit()
        return variant

    @staticmethod
    def get_by_id(variant_id: uuid.UUID) -> "Variant | None":
        """Return the variant matching *variant_id*, or ``None`` if not found."""
        return db.session.get(Variant, variant_id)

    @staticmethod
    def get_all() -> list["Variant"]:
        """Return all variants ordered by name."""
        return list(db.session.execute(
            db.select(Variant).order_by(Variant.name)
        ).scalars().all())

    @staticmethod
    def get_by_project(project_id: uuid.UUID) -> list["Variant"]:
        """Return all variants belonging to *project_id*, ordered by name."""
        return list(db.session.execute(
            db.select(Variant).where(Variant.project_id == project_id).order_by(Variant.name)
        ).scalars().all())

    @staticmethod
    def get_by_name_and_project(name: str, project_id: uuid.UUID) -> "Variant | None":
        """Return an existing variant by *name* under *project_id*, or None if it does not exist."""
        return db.session.execute(
            db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
        ).scalar_one_or_none()

    @staticmethod
    def get_or_create(name: str, project_id: uuid.UUID) -> "Variant":
        """Return an existing variant by *name* under *project_id*, or create and persist a new one."""

        existing = db.session.execute(
            db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        try:
            with db.session.begin_nested():
                variant = Variant(name=name, project_id=project_id)
                db.session.add(variant)
                db.session.flush()
            db.session.commit()
            return variant
        except IntegrityError:
            return db.session.execute(
                db.select(Variant).where(Variant.name == name, Variant.project_id == project_id)
            ).scalar_one()

    def update(self, name: str) -> "Variant":
        """Update the variant's *name* in place, persist the change and return ``self``."""
        self.name = name
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this variant (and its scans via cascade) from the database."""
        db.session.delete(self)
        db.session.commit()


@event.listens_for(Variant, "before_delete")
def _reap_assessment_targets(
    mapper: "Mapper[Variant]", connection: "Connection", variant: "Variant",
) -> None:
    """Drop the assessment targets pointing at a variant being deleted.

    ``assessment_targets.variant_id`` has no ``ondelete`` clause and this
    application keeps sqlite's ``foreign_keys`` pragma off, so nothing removes
    these rows on its own.  Left behind, they still surface through unfiltered
    reads (``get_by_vulnerability``, the assessments API) pointing at a variant
    that no longer exists.

    An assessment left with no targets at all goes with them: it is reachable
    only through its targets, so it would be an invisible orphan.  An
    assessment that also targets other variants keeps those and survives.

    Registered as a mapper event rather than written into :meth:`delete` so it
    also fires when a variant is removed through the project's ORM cascade.
    """
    # Core statements against the mapped tables, not raw SQL: the listener gets
    # a Connection rather than a Session, and only the mapped columns know how
    # to bind a UUID for the active driver.
    from .assessment import Assessment
    from .assessment_target import AssessmentTarget

    # ``__table__`` is typed as FromClause; these are real Tables, and only
    # Table carries .delete().
    targets = cast(Table, AssessmentTarget.__table__)
    assessments = cast(Table, Assessment.__table__)

    affected = {
        row[0] for row in connection.execute(
            select(targets.c.assessment_id).where(targets.c.variant_id == variant.id)
        )
    }
    connection.execute(targets.delete().where(targets.c.variant_id == variant.id))
    if not affected:
        return

    # Of the assessments this variant was part of, keep the ones another target
    # still reaches and drop the rest.
    still_reachable = {
        row[0] for row in connection.execute(
            select(targets.c.assessment_id).where(targets.c.assessment_id.in_(affected))
        )
    }
    orphans = affected - still_reachable
    if orphans:
        connection.execute(assessments.delete().where(assessments.c.id.in_(orphans)))
