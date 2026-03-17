# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional, TYPE_CHECKING
from sqlalchemy.orm import Mapped, relationship
from ..extensions import db, Base

if TYPE_CHECKING:
    from .time_estimate import TimeEstimate  # noqa: F811


class Finding(Base):
    """Links a :class:`Package` to a :class:`Vulnerability`."""

    __tablename__ = "findings"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    package_id = db.Column(db.Uuid, db.ForeignKey("packages.id"), nullable=False)
    vulnerability_id = db.Column(db.String(50), db.ForeignKey("vulnerabilities.id"), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("package_id", "vulnerability_id", name="uq_finding_package_vulnerability"),
    )

    package = db.relationship("Package")
    vulnerability = db.relationship("Vulnerability", back_populates="findings")
    observations = db.relationship("Observation", back_populates="finding", cascade="all, delete-orphan")
    assessments = db.relationship("Assessment", back_populates="finding", cascade="all, delete-orphan")
    time_estimate: Mapped[Optional["TimeEstimate"]] = relationship(
        "TimeEstimate", back_populates="finding", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id} package_id={self.package_id}"
            f" vulnerability_id={self.vulnerability_id!r}>"
        )

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_package_id(package_id: "uuid.UUID | str") -> uuid.UUID:
        """
        Accept a UUID, a UUID string, or a ``"name@version"`` package string-id,
        and return the corresponding UUID primary key.
        """
        if isinstance(package_id, uuid.UUID):
            return package_id
        if isinstance(package_id, str):
            # Try parsing as UUID first
            try:
                return uuid.UUID(package_id)
            except ValueError:
                pass
            # Fall back to "name@version" lookup
            from .package import Package
            pkg = Package.get_by_string_id(package_id)
            if pkg is not None:
                return pkg.id
            raise ValueError(f"Cannot resolve package_id {package_id!r}: no matching package found")
        raise TypeError(f"Expected UUID or str, got {type(package_id)!r}")

    @staticmethod
    def create(package_id: "uuid.UUID | str", vulnerability_id: str) -> "Finding":
        """Create a new finding, persist it and return it."""
        package_id = Finding._resolve_package_id(package_id)
        finding = Finding(package_id=package_id, vulnerability_id=vulnerability_id.upper())
        db.session.add(finding)
        db.session.commit()
        return finding

    @staticmethod
    def get_by_id(finding_id: uuid.UUID | str) -> Optional["Finding"]:
        """Return the finding matching *finding_id*, or ``None``."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return db.session.get(Finding, finding_id)

    @staticmethod
    def get_by_package(package_id: uuid.UUID | str) -> list["Finding"]:
        """Return all findings for the given package."""
        package_id = Finding._resolve_package_id(package_id)
        return list(db.session.execute(
            db.select(Finding).where(Finding.package_id == package_id)
        ).scalars().all())

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list["Finding"]:
        """Return all findings for the given vulnerability id."""
        return list(db.session.execute(
            db.select(Finding).where(Finding.vulnerability_id == vulnerability_id.upper())
        ).scalars().all())

    @staticmethod
    def get_by_package_and_vulnerability(
        package_id: uuid.UUID | str, vulnerability_id: str
    ) -> Optional["Finding"]:
        """Return the finding for the given package + vulnerability pair, or ``None``."""
        package_id = Finding._resolve_package_id(package_id)
        return db.session.execute(
            db.select(Finding).where(
                Finding.package_id == package_id,
                Finding.vulnerability_id == vulnerability_id.upper(),
            )
        ).scalar_one_or_none()

    @staticmethod
    def get_or_create(package_id: uuid.UUID | str, vulnerability_id: str) -> "Finding":
        """Return an existing finding or create a new one."""
        existing = Finding.get_by_package_and_vulnerability(package_id, vulnerability_id)
        if existing is None:
            try:
                with db.session.begin_nested():
                    existing = Finding.create(package_id, vulnerability_id)
            except Exception:
                existing = Finding.get_by_package_and_vulnerability(package_id, vulnerability_id)
        return existing

    def delete(self) -> None:
        """Delete this finding from the database."""
        db.session.delete(self)
        db.session.commit()
