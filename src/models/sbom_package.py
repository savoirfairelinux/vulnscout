# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import typing
import uuid

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db, Base

if typing.TYPE_CHECKING:
    from ..models import SBOMDocument, Package


class SBOMPackage(Base):
    """Junction table linking an SBOM document to a package."""

    __tablename__ = "sbom_packages"

    sbom_document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_documents.id"), primary_key=True)
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"), primary_key=True, index=True)

    sbom_document: Mapped["SBOMDocument"] = relationship(back_populates="sbom_packages")
    package: Mapped["Package"] = relationship(back_populates="sbom_packages")

    def __repr__(self) -> str:
        return f"<SBOMPackage sbom_document_id={self.sbom_document_id} package_id={self.package_id}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(sbom_document_id: uuid.UUID | str, package_id: uuid.UUID | str) -> "SBOMPackage":
        """Link *package_id* to *sbom_document_id*, persist and return the association."""
        if isinstance(sbom_document_id, str):
            sbom_document_id = uuid.UUID(sbom_document_id)
        if isinstance(package_id, str):
            package_id = uuid.UUID(package_id)
        entry = SBOMPackage(sbom_document_id=sbom_document_id, package_id=package_id)
        db.session.add(entry)
        db.session.commit()
        return entry

    @staticmethod
    def get(sbom_document_id: uuid.UUID | str, package_id: uuid.UUID | str) -> "SBOMPackage | None":
        """Return the association or ``None`` if not found."""
        if isinstance(sbom_document_id, str):
            sbom_document_id = uuid.UUID(sbom_document_id)
        if isinstance(package_id, str):
            package_id = uuid.UUID(package_id)
        return db.session.get(SBOMPackage, (sbom_document_id, package_id))

    @staticmethod
    def get_by_document(sbom_document_id: uuid.UUID | str) -> list["SBOMPackage"]:
        """Return all associations for the given SBOM document."""
        if isinstance(sbom_document_id, str):
            sbom_document_id = uuid.UUID(sbom_document_id)
        return list(db.session.execute(
            db.select(SBOMPackage).where(SBOMPackage.sbom_document_id == sbom_document_id)
        ).scalars().all())

    @staticmethod
    def get_by_package(package_id: uuid.UUID | str) -> list["SBOMPackage"]:
        """Return all associations for the given package."""
        if isinstance(package_id, str):
            package_id = uuid.UUID(package_id)
        return list(db.session.execute(
            db.select(SBOMPackage).where(SBOMPackage.package_id == package_id)
        ).scalars().all())

    @staticmethod
    def get_or_create(sbom_document_id: uuid.UUID | str, package_id: uuid.UUID | str) -> "SBOMPackage":
        """Return an existing association or create a new one."""
        existing = SBOMPackage.get(sbom_document_id, package_id)
        if existing is not None:
            return existing
        try:
            with db.session.begin_nested():
                return SBOMPackage.create(sbom_document_id, package_id)
        except Exception:
            return SBOMPackage.get(sbom_document_id, package_id)  # type: ignore[return-value]

    def delete(self) -> None:
        """Remove this association from the database."""
        from .package_dependency import PackageDependency

        db.session.execute(
            db.delete(PackageDependency).where(
                PackageDependency.sbom_document_id == self.sbom_document_id,
                db.or_(
                    PackageDependency.package_id == self.package_id,
                    PackageDependency.dependency_id == self.package_id,
                ),
            )
        )
        db.session.delete(self)
        db.session.commit()
