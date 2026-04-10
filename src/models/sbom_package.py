# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from ..extensions import db, Base


class SBOMPackage(Base):
    """Junction table linking an SBOM document to a package."""

    __tablename__ = "sbom_packages"

    sbom_document_id = db.Column(db.Uuid, db.ForeignKey("sbom_documents.id"), primary_key=True)
    package_id = db.Column(db.Uuid, db.ForeignKey("packages.id"), primary_key=True, index=True)

    sbom_document = db.relationship("SBOMDocument", back_populates="sbom_packages")
    package = db.relationship("Package", back_populates="sbom_packages")

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
        db.session.delete(self)
        db.session.commit()
