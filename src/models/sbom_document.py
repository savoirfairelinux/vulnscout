# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import typing
import uuid

from sqlalchemy.orm import Mapped, relationship

from ..extensions import db, Base
from . import Variant, Scan

if typing.TYPE_CHECKING:
    from . import SBOMPackage


class SBOMDocument(Base):
    """Represents an SBOM document file linked to a scan."""

    __tablename__ = "sbom_documents"

    id: Mapped[uuid.UUID] = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    path: Mapped[str] = db.Column(db.Text, nullable=False)
    source_name: Mapped[str] = db.Column(db.String, nullable=False)
    format: Mapped[str | None] = db.Column(db.String, nullable=True)  # e.g. 'spdx', 'cdx', 'openvex', 'yocto_cve_check'
    scan_id: Mapped[uuid.UUID] = db.Column(db.Uuid, db.ForeignKey("scans.id"), nullable=False, index=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="sbom_documents")
    sbom_packages: Mapped[list["SBOMPackage"]] = relationship(
        "SBOMPackage",
        back_populates="sbom_document",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SBOMDocument id={self.id} source_name={self.source_name!r} format={self.format!r}>"

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(path: str, source_name: str, scan_id: uuid.UUID, format: str | None = None) -> "SBOMDocument":
        """Create a new SBOM document with the given path, source_name and optional format
        under scan_id, persist it and return it.
        """
        sbomdocument = SBOMDocument(path=path, source_name=source_name, format=format, scan_id=scan_id)
        db.session.add(sbomdocument)
        db.session.commit()
        return sbomdocument

    @staticmethod
    def get_by_id(document_id: uuid.UUID) -> "SBOMDocument | None":
        """Return the SBOM document matching *document_id*, or ``None`` if not found."""
        return db.session.get(SBOMDocument, document_id)

    @staticmethod
    def get_by_path(path: str) -> "SBOMDocument | None":
        """Return the most-recently-created SBOM document matching *path*, or ``None``."""
        results = list(db.session.execute(
            db.select(SBOMDocument).where(SBOMDocument.path == path)
        ).scalars().all())
        return results[-1] if results else None

    @staticmethod
    def get_all() -> list["SBOMDocument"]:
        """Return all SBOM documents ordered by path."""
        return list(db.session.execute(
            db.select(SBOMDocument).order_by(SBOMDocument.path)
        ).scalars().all())

    @staticmethod
    def get_by_scan(scan_id: uuid.UUID) -> list["SBOMDocument"]:
        """Return all SBOM documents belonging to *scan_id*, ordered by path."""
        return list(db.session.execute(
            db.select(SBOMDocument)
            .where(SBOMDocument.scan_id == scan_id)
            .order_by(SBOMDocument.path)
        ).scalars().all())

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID) -> list["SBOMDocument"]:
        """Return all SBOM documents belonging to *variant_id* (across all its scans), ordered by path."""
        return list(db.session.execute(
            db.select(SBOMDocument)
            .join(Scan)
            .where(Scan.variant_id == variant_id)
            .order_by(SBOMDocument.path)
        ).scalars().all())

    @staticmethod
    def get_by_project(project_id: uuid.UUID) -> list["SBOMDocument"]:
        """Return all SBOM documents belonging to *project_id* (across all its variants and scans), ordered by path."""
        return list(db.session.execute(
            db.select(SBOMDocument)
            .join(Scan)
            .join(Variant, Scan.variant_id == Variant.id)
            .where(Variant.project_id == project_id)
            .order_by(SBOMDocument.path)
        ).scalars().all())

    def update(self, path: str, source_name: str, format: str | None = None) -> "SBOMDocument":
        """Update path, source_name and optional format in place, persist the change and return ``self``."""
        self.path = path
        self.source_name = source_name
        self.format = format
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this variant (and its scans via cascade) from the database."""
        db.session.delete(self)
        db.session.commit()
