# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import typing
import uuid

from sqlalchemy import CheckConstraint, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db, Base

if typing.TYPE_CHECKING:
    from ..models import SBOMDocument, Package

PackageType = typing.Literal["normal", "workspace", "built"]


class PackageEvidence(typing.TypedDict):
    cpe: list[str]
    purl: list[str]
    source_urls: list[str]
    source_revisions: typing.NotRequired[list[str]]
    component_types: typing.NotRequired[list[PackageType]]


class SBOMPackage(Base):
    """Junction table linking an SBOM document to a package."""

    __tablename__ = "sbom_packages"
    __table_args__ = (
        CheckConstraint("type IN ('normal', 'workspace', 'built')", name="ck_sbom_packages_type"),
    )

    sbom_document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_documents.id"), primary_key=True)
    package_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("packages.id"), primary_key=True, index=True)
    source_urls: Mapped[list | None] = mapped_column(JSON)
    cpe: Mapped[list | None] = mapped_column(JSON)
    purl: Mapped[list | None] = mapped_column(JSON)
    source_revisions: Mapped[list | None] = mapped_column(JSON)
    type: Mapped[PackageType] = mapped_column(String(9), default="normal", server_default="normal")

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

    @staticmethod
    def evidence_for_documents(document_ids: set[uuid.UUID]) -> dict[uuid.UUID, PackageEvidence]:
        """Aggregate only selected document evidence, never global matching identifiers."""
        if not document_ids:
            return {}
        evidence_sets: dict[uuid.UUID, dict[str, set[str]]] = {}
        component_types: dict[uuid.UUID, set[PackageType]] = {}
        for package_id, cpe, purl, source_urls, revisions, package_type in db.session.execute(
            db.select(SBOMPackage.package_id, SBOMPackage.cpe, SBOMPackage.purl,
                      SBOMPackage.source_urls, SBOMPackage.source_revisions, SBOMPackage.type)
            .where(SBOMPackage.sbom_document_id.in_(document_ids))
        ):
            item = evidence_sets.setdefault(package_id, {
                "cpe": set(), "purl": set(), "source_urls": set(), "source_revisions": set(),
            })
            item["cpe"].update(cpe or [])
            item["purl"].update(purl or [])
            item["source_urls"].update(source_urls or [])
            item["source_revisions"].update(revisions or [])
            component_types.setdefault(package_id, set()).add(package_type)
        evidence: dict[uuid.UUID, PackageEvidence] = {}
        for package_id, values in evidence_sets.items():
            result = PackageEvidence(
                cpe=sorted(values["cpe"]), purl=sorted(values["purl"]), source_urls=sorted(values["source_urls"]),
            )
            if values["source_revisions"]:
                result["source_revisions"] = sorted(values["source_revisions"])
            types = component_types[package_id]
            if types != {"normal"}:
                result["component_types"] = sorted(types)
            evidence[package_id] = result
        return evidence

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
