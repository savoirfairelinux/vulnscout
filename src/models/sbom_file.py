# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Document-scoped SPDX files and their package/build associations."""

from typing import Any, TYPE_CHECKING, TypedDict
import uuid

from sqlalchemy import ForeignKey, ForeignKeyConstraint, Index, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import Base, db
from .sbom_document import SBOMDocument
from .scan import Scan
from .variant import Variant

if TYPE_CHECKING:
    from .sbom_package import SBOMPackage


class SourceFileEvidence(TypedDict):
    spdx_id: str
    path: str
    document_id: str
    document_name: str
    scan_id: str
    variant_id: str
    variant_name: str
    properties: dict[str, Any]
    builds: list[dict[str, Any]]


def has_compilation_evidence(builds: list[dict[str, Any]]) -> bool:
    """Recipe task inputs alone do not establish which source files were compiled."""
    return any(
        build.get("compiled", True) and not str(build.get("build_type", "")).startswith((
            "http://openembedded.org/bitbake/", "https://openembedded.org/bitbake/",
        ))
        for build in builds
    )


class SBOMFile(Base):
    __tablename__ = "sbom_files"

    sbom_document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_documents.id"), primary_key=True)
    spdx_id: Mapped[str] = mapped_column(Text, primary_key=True)
    path: Mapped[str] = mapped_column(Text)
    properties: Mapped[dict] = mapped_column(JSON)

    sbom_document: Mapped["SBOMDocument"] = relationship(back_populates="files")
    package_links: Mapped[list["PackageSourceFile"]] = relationship(
        back_populates="file", cascade="all, delete-orphan",
    )


class PackageSourceFile(Base):
    __tablename__ = "package_source_files"
    __table_args__ = (
        Index("ix_package_source_files_file", "file_document_id", "spdx_id"),
        ForeignKeyConstraint(
            ["sbom_document_id", "package_id"], ["sbom_packages.sbom_document_id", "sbom_packages.package_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["file_document_id", "spdx_id"], ["sbom_files.sbom_document_id", "sbom_files.spdx_id"],
            ondelete="CASCADE",
        ),
    )

    sbom_document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    package_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    file_document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    spdx_id: Mapped[str] = mapped_column(Text, primary_key=True)
    builds: Mapped[list] = mapped_column(JSON)

    sbom_package: Mapped["SBOMPackage"] = relationship(back_populates="source_files")
    file: Mapped["SBOMFile"] = relationship(back_populates="package_links")

    @staticmethod
    def evidence_for_documents(document_ids: set[uuid.UUID]) -> dict[uuid.UUID, list[SourceFileEvidence]]:
        """Read only file associations owned by the selected package documents."""
        result: dict[uuid.UUID, dict[tuple, SourceFileEvidence]] = {}
        if not document_ids:
            return {}
        rows = db.session.execute(
            db.select(PackageSourceFile, SBOMFile, SBOMDocument.source_name,
                      SBOMDocument.scan_id, Variant.id, Variant.name)
            .join(SBOMFile, PackageSourceFile.file)
            .join(SBOMDocument, SBOMFile.sbom_document_id == SBOMDocument.id)
            .join(Scan, SBOMDocument.scan_id == Scan.id)
            .join(Variant, Scan.variant_id == Variant.id)
            .where(PackageSourceFile.sbom_document_id.in_(document_ids))
        )
        for link, file, document_name, scan_id, variant_id, variant_name in rows:
            files = result.setdefault(link.package_id, {})
            key = (file.sbom_document_id, file.spdx_id)
            item = files.setdefault(key, SourceFileEvidence(
                spdx_id=file.spdx_id, path=file.path, document_id=str(file.sbom_document_id),
                document_name=document_name, properties=file.properties, builds=[],
                scan_id=str(scan_id), variant_id=str(variant_id), variant_name=variant_name,
            ))
            for build in link.builds:
                if build not in item["builds"]:
                    item["builds"].append(build)
        return {
            package_id: sorted(files.values(), key=lambda item: (item["path"], item["document_id"], item["spdx_id"]))
            for package_id, files in result.items()
        }
