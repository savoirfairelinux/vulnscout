# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Document-scoped SPDX files and their package/build associations."""

from typing import Any, TYPE_CHECKING, TypedDict
import uuid

from sqlalchemy import ForeignKey, ForeignKeyConstraint, func, Index, JSON, Text, UniqueConstraint
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


class SourceFileCounts(TypedDict):
    source_file_count: int
    compiled_source_file_count: int


def has_compilation_evidence(builds: list[dict[str, Any]]) -> bool:
    """Recognize West's compiler targets, not arbitrary build or generator tasks."""
    return any(
        build.get("compiled", True) is True
        and build.get("build_type") == "urn:spdx.dev:zephyr-cmake"
        and isinstance(build.get("parameters"), list)
        and any(
            isinstance(parameter, dict)
            and parameter.get("key") in ("compile:flags:C", "compile:flags:CXX", "compile:flags:ASM")
            and isinstance(parameter.get("value"), str)
            for parameter in build["parameters"]
        )
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
    build_links: Mapped[list["SBOMFileBuild"]] = relationship(
        back_populates="file", cascade="all, delete-orphan",
    )


class SBOMBuild(Base):
    __tablename__ = "sbom_builds"
    __table_args__ = (UniqueConstraint("sbom_document_id", "spdx_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sbom_documents.id"))
    spdx_id: Mapped[str] = mapped_column(Text)
    build_type: Mapped[str | None] = mapped_column(Text)
    parameters: Mapped[list] = mapped_column(JSON)
    outputs: Mapped[list[str]] = mapped_column(JSON)
    compiled: Mapped[bool]

    sbom_document: Mapped["SBOMDocument"] = relationship(back_populates="builds")
    file_links: Mapped[list["SBOMFileBuild"]] = relationship(
        back_populates="build", cascade="all, delete-orphan",
    )


class SBOMFileBuild(Base):
    __tablename__ = "sbom_file_builds"
    __table_args__ = (
        ForeignKeyConstraint(
            ["file_document_id", "spdx_id"], ["sbom_files.sbom_document_id", "sbom_files.spdx_id"],
            ondelete="CASCADE",
        ),
        Index("ix_sbom_file_builds_build", "build_id"),
    )

    file_document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    spdx_id: Mapped[str] = mapped_column(Text, primary_key=True)
    build_id: Mapped[int] = mapped_column(ForeignKey("sbom_builds.id", ondelete="CASCADE"), primary_key=True)

    file: Mapped["SBOMFile"] = relationship(back_populates="build_links")
    build: Mapped["SBOMBuild"] = relationship(back_populates="file_links")


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

    sbom_package: Mapped["SBOMPackage"] = relationship(back_populates="source_files")
    file: Mapped["SBOMFile"] = relationship(back_populates="package_links")

    @staticmethod
    def counts_for_documents(
        document_ids: set[uuid.UUID], package_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, SourceFileCounts]:
        """Count distinct file records and compiled paths without fetching JSON evidence."""
        if not document_ids or package_ids == set():
            return {}
        filters = [PackageSourceFile.sbom_document_id.in_(document_ids)]
        if package_ids is not None:
            filters.append(PackageSourceFile.package_id.in_(package_ids))
        associations = db.select(
            PackageSourceFile.package_id, PackageSourceFile.file_document_id, PackageSourceFile.spdx_id,
        ).where(*filters).distinct().subquery()
        counts = {
            package_id: SourceFileCounts(source_file_count=count, compiled_source_file_count=0)
            for package_id, count in db.session.execute(
                db.select(associations.c.package_id, func.count()).group_by(associations.c.package_id)
            )
        }
        compiled = db.select(SBOMFileBuild.build_id).join(SBOMBuild).where(
            SBOMFileBuild.file_document_id == SBOMFile.sbom_document_id,
            SBOMFileBuild.spdx_id == SBOMFile.spdx_id,
            SBOMBuild.compiled.is_(True),
        ).exists()
        paths = db.select(associations.c.package_id, SBOMFile.path).join(SBOMFile, db.and_(
            associations.c.file_document_id == SBOMFile.sbom_document_id,
            associations.c.spdx_id == SBOMFile.spdx_id,
        )).where(compiled).distinct().subquery()
        for package_id, count in db.session.execute(
            db.select(paths.c.package_id, func.count()).group_by(paths.c.package_id)
        ):
            counts[package_id]["compiled_source_file_count"] = count
        return counts

    @staticmethod
    def evidence_for_documents(
        document_ids: set[uuid.UUID], package_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, list[SourceFileEvidence]]:
        """Read only file associations owned by the selected package documents."""
        result: dict[uuid.UUID, dict[tuple, SourceFileEvidence]] = {}
        if not document_ids or package_ids == set():
            return {}
        filters = [PackageSourceFile.sbom_document_id.in_(document_ids)]
        if package_ids is not None:
            filters.append(PackageSourceFile.package_id.in_(package_ids))
        build_links = list(db.session.execute(
            db.select(SBOMFileBuild.file_document_id, SBOMFileBuild.spdx_id, SBOMFileBuild.build_id)
            .join(PackageSourceFile, db.and_(
                PackageSourceFile.file_document_id == SBOMFileBuild.file_document_id,
                PackageSourceFile.spdx_id == SBOMFileBuild.spdx_id,
            ))
            .where(*filters)
            .distinct()
        ))
        build_ids = {build_id for _, _, build_id in build_links}
        builds = {
            build.id: {
                "spdx_id": build.spdx_id, "document_name": document_name, "build_type": build.build_type,
                "parameters": build.parameters, "outputs": build.outputs,
                "compiled": has_compilation_evidence([{
                    "build_type": build.build_type, "parameters": build.parameters, "compiled": build.compiled,
                }]),
            }
            for build, document_name in db.session.execute(
                db.select(SBOMBuild, SBOMDocument.source_name)
                .join(SBOMDocument, SBOMBuild.sbom_document_id == SBOMDocument.id)
                .where(SBOMBuild.id.in_(build_ids))
            )
        } if build_ids else {}
        file_builds: dict[tuple, list[dict[str, Any]]] = {}
        for document_id, spdx_id, build_id in build_links:
            file_builds.setdefault((document_id, spdx_id), []).append(builds[build_id])
        for values in file_builds.values():
            values.sort(key=lambda build: (build["document_name"], build["spdx_id"]))
        rows = db.session.execute(
            db.select(PackageSourceFile, SBOMFile, SBOMDocument.source_name,
                      SBOMDocument.scan_id, Variant.id, Variant.name)
            .join(SBOMFile, PackageSourceFile.file)
            .join(SBOMDocument, SBOMFile.sbom_document_id == SBOMDocument.id)
            .join(Scan, SBOMDocument.scan_id == Scan.id)
            .join(Variant, Scan.variant_id == Variant.id)
            .where(*filters)
        )
        for link, file, document_name, scan_id, variant_id, variant_name in rows:
            files = result.setdefault(link.package_id, {})
            key = (file.sbom_document_id, file.spdx_id)
            files.setdefault(key, SourceFileEvidence(
                spdx_id=file.spdx_id, path=file.path, document_id=str(file.sbom_document_id),
                document_name=document_name, properties=file.properties, builds=file_builds.get(key, []),
                scan_id=str(scan_id), variant_id=str(variant_id), variant_name=variant_name,
            ))
        return {
            package_id: sorted(files.values(), key=lambda item: (item["path"], item["document_id"], item["spdx_id"]))
            for package_id, files in result.items()
        }
