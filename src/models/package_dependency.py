# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from sqlalchemy import ForeignKey, ForeignKeyConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import Base


class PackageDependency(Base):
    """Edge stored under the dependent's document; the dependency may sit in another document of the scan."""

    __tablename__ = "package_dependencies"

    sbom_document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    package_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    dependency_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"), primary_key=True
    )

    __table_args__ = (
        Index("ix_package_dependencies_document_dependency", "sbom_document_id", "dependency_id"),
        ForeignKeyConstraint(
            ["sbom_document_id", "package_id"],
            ["sbom_packages.sbom_document_id", "sbom_packages.package_id"],
            ondelete="CASCADE",
        ),
    )
