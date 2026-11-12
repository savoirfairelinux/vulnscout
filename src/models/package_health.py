# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Upstream repository mapping and OpenSSF Scorecard cache for packages."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import Base


class PackageRepository(Base):
    """Upstream source repository resolved for one package and active evidence identity."""

    __tablename__ = "package_repositories"

    package_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"), primary_key=True,
    )
    evidence_key: Mapped[str] = mapped_column(String(64), primary_key=True, default="")
    repository: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[str | None] = mapped_column(Text)
    deprecated: Mapped[bool | None]
    deprecated_reason: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime]


class RepositoryScorecard(Base):
    """Cached OpenSSF Scorecard lookup for one repository."""

    __tablename__ = "repository_scorecards"

    repository: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))
    # Scorecard publishes names in the repository's canonical case, which SBOM identifiers may not keep.
    published_repository: Mapped[str | None] = mapped_column(String(255))
    score: Mapped[float | None]
    checks: Mapped[list | None] = mapped_column(JSON)
    scorecard_date: Mapped[str | None] = mapped_column(String(32))
    commit: Mapped[str | None] = mapped_column(String(64))
    fetched_at: Mapped[datetime]
