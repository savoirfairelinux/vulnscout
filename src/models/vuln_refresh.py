# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import Base

if TYPE_CHECKING:
    from .vulnerability import Vulnerability


class VulnRefresh(Base):
    """
    Stores per-vulnerability refresh metadata (fetch timestamps, NVD last-modified, etc.)
    in a separate table so that the core ``vulnerabilities`` table stays focused on
    vulnerability content.

    There is at most one ``VulnRefresh`` row per vulnerability.  A row is only created
    the first time any refresh field is written, so vulnerabilities that have never been
    enriched by an external source will have no corresponding row.
    """

    __tablename__ = "vuln_refresh"

    vuln_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # EPSS enrichment timestamps
    epss_fetched_at: Mapped[datetime | None]
    epss_data_updated_at: Mapped[datetime | None]

    # NVD enrichment timestamps
    nvd_last_modified: Mapped[str | None] = mapped_column(Text)
    nvd_fetched_at: Mapped[datetime | None]
    nvd_data_updated_at: Mapped[datetime | None]

    # GHSA enrichment timestamps
    ghsa_fetched_at: Mapped[datetime | None]
    ghsa_data_updated_at: Mapped[datetime | None]

    # ENISA EUVD enrichment timestamps
    euvd_fetched_at: Mapped[datetime | None]
    euvd_data_updated_at: Mapped[datetime | None]

    # ------------------------------------------------------------------
    # Relationship
    # ------------------------------------------------------------------
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="refresh")
