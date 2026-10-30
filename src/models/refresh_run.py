# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Durable refresh artifacts, independent of live vulnerabilities and queue retention."""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import Base


class RefreshRun(Base):
    __tablename__ = "refresh_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scope: Mapped[dict] = mapped_column(JSON)
    sources: Mapped[list] = mapped_column(JSON)
    source_status: Mapped[dict] = mapped_column(JSON)
    coverage: Mapped[list] = mapped_column(JSON)


class RefreshChange(Base):
    __tablename__ = "refresh_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    snapshot: Mapped[dict] = mapped_column(JSON)
