# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Durable refresh artifacts, independent of live vulnerabilities and queue retention."""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import Base


class RefreshRun(Base):
    __tablename__ = "refresh_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scope: Mapped[dict] = mapped_column(JSON)
    sources: Mapped[list] = mapped_column(JSON)
    source_status: Mapped[dict] = mapped_column(JSON)
    # Retain the empty legacy column to avoid rebuilding a referenced SQLite table.
    _legacy_coverage: Mapped[list] = mapped_column("coverage", JSON, default=list)
    owner: Mapped[dict] = mapped_column(JSON)
    targets: Mapped[list["RefreshTarget"]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True, order_by="RefreshTarget.id",
    )

    @property
    def coverage(self) -> list[dict]:
        return [target.as_dict() for target in self.targets]


class RefreshTarget(Base):
    __tablename__ = "refresh_targets"
    __table_args__ = (
        UniqueConstraint("run_id", "source", "vuln_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    source: Mapped[str] = mapped_column(String(16))
    vuln_id: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(String)
    packages: Mapped[list] = mapped_column(JSON)

    def as_dict(self) -> dict:
        return {key: getattr(self, key) for key in ("source", "vuln_id", "status", "error", "packages")}


class RefreshChange(Base):
    __tablename__ = "refresh_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    snapshot: Mapped[dict] = mapped_column(JSON)
