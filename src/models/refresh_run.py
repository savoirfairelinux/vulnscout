# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Durable refresh artifacts, independent of live vulnerabilities and queue retention.

Per-source and per-target outcomes are separate rows so concurrent writers
(provider loop, queue cancellation, owner reconciliation) update only the
rows they own with single atomic statements, never a shared document.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import Base


class RefreshRun(Base):
    __tablename__ = "refresh_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scope: Mapped[dict] = mapped_column(JSON)
    owner: Mapped[dict] = mapped_column(JSON)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RefreshRunScope(Base):
    """Queryable project/variant pairs of a run's initiating scope."""

    __tablename__ = "refresh_run_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    project_id: Mapped[str | None] = mapped_column(String(36))
    variant_id: Mapped[str | None] = mapped_column(String(36))


class RefreshRunSource(Base):
    __tablename__ = "refresh_run_sources"

    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), primary_key=True,
    )
    source: Mapped[str] = mapped_column(String(16), primary_key=True)
    position: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))


class RefreshTarget(Base):
    __tablename__ = "refresh_run_targets"
    __table_args__ = (UniqueConstraint("run_id", "source", "vuln_id", name="uq_refresh_run_targets_identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    source: Mapped[str] = mapped_column(String(16))
    vuln_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(Text)


class RefreshTargetLink(Base):
    """Active package/variant link captured when a target was added; immutable."""

    __tablename__ = "refresh_run_target_links"
    __table_args__ = (Index("ix_refresh_run_target_links_scope", "project_id", "variant_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("refresh_run_targets.id", ondelete="CASCADE"), index=True,
    )
    package_id: Mapped[str] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    package: Mapped[str] = mapped_column(Text)
    project_id: Mapped[str] = mapped_column(String(36))
    variant_id: Mapped[str] = mapped_column(String(36))


class RefreshChange(Base):
    __tablename__ = "refresh_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("refresh_runs.run_id", ondelete="CASCADE"), index=True,
    )
    target_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("refresh_run_targets.id", ondelete="CASCADE"), index=True,
    )
    vuln_id: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16))
    field: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    change_type: Mapped[str] = mapped_column(String(16))
    snapshot: Mapped[dict] = mapped_column(JSON)
