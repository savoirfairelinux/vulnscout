# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from ..extensions import db, Base

from sqlalchemy.orm import Mapped


class ScanDiffCache(Base):
    """Pre-computed scan history diff data.

    This is a **derived / cache** table — every row can be regenerated
    from the source data (scans, observations, findings, packages).
    It should *not* be exported when shipping the database for
    portability; instead it is rebuilt on import via
    ``recompute_variant_cache()``.
    """

    __tablename__ = "scan_diff_cache"

    scan_id: Mapped[uuid.UUID] = db.Column(
        db.Uuid, db.ForeignKey("scans.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # --- absolute counts (always present) ---
    finding_count: Mapped[int] = db.Column(db.Integer, nullable=False, default=0)
    package_count: Mapped[int] = db.Column(db.Integer, nullable=False, default=0)
    vuln_count: Mapped[int] = db.Column(db.Integer, nullable=False, default=0)

    is_first: Mapped[bool] = db.Column(db.Boolean, nullable=False, default=True)

    # --- diff counts (nullable — None for first-SBOM scans) ---
    findings_added: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    findings_removed: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    findings_upgraded: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    findings_unchanged: Mapped[int | None] = db.Column(db.Integer, nullable=True)

    packages_added: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    packages_removed: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    packages_upgraded: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    packages_unchanged: Mapped[int | None] = db.Column(db.Integer, nullable=True)

    vulns_added: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    vulns_removed: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    vulns_unchanged: Mapped[int | None] = db.Column(db.Integer, nullable=True)

    # --- tool-scan specific (nullable — None for SBOM scans) ---
    newly_detected_findings: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    newly_detected_vulns: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    branch_finding_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    branch_vuln_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    branch_package_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)

    # --- global result (nullable — None when no tool scans exist) ---
    global_finding_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    global_vuln_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)
    global_package_count: Mapped[int | None] = db.Column(db.Integer, nullable=True)

    # --- SBOM formats (JSON list as text, e.g. '["spdx2","spdx3"]') ---
    formats_json: Mapped[str | None] = db.Column(db.Text, nullable=True)

    def __repr__(self) -> str:
        return f"<ScanDiffCache scan_id={self.scan_id}>"
