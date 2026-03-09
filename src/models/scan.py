# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from datetime import datetime, timezone
from ..extensions import db


class Scan(db.Model):
    """Represents a single scan run associated with a variant."""

    __tablename__ = "scans"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    description = db.Column(db.Text, nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    variant_id = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=False)

    variant = db.relationship("Variant", back_populates="scans")
    sbom_documents = db.relationship("SBOMDocument", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} timestamp={self.timestamp}>"
