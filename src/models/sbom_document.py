# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from ..extensions import db


class SBOMDocument(db.Model):
    """Represents an SBOM document file linked to a scan."""

    __tablename__ = "sbom_documents"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    path = db.Column(db.Text, nullable=False)
    source_name = db.Column(db.String, nullable=False)
    scan_id = db.Column(db.Uuid, db.ForeignKey("scans.id"), nullable=False)

    scan = db.relationship("Scan", back_populates="sbom_documents")

    def __repr__(self) -> str:
        return f"<SBOMDocument id={self.id} source_name={self.source_name!r}>"
