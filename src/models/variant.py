# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from ..extensions import db


class Variant(db.Model):
    """Represents a named variant (e.g. board configuration) belonging to a project."""

    __tablename__ = "variants"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=False, unique=True)
    project_id = db.Column(db.Uuid, db.ForeignKey("projects.id"), nullable=False)

    project = db.relationship("Project", back_populates="variants")
    scans = db.relationship("Scan", back_populates="variant", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Variant id={self.id} name={self.name!r}>"
