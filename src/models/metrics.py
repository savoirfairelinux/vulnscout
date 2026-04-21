# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional, TYPE_CHECKING
from ..extensions import db, Base

if TYPE_CHECKING:
    from .cvss import CVSS


class Metrics(Base):
    """Stores a CVSS / scoring metric record for a :class:`Vulnerability`."""

    __tablename__ = "metrics"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id = db.Column(db.String(50), db.ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    version = db.Column(db.String, nullable=True)
    score = db.Column(db.Numeric, nullable=True)
    vector = db.Column(db.Text, nullable=True)
    author = db.Column(db.String, nullable=True)

    vulnerability = db.relationship("Vulnerability", back_populates="metrics")

    def __repr__(self) -> str:
        return (
            f"<Metrics id={self.id} vulnerability_id={self.vulnerability_id!r}"
            f" version={self.version!r} score={self.score}>"
        )

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        vulnerability_id: str,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
    ) -> "Metrics":
        """Create a new metrics record, persist it and return it."""
        metrics = Metrics(
            vulnerability_id=vulnerability_id.upper(),
            version=version,
            score=score,
            vector=vector,
            author=author,
        )
        db.session.add(metrics)
        db.session.commit()
        return metrics

    @staticmethod
    def get_by_id(metrics_id: uuid.UUID | str) -> Optional["Metrics"]:
        """Return the metrics record matching *metrics_id*, or ``None``."""
        if isinstance(metrics_id, str):
            metrics_id = uuid.UUID(metrics_id)
        return db.session.get(Metrics, metrics_id)

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list["Metrics"]:
        """Return all metrics for the given vulnerability id."""
        return list(db.session.execute(
            db.select(Metrics).where(Metrics.vulnerability_id == vulnerability_id.upper())
        ).scalars().all())

    def update(
        self,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
    ) -> "Metrics":
        """Update fields in place, persist the change and return ``self``."""
        if version is not None:
            self.version = version
        if score is not None:
            self.score = score
        if vector is not None:
            self.vector = vector
        if author is not None:
            self.author = author
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this metrics record from the database."""
        db.session.delete(self)
        db.session.commit()

    # Session-level dedup cache: avoids repeated 3-column SELECTs during
    # bulk ingestion.  Cleared automatically when the session is reset.
    _seen: set[tuple] = set()

    @classmethod
    def reset_cache(cls) -> None:
        """Clear the dedup cache (call between ingestion runs)."""
        cls._seen = set()

    @classmethod
    def from_cvss(cls, cvss: "CVSS", vulnerability_id: str) -> "Metrics":
        """Create a :class:`Metrics` record from an in-memory :class:`CVSS` object.

        If a matching record (same vulnerability_id + version + score) already exists it is
        returned unchanged; otherwise a new one is persisted.
        """
        vid = vulnerability_id.upper()
        dedup_key = (vid, cvss.version, float(cvss.base_score) if cvss.base_score is not None else None)
        if dedup_key in cls._seen:
            # Already persisted in this session — skip the SELECT entirely.
            return None  # type: ignore[return-value]
        cls._seen.add(dedup_key)

        # _seen is pre-populated from the DB at startup for all existing metrics.
        # Reaching here means this is genuinely new — skip the existence SELECT
        # and attempt the insert directly. On the rare race/duplicate, fall back.
        #
        # Use flush() instead of create() (which calls commit()) so the
        # caller's SAVEPOINT context stays open for subsequent metric inserts.
        try:
            with db.session.begin_nested():
                record = cls(
                    vulnerability_id=vid,
                    version=cvss.version,
                    score=cvss.base_score,
                    vector=cvss.vector_string,
                    author=cvss.author,
                )
                db.session.add(record)
                db.session.flush()
                return record
        except Exception:
            return db.session.execute(
                db.select(Metrics).where(
                    Metrics.vulnerability_id == vid,
                    Metrics.version == cvss.version,
                    Metrics.score == cvss.base_score,
                )
            ).scalar_one()
