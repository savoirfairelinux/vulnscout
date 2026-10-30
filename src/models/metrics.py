# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, cast

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db, Base

if TYPE_CHECKING:
    from ..models import CVSS, Vulnerability, Variant


class Metrics(Base):
    """Stores a CVSS / scoring metric record for a :class:`Vulnerability`."""

    __tablename__ = "metrics"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    variant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("variants.id"), index=True, active_history=True)
    version: Mapped[str | None] = mapped_column(active_history=True)
    # ``active_history`` lets the ``vulnerability_history`` listener see the old score.
    score: Mapped[Decimal | None] = mapped_column(active_history=True)
    vector: Mapped[str | None] = mapped_column(Text, active_history=True)
    author: Mapped[str | None] = mapped_column(active_history=True)
    origin: Mapped[str | None] = mapped_column()

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="metrics")
    variant: Mapped["Variant | None"] = relationship(back_populates="metrics")

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
        variant_id: Optional[uuid.UUID] = None,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> "Metrics":
        """Create a new metrics record, persist it and return it."""
        metrics = Metrics(
            vulnerability_id=vulnerability_id.upper(),
            variant_id=variant_id,
            version=version,
            score=score,
            vector=vector,
            author=author,
            origin=origin,
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

    @staticmethod
    def get_by_vulnerability_and_variant(
        vulnerability_id: str,
        variant_id: uuid.UUID,
        include_unscoped: bool = True,
    ) -> list["Metrics"]:
        """Return metrics for a vulnerability scoped to *variant_id*.

        When *include_unscoped* is ``True``, legacy records with
        ``variant_id is NULL`` are also included.
        """
        query = db.select(Metrics).where(Metrics.vulnerability_id == vulnerability_id.upper())
        if include_unscoped:
            query = query.where(db.or_(Metrics.variant_id == variant_id, Metrics.variant_id.is_(None)))
        else:
            query = query.where(Metrics.variant_id == variant_id)
        return list(db.session.execute(query).scalars().all())

    def update(
        self,
        version: Optional[str] = None,
        score: Optional[float] = None,
        vector: Optional[str] = None,
        author: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> "Metrics":
        """Update fields in place, persist the change and return ``self``."""
        if version is not None:
            self.version = version
        if score is not None:
            self.score = Decimal(score)
        if vector is not None:
            self.vector = vector
        if author is not None:
            self.author = author
        if origin is not None:
            self.origin = origin
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this metrics record from the database."""
        db.session.delete(self)
        db.session.commit()

    def to_dict(self) -> dict:
        """Return a CVSS-compatible dict representation of this metrics record."""
        return {
            "variant_id": str(self.variant_id) if self.variant_id is not None else None,
            "version": self.version or "",
            "vector_string": self.vector or "",
            "author": self.author or "unknown",
            "origin": self.origin or "scanner",
            "base_score": float(self.score) if self.score is not None else 0.0,
            "exploitability_score": 0.0,
            "impact_score": 0.0,
        }

    # Session-level dedup cache: avoids repeated 3-column SELECTs during
    # bulk ingestion.  Cleared automatically when the session is reset.
    _seen: set[tuple] = set()

    @classmethod
    def reset_cache(cls) -> None:
        """Clear the dedup cache (call between ingestion runs)."""
        cls._seen = set()

    @classmethod
    def from_cvss(
        cls,
        cvss: "CVSS",
        vulnerability_id: str,
        variant_id: uuid.UUID | None = None,
    ) -> Optional["Metrics"]:
        """Create a :class:`Metrics` record from an in-memory :class:`CVSS` object.

        If a matching record (same vulnerability_id + variant_id + version + score) already exists it is
        returned unchanged when insert fallback is triggered; otherwise a new one is persisted.
        When the session dedup cache hits, ``None`` is returned to signal a no-op.

        Scoping rule based on ``origin``:
          * ``"custom"`` — user-entered override; stored scoped to *variant_id*
            so it stays isolated per project/variant.
          * anything else (``"scanner"`` and the like) — standard data shared by
            every variant; forced to ``variant_id = NULL`` so it is stored once
            and never duplicated across variants.
        """
        vid = vulnerability_id.upper()

        # Standard (scanner) metrics are global: never scope them to a variant,
        # otherwise the same NVD/Grype score would be stored once per variant.
        origin = getattr(cvss, "origin", None)
        if origin != "custom":
            variant_id = None

        dedup_key = (
            vid,
            variant_id,
            cvss.version,
            float(cvss.base_score) if cvss.base_score is not None else None,
        )
        if dedup_key in cls._seen:
            # Already persisted in this session: no-op.
            return None
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
                    variant_id=variant_id,
                    version=cvss.version,
                    score=cvss.base_score,
                    vector=cvss.vector_string,
                    author=cvss.author,
                    origin=origin,
                )
                db.session.add(record)
                db.session.flush()
                return record
        except Exception as exc:
            existing = db.session.execute(
                db.select(Metrics).where(
                    Metrics.vulnerability_id == vid,
                    Metrics.variant_id == variant_id,
                    Metrics.version == cvss.version,
                    Metrics.score == cvss.base_score,
                )
            ).scalar_one_or_none()
            if existing is None:
                raise exc
            return cast("Metrics", existing)
