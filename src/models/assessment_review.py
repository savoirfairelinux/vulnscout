# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from datetime import datetime, timezone

from sqlalchemy import Text, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, relationship, mapped_column

from ..extensions import db, Base
from ..helpers.datetime_utils import ensure_utc_iso
from .assessment import Assessment


# Fields compared to decide whether a review agrees with its assessment.
VERDICT_FIELDS = ("status", "justification", "impact_statement", "workaround")


class AssessmentReview(Base):
    """An AI-generated second opinion on a single custom :class:`Assessment`.

    Carries the same VEX fields as the assessment it reviews, so a future
    "accept" action can copy them across unchanged, plus a ``rationale``
    explaining the review itself. Exactly one review may exist per assessment;
    writes overwrite.
    """

    __tablename__ = "assessment_reviews"
    __table_args__ = (UniqueConstraint("assessment_id", name="uq_assessment_review_assessment"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(nullable=False)
    status_notes: Mapped[str | None] = mapped_column(Text)
    justification: Mapped[str | None] = mapped_column(Text)
    impact_statement: Mapped[str | None] = mapped_column(Text)
    workaround: Mapped[str | None] = mapped_column(Text)
    responses: Mapped[list[str] | None] = mapped_column(JSON)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="review")

    def __repr__(self) -> str:
        return (
            f"<AssessmentReview id={self.id} status={self.status!r}"
            f" assessment_id={self.assessment_id}>"
        )

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------

    def verdict(self) -> str:
        """``'agrees'`` when every VEX field matches the parent assessment."""
        parent = self.assessment
        if parent is None:
            return "differs"
        for field in VERDICT_FIELDS:
            if (getattr(self, field) or "") != (getattr(parent, field) or ""):
                return "differs"
        if sorted(self.responses or []) != sorted(parent.responses or []):
            return "differs"
        return "agrees"

    def is_stale(self) -> bool:
        """True when the assessment was edited after this review was written."""
        parent = self.assessment
        if parent is None or parent.timestamp is None or self.timestamp is None:
            return False
        return parent.timestamp > self.timestamp

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "assessment_id": str(self.assessment_id),
            "status": self.status or "",
            "status_notes": self.status_notes or "",
            "justification": self.justification or "",
            "impact_statement": self.impact_statement or "",
            "workaround": self.workaround or "",
            "responses": list(self.responses or []),
            "rationale": self.rationale or "",
            "timestamp": ensure_utc_iso(self.timestamp),
            "verdict": self.verdict(),
            "is_stale": self.is_stale(),
        }

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_by_assessment(assessment_id: uuid.UUID) -> "AssessmentReview | None":
        return db.session.execute(
            db.select(AssessmentReview).where(AssessmentReview.assessment_id == assessment_id)
        ).scalars().one_or_none()

    @staticmethod
    def get_for_variants(variant_ids: list[uuid.UUID] | None = None) -> list["AssessmentReview"]:
        query = db.select(AssessmentReview).join(
            Assessment, AssessmentReview.assessment_id == Assessment.id
        )
        if variant_ids:
            query = query.where(Assessment.variant_id.in_(variant_ids))
        return list(db.session.execute(query).scalars().unique().all())

    @staticmethod
    def upsert(
        assessment_id: uuid.UUID,
        status: str,
        rationale: str,
        status_notes: str | None = None,
        justification: str | None = None,
        impact_statement: str | None = None,
        workaround: str | None = None,
        responses: list[str] | None = None,
    ) -> "AssessmentReview":
        """Create the review, or overwrite the existing one for this assessment."""
        review = AssessmentReview.get_by_assessment(assessment_id)
        if review is None:
            review = AssessmentReview(id=uuid.uuid4(), assessment_id=assessment_id)
            db.session.add(review)
        review.status = status
        review.rationale = rationale
        review.status_notes = status_notes
        review.justification = justification
        review.impact_statement = impact_statement
        review.workaround = workaround
        review.responses = list(responses or [])
        review.timestamp = datetime.now(timezone.utc)
        db.session.commit()
        return review

    def delete(self) -> None:
        db.session.delete(self)
        db.session.commit()
