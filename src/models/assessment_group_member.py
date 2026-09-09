# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Records which assessments were written by a single user action.

Membership is *sparse*: a row exists only when one action produced more than
one assessment for one vulnerability.  A single-target assessment has no group
and is referenced by its own assessment id.
"""

import json
import uuid

from sqlalchemy import ForeignKey, select
from sqlalchemy.orm import Mapped, mapped_column

from ..extensions import db, Base
from .assessment_target import GroupInvariantError

#: Fields that must be identical across a group's members.  A group is read
#: through its first member (``build_groups`` exposes ``head``) and written as a
#: whole (reconcile, approve, reject, delete), so members that differ on any of
#: these would hide content on read and be mutated as one action on write.
GROUP_CONTENT_FIELDS = (
    "status", "simplified_status", "status_notes", "justification",
    "impact_statement", "workaround", "origin",
)


#: Groups and targets enforce the same invariant -- one project, one
#: vulnerability, consistent content -- and both are raised on the same call
#: path (``create_assessment_record`` -> ``Assessment.create`` ->
#: ``validate_targets``, then ``AssessmentGroupMember.create_group``).  Two
#: distinct classes of the same name meant the route handlers caught one and
#: turned the other into a 500, so there is exactly one class, defined next to
#: the targets and re-exported here for the modules that import it from this
#: module.
__all__ = ["GROUP_CONTENT_FIELDS", "GroupInvariantError", "canonical_responses",
           "AssessmentGroupMember"]


def canonical_responses(responses: "list[str] | None") -> str:
    """Return an order-independent representation of a row's VEX responses."""
    return json.dumps(sorted(str(item) for item in (responses or [])))


class AssessmentGroupMember(Base):
    """Links one :class:`Assessment` to the group it was created with."""

    __tablename__ = "assessment_group_members"

    # Primary key on assessment_id enforces "one group per assessment".
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(index=True, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<AssessmentGroupMember assessment_id={self.assessment_id}"
            f" group_id={self.group_id}>"
        )

    @staticmethod
    def invariant_keys(assessment_ids: "list[uuid.UUID]") -> "dict[uuid.UUID, tuple]":
        """Return the group-invariant key of every requested assessment.

        The key is ``(project, vulnerability, content…, responses)``.  Rows are
        resolved in bulk — project through the row's variant, vulnerability
        through its finding — so validating a group costs one query rather than
        one per member.  Unknown ids are simply absent from the result.
        """
        from .assessment import Assessment
        from .finding import Finding
        from .variant import Variant

        if not assessment_ids:
            return {}
        rows = db.session.execute(
            select(Assessment, Variant.project_id, Finding.vulnerability_id)
            .outerjoin(Variant, Variant.id == Assessment.variant_id)
            .outerjoin(Finding, Finding.id == Assessment.finding_id)
            .where(Assessment.id.in_(assessment_ids))
        ).all()
        return {
            row[0].id: (
                row[1],
                (row[2] or "").upper(),
                *(getattr(row[0], field) or "" for field in GROUP_CONTENT_FIELDS),
                canonical_responses(row[0].responses),
            )
            for row in rows
        }

    @staticmethod
    def validate_group(
        assessment_ids: "list[uuid.UUID]", group_id: "uuid.UUID | None" = None
    ) -> None:
        """Raise :class:`GroupInvariantError` unless these rows may share a group.

        Called before every membership write: reads expose only the first
        member's content while delete/reconcile/approve/reject mutate every
        member, so a group that crosses a project, a vulnerability or a content
        variation would silently hide rows and mutate unrelated ones.
        """
        candidate_ids = list(assessment_ids)
        if group_id is not None:
            candidate_ids += [
                member_id
                for member_id in AssessmentGroupMember.get_assessment_ids(group_id)
                if member_id not in set(assessment_ids)
            ]
        keys = AssessmentGroupMember.invariant_keys(candidate_ids)
        missing = [str(a) for a in candidate_ids if a not in keys]
        if missing:
            raise GroupInvariantError(
                "Unknown assessment: " + ", ".join(sorted(missing))
            )
        distinct = set(keys.values())
        if len(distinct) > 1:
            projects = {key[0] for key in distinct}
            vulns = {key[1] for key in distinct}
            if len(projects) > 1:
                reason = "they belong to different projects"
            elif len(vulns) > 1:
                reason = "they address different vulnerabilities"
            else:
                reason = "their content differs"
            raise GroupInvariantError(
                f"Assessments cannot share a group: {reason}"
            )

    @staticmethod
    def create_group(
        assessment_ids: "list[uuid.UUID]",
        group_id: "uuid.UUID | None" = None,
        commit: bool = True,
    ) -> uuid.UUID:
        """Put every assessment in ``assessment_ids`` into one group.

        Args:
            assessment_ids: rows to link.  May be a single id when joining a
                group that an earlier request already created.
            group_id: join this existing group instead of starting a new one.
            commit: False for bulk operations inside ``batch_session()``.

        Returns:
            The group id the assessments now belong to.

        Raises:
            GroupInvariantError: when the resulting group would span more than
                one project, vulnerability or content tuple.
        """
        AssessmentGroupMember.validate_group(assessment_ids, group_id)
        resolved = group_id or uuid.uuid4()
        for assessment_id in assessment_ids:
            db.session.add(
                AssessmentGroupMember(assessment_id=assessment_id, group_id=resolved)
            )
        if commit:
            db.session.commit()
        else:
            db.session.flush()
        return resolved

    @staticmethod
    def get_assessment_ids(group_id: uuid.UUID) -> "list[uuid.UUID]":
        """Return every assessment id in the group, empty when unknown."""
        return list(db.session.execute(
            select(AssessmentGroupMember.assessment_id)
            .where(AssessmentGroupMember.group_id == group_id)
        ).scalars())

    @staticmethod
    def get_group_ids(
        assessment_ids: "list[uuid.UUID]",
    ) -> "dict[uuid.UUID, uuid.UUID]":
        """Return ``{assessment_id: group_id}`` for the grouped rows, in one query."""
        if not assessment_ids:
            return {}
        return {
            row.assessment_id: row.group_id
            for row in db.session.execute(
                select(AssessmentGroupMember.assessment_id,
                       AssessmentGroupMember.group_id)
                .where(AssessmentGroupMember.assessment_id.in_(assessment_ids))
            ).all()
        }

    @staticmethod
    def get_group_id(assessment_id: uuid.UUID) -> "uuid.UUID | None":
        """Return the assessment's group id, or None when it is ungrouped."""
        return db.session.execute(
            select(AssessmentGroupMember.group_id)
            .where(AssessmentGroupMember.assessment_id == assessment_id)
        ).scalar_one_or_none()
