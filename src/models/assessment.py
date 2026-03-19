# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import orm
from ..extensions import db, Base


# ---------------------------------------------------------------------------
# VEX-related constants
# ---------------------------------------------------------------------------

VALID_STATUS_OPENVEX = ["under_investigation", "not_affected", "affected", "fixed"]
VALID_STATUS_CDX_VEX = ["in_triage", "false_positive", "not_affected", "exploitable",
                        "resolved", "resolved_with_pedigree"]
STATUS_CDX_VEX_TO_OPENVEX = {
    "in_triage": "under_investigation",
    "false_positive": "not_affected",
    "not_affected": "not_affected",
    "exploitable": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed"
}
STATUS_OPENVEX_TO_CDX_VEX = {
    "under_investigation": "in_triage",
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved"
}

VALID_JUSTIFICATION_OPENVEX = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist"
]
VALID_JUSTIFICATION_CDX_VEX = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control"
]
JUSTIFICATION_CDX_VEX_TO_OPENVEX = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "component_not_present",
    "requires_environment": "vulnerable_code_not_present",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist"
}
JUSTIFICATION_OPENVEX_TO_CDX_VEX = {
    "component_not_present": "requires_dependency",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",
    "inline_mitigations_already_exist": "protected_by_mitigating_control"
}

RESPONSES_CDX_VEX = [
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available"
]


# ---------------------------------------------------------------------------
# Assessment model
# ---------------------------------------------------------------------------

class Assessment(Base):
    """Stores a triage assessment for a :class:`Finding` scoped to a :class:`Variant`.

    Also serves as a drop-in replacement for the former in-memory
    ``VulnAssessment`` DTO so that parsers and controllers can use the same
    API.  Call :meth:`new_dto` to create a lightweight, non-persisted instance
    for the parsing pipeline.
    """

    __tablename__ = "assessments"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    source = db.Column(db.String, nullable=True)
    status = db.Column(db.String, nullable=True)
    simplified_status = db.Column(db.String, nullable=True)
    status_notes = db.Column(db.Text, nullable=True)
    justification = db.Column(db.Text, nullable=True)
    impact_statement = db.Column(db.Text, nullable=True)
    workaround = db.Column(db.Text, nullable=True)
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    responses = db.Column(db.JSON, nullable=True)
    finding_id = db.Column(db.Uuid, db.ForeignKey("findings.id"), nullable=True)
    variant_id = db.Column(db.Uuid, db.ForeignKey("variants.id"), nullable=True)

    finding = db.relationship("Finding", back_populates="assessments")
    variant = db.relationship("Variant", back_populates="assessments")

    # ------------------------------------------------------------------
    # Transient attributes (initialised by _init_transient)
    # ------------------------------------------------------------------

    @orm.reconstructor
    def _init_on_load(self):
        """Called by SQLAlchemy when reconstituting from the DB."""
        self._init_transient()

    def _init_transient(self):
        if not hasattr(self, "_vuln_id"):
            self._vuln_id = ""
        if not hasattr(self, "_packages"):
            self._packages: list[str] = []

    # ------------------------------------------------------------------
    # vuln_id / packages — transient properties for parsing pipeline
    # ------------------------------------------------------------------

    @property
    def vuln_id(self) -> str:
        # _vuln_id is always initialised by _init_transient / new_dto; avoid
        # the repeated hasattr overhead in hot ingestion loops.
        val = self._vuln_id
        if val:
            return val
        try:
            if self.finding:
                return self.finding.vulnerability_id or ""
        except Exception:
            pass
        return ""

    @vuln_id.setter
    def vuln_id(self, value: str):
        self._vuln_id = value

    @property
    def packages(self) -> list[str]:
        if hasattr(self, "_packages") and self._packages:
            return self._packages
        try:
            if self.finding and self.finding.package:
                return [self.finding.package.string_id]
        except Exception:
            pass
        return []

    @packages.setter
    def packages(self, value):
        self._packages = list(value or [])

    def __repr__(self) -> str:
        return (
            f"<Assessment id={self.id} status={self.status!r}"
            f" finding_id={self.finding_id} variant_id={self.variant_id}>"
        )

    # ==================================================================
    # Factory: create an in-memory DTO (not yet persisted)
    # ==================================================================

    @classmethod
    def new_dto(cls, vuln_id: str, packages: Optional[list[str]] = None) -> "Assessment":
        """Create a lightweight, non-persisted Assessment for the parsing pipeline.

        This replaces the former ``VulnAssessment(vuln_id, packages)`` constructor.
        """
        from .vulnerability import Vulnerability
        if isinstance(vuln_id, Vulnerability):
            vuln_id = vuln_id.id
        obj = cls()
        obj._vuln_id = vuln_id
        obj._packages = []
        obj.id = uuid.uuid4()
        obj.status = "under_investigation"
        obj.status_notes = ""
        obj.justification = ""
        obj.impact_statement = ""
        obj.responses = []
        obj.workaround = ""
        obj.timestamp = datetime.now(timezone.utc)
        for p in (packages or []):
            obj.add_package(p)
        return obj

    # ==================================================================
    # Validation / mutation helpers
    # ==================================================================

    def add_package(self, package) -> bool:
        """Add a package to the transient package list.

        *package* can be a ``'name@version'`` string or a :class:`Package` instance.
        """
        if not hasattr(self, "_packages"):
            self._packages = []
        if isinstance(package, str):
            if package not in self._packages:
                self._packages.append(package)
            return True
        try:
            from .package import Package
            if isinstance(package, Package):
                sid = package.string_id
                if sid not in self._packages:
                    self._packages.append(sid)
                return True
        except Exception:
            pass
        return False

    def set_status(self, status: str) -> bool:
        """Validate and set the assessment status (OpenVEX or CDX VEX).

        Return ``True`` if the status was accepted, ``False`` otherwise.
        """
        if status in VALID_STATUS_OPENVEX or status in VALID_STATUS_CDX_VEX:
            self.status = status
            return True
        return False

    def get_status_openvex(self) -> Optional[str]:
        if self.status in VALID_STATUS_OPENVEX:
            return self.status
        if self.status in STATUS_CDX_VEX_TO_OPENVEX:
            return STATUS_CDX_VEX_TO_OPENVEX[self.status]
        return None

    def get_status_cdx_vex(self) -> Optional[str]:
        if self.status in VALID_STATUS_CDX_VEX:
            return self.status
        if self.status in STATUS_OPENVEX_TO_CDX_VEX:
            return STATUS_OPENVEX_TO_CDX_VEX[self.status]
        return None

    def is_compatible_status(self, status: str) -> bool:
        if status == self.status:
            return True
        if status in VALID_STATUS_OPENVEX and self.status in STATUS_CDX_VEX_TO_OPENVEX:
            return STATUS_CDX_VEX_TO_OPENVEX[self.status] == status
        if status in VALID_STATUS_CDX_VEX and self.status in STATUS_OPENVEX_TO_CDX_VEX:
            return STATUS_OPENVEX_TO_CDX_VEX[self.status] == status
        return False

    def set_status_notes(self, notes: str, append: bool = False):
        if append and self.status_notes:
            if notes not in self.status_notes:
                self.status_notes = self.status_notes + "\n" + notes
        else:
            self.status_notes = notes

    def is_justification_required(self) -> bool:
        return self.status == "not_affected"

    def set_justification(self, justification: str) -> bool:
        if justification in VALID_JUSTIFICATION_OPENVEX or justification in VALID_JUSTIFICATION_CDX_VEX:
            self.justification = justification
            return True
        return False

    def get_justification_openvex(self) -> Optional[str]:
        if self.justification in VALID_JUSTIFICATION_OPENVEX:
            return self.justification
        if self.justification in JUSTIFICATION_CDX_VEX_TO_OPENVEX:
            return JUSTIFICATION_CDX_VEX_TO_OPENVEX[self.justification]
        return None

    def get_justification_cdx_vex(self) -> Optional[str]:
        if self.justification in VALID_JUSTIFICATION_CDX_VEX:
            return self.justification
        if self.justification in JUSTIFICATION_OPENVEX_TO_CDX_VEX:
            return JUSTIFICATION_OPENVEX_TO_CDX_VEX[self.justification]
        return None

    def is_compatible_justification(self, justification: str) -> bool:
        if justification == self.justification:
            return True
        if justification in VALID_JUSTIFICATION_OPENVEX and self.justification in JUSTIFICATION_CDX_VEX_TO_OPENVEX:
            return JUSTIFICATION_CDX_VEX_TO_OPENVEX[self.justification] == justification
        if justification in VALID_JUSTIFICATION_CDX_VEX and self.justification in JUSTIFICATION_OPENVEX_TO_CDX_VEX:
            return JUSTIFICATION_OPENVEX_TO_CDX_VEX[self.justification] == justification
        return False

    def set_not_affected_reason(self, reason: str, append: bool = False):
        if append and self.impact_statement:
            if reason not in self.impact_statement:
                self.impact_statement = self.impact_statement + "\n" + reason
        else:
            self.impact_statement = reason

    def add_response(self, response: str) -> bool:
        if response in RESPONSES_CDX_VEX:
            if self.responses is None:
                self.responses = []
            if response not in self.responses:
                self.responses.append(response)
            return True
        return False

    def remove_response(self, response: str) -> bool:
        if self.responses and response in self.responses:
            self.responses.remove(response)
            return True
        return False

    def set_workaround(self, workaround: str, timestamp: Optional[str] = None):
        """Set the workaround text. The timestamp argument is accepted for compatibility but not stored."""
        self.workaround = workaround

    # ==================================================================
    # Serialisation
    # ==================================================================

    def to_dict(self) -> dict:
        ts = self.timestamp
        if ts is not None:
            ts = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        return {
            "id": str(self.id),
            "source": self.source or "",
            "vuln_id": self.vuln_id,
            "packages": list(self.packages),
            "timestamp": ts,
            "last_update": ts or "",
            "status": self.status or "",
            "status_notes": self.status_notes or "",
            "justification": self.justification or "",
            "impact_statement": self.impact_statement or "",
            "responses": list(self.responses or []),
            "workaround": self.workaround or "",
        }

    @staticmethod
    def from_dict(data: dict) -> "Assessment":
        """Create a DTO from a dict representation (replaces ``VulnAssessment.from_dict``)."""
        obj = Assessment.new_dto(data.get("vuln_id", ""), data.get("packages", []))
        if "id" in data:
            try:
                obj.id = uuid.UUID(data["id"]) if not isinstance(data["id"], uuid.UUID) else data["id"]
            except (ValueError, AttributeError):
                pass
        obj.status = data.get("status", "under_investigation")
        obj.status_notes = data.get("status_notes", "")
        obj.justification = data.get("justification", "")
        obj.impact_statement = data.get("impact_statement", "")
        obj.responses = data.get("responses", [])
        obj.workaround = data.get("workaround", "")
        if "timestamp" in data and isinstance(data["timestamp"], str):
            try:
                obj.timestamp = datetime.fromisoformat(data["timestamp"])
            except (ValueError, TypeError):
                pass
        return obj

    def to_openvex_dict(self) -> Optional[dict]:
        """Return an OpenVEX statement dict, or ``None`` if the status is invalid."""
        openvex_status = self.get_status_openvex()
        if openvex_status is None:
            return None

        openvex_justif: Optional[str] = ""
        if self.justification:
            openvex_justif = self.get_justification_openvex()

        if self.status == "false_positive" and self.justification not in VALID_JUSTIFICATION_OPENVEX:
            openvex_justif = "component_not_present"

        if (openvex_status == "not_affected"
           and openvex_justif not in VALID_JUSTIFICATION_OPENVEX
           and not self.impact_statement):
            return None

        openvex_impact = self.impact_statement or ""
        if self.justification in VALID_JUSTIFICATION_CDX_VEX and not self.impact_statement:
            openvex_impact = self.justification

        ts = self.timestamp
        if ts is not None and hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        return {
            "vulnerability": {"name": self.vuln_id},
            "products": [{"@id": p} for p in self.packages],
            "timestamp": ts,
            "last_updated": ts or "",
            "status": openvex_status,
            "status_notes": self.status_notes or "",
            "justification": openvex_justif,
            "impact_statement": openvex_impact,
            "action_statement": self.workaround or "",
        }

    def to_cdx_vex_dict(self) -> Optional[dict]:
        """Return a CycloneDX VEX analysis dict, or ``None`` if the status is invalid."""
        cdx_state = self.get_status_cdx_vex()
        if cdx_state is None:
            return None

        cdx_justif: Optional[str] = ""
        if self.justification:
            cdx_justif = self.get_justification_cdx_vex()

        if self.status == "not_affected" and self.justification == "component_not_present":
            cdx_state = "false_positive"
            cdx_justif = ""

        cdx_response = list(self.responses or [])
        if self.workaround in RESPONSES_CDX_VEX:
            cdx_response.append(self.workaround)
        if len(cdx_response) < 1 and self.workaround:
            cdx_response = ["workaround_available"]

        detail = self.status_notes or ""
        if self.impact_statement and detail:
            detail += "\n" + self.impact_statement
        elif self.impact_statement:
            detail = self.impact_statement

        ts = self.timestamp
        if ts is not None and hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        return {
            "workaround": self.workaround or "",
            "analysis": {
                "state": cdx_state,
                "detail": detail,
                "justification": cdx_justif,
                "response": cdx_response,
                "firstIssued": ts,
                "lastUpdated": ts or "",
            },
        }

    def merge(self, other: "Assessment") -> bool:
        """Merge *other* into this assessment (for deduplication during parsing)."""
        if str(self.id) != str(other.id):
            return False
        if self.vuln_id != other.vuln_id:
            return False
        for p in other.packages:
            self.add_package(p)

        other_ts = other.timestamp
        self_ts = self.timestamp
        # Normalise to comparable types
        if isinstance(other_ts, str) and isinstance(self_ts, str):
            if other_ts > self_ts:
                self.timestamp = other_ts
        elif isinstance(other_ts, datetime) and isinstance(self_ts, datetime):
            if other_ts > self_ts:
                self.timestamp = other_ts

        if not self.is_compatible_status(other.status or ""):
            self.set_status(other.status or "")
        if other.status_notes:
            for note in other.status_notes.split("\n"):
                if note and (not self.impact_statement or note not in self.impact_statement):
                    self.set_status_notes(note, True)
        if not self.is_compatible_justification(other.justification or ""):
            self.set_justification(other.justification or "")
        if other.impact_statement:
            for reason in other.impact_statement.split("\n"):
                self.set_not_affected_reason(reason, True)
        for r in (other.responses or []):
            self.add_response(r)
        if other.workaround:
            self.set_workaround(other.workaround)
        return True

    # ==================================================================
    # CRUD helpers
    # ==================================================================

    @staticmethod
    def create(
        status: str,
        finding_id: Optional[uuid.UUID | str] = None,
        variant_id: Optional[uuid.UUID | str] = None,
        source: Optional[str] = None,
        simplified_status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
    ) -> "Assessment":
        """Create a new assessment, persist it and return it."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        assessment = Assessment(
            status=status,
            finding_id=finding_id,
            variant_id=variant_id,
            source=source,
            simplified_status=simplified_status,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses or [],
        )
        db.session.add(assessment)
        db.session.commit()
        return assessment

    @staticmethod
    def get_all() -> list["Assessment"]:
        """Return all assessments."""
        return list(db.session.execute(
            db.select(Assessment).order_by(Assessment.timestamp)
        ).scalars().all())

    @staticmethod
    def from_vuln_assessment(assess, finding_id=None) -> "Assessment":
        """Create or update an ``Assessment`` DB record from an Assessment DTO."""
        existing = None
        if finding_id is not None:
            existing = db.session.execute(
                db.select(Assessment).where(Assessment.finding_id == finding_id)
            ).scalar_one_or_none()

        if existing is not None:
            existing.status = assess.status or existing.status
            existing.status_notes = assess.status_notes or existing.status_notes
            existing.justification = assess.justification or existing.justification
            existing.impact_statement = assess.impact_statement or existing.impact_statement
            existing.workaround = getattr(assess, "workaround", None) or existing.workaround
            existing.responses = list(assess.responses) if assess.responses else existing.responses
            db.session.commit()
            return existing

        record = Assessment.create(
            status=assess.status or "under_investigation",
            finding_id=finding_id,
            status_notes=assess.status_notes,
            justification=assess.justification,
            impact_statement=assess.impact_statement,
            workaround=getattr(assess, "workaround", None),
            responses=list(assess.responses) if assess.responses else [],
        )
        return record

    @staticmethod
    def get_by_id(assessment_id: uuid.UUID | str) -> Optional["Assessment"]:
        """Return the assessment matching *assessment_id*, or ``None``."""
        if isinstance(assessment_id, str):
            try:
                assessment_id = uuid.UUID(assessment_id)
            except ValueError:
                return None
        return db.session.get(Assessment, assessment_id)

    @staticmethod
    def get_by_finding(finding_id: uuid.UUID | str) -> list["Assessment"]:
        """Return all assessments for the given finding."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        return list(db.session.execute(
            db.select(Assessment).where(Assessment.finding_id == finding_id)
        ).scalars().all())

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list["Assessment"]:
        """Return all assessments for the given variant."""
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return list(db.session.execute(
            db.select(Assessment).where(Assessment.variant_id == variant_id)
        ).scalars().all())

    @staticmethod
    def get_by_finding_and_variant(
        finding_id: uuid.UUID | str,
        variant_id: uuid.UUID | str,
    ) -> list["Assessment"]:
        """Return assessments matching both *finding_id* and *variant_id*."""
        if isinstance(finding_id, str):
            finding_id = uuid.UUID(finding_id)
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return list(db.session.execute(
            db.select(Assessment).where(
                Assessment.finding_id == finding_id,
                Assessment.variant_id == variant_id,
            )
        ).scalars().all())

    @staticmethod
    def get_by_vulnerability(vulnerability_id: str) -> list["Assessment"]:
        """Return all assessments whose finding links to *vulnerability_id*."""
        from .finding import Finding
        return list(db.session.execute(
            db.select(Assessment)
            .join(Finding, Assessment.finding_id == Finding.id)
            .where(Finding.vulnerability_id == vulnerability_id.upper())
            .order_by(Assessment.timestamp)
        ).scalars().all())

    @staticmethod
    def get_by_package(package_id: "uuid.UUID | str") -> list["Assessment"]:
        """Return all assessments whose finding links to *package_id*.

        *package_id* may be a UUID, UUID string, or ``'name@version'`` string.
        """
        from .finding import Finding
        if isinstance(package_id, str):
            pkg_str: str = package_id
            try:
                package_id = uuid.UUID(pkg_str)
            except ValueError:
                from .package import Package
                pkg = Package.get_by_string_id(pkg_str)
                if pkg is None:
                    return []
                package_id = pkg.id
        return list(db.session.execute(
            db.select(Assessment)
            .join(Finding, Assessment.finding_id == Finding.id)
            .where(Finding.package_id == package_id)
            .order_by(Assessment.timestamp)
        ).scalars().all())

    def update(
        self,
        status: Optional[str] = None,
        source: Optional[str] = None,
        simplified_status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
        **_kwargs,
    ) -> "Assessment":
        """Update fields in place, persist the change and return ``self``."""
        if status is not None:
            self.status = status
        if source is not None:
            self.source = source
        if simplified_status is not None:
            self.simplified_status = simplified_status
        if status_notes is not None:
            self.status_notes = status_notes
        if justification is not None:
            self.justification = justification
        if impact_statement is not None:
            self.impact_statement = impact_statement
        if workaround is not None:
            self.workaround = workaround
        if responses is not None:
            self.responses = responses
        db.session.commit()
        return self

    def delete(self) -> None:
        """Delete this assessment from the database."""
        db.session.delete(self)
        db.session.commit()
