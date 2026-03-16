# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
import semver
from typing import Optional
from ..extensions import db, Base


class Package(Base):
    """
    Represents a software package stored in the ``packages`` DB table.

    The class is also a drop-in replacement for the old in-memory Package DTO
    so that parsers and output-writers can continue to use the same API.
    """

    __tablename__ = "packages"

    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String, nullable=True)
    version = db.Column(db.String, nullable=True)
    # TODO: Spin-off CPE and PURL into separate tables
    cpe = db.Column(db.JSON, nullable=True)
    purl = db.Column(db.JSON, nullable=True)
    licences = db.Column(db.String, nullable=True)

    sbom_packages = db.relationship("SBOMPackage", back_populates="package", cascade="all, delete-orphan")
    findings = db.relationship("Finding", back_populates="package", cascade="all, delete-orphan")

    # ------------------------------------------------------------------
    # Constructor with support for legacy arg calls
    #   Package(name, version, cpe_list, purl_list, licences)
    # ------------------------------------------------------------------

    def __init__(
        self,
        name: str = "",
        version: str = "",
        cpe: Optional[list] = None,
        purl: Optional[list] = None,
        licences: str = "",
        **kwargs,
    ):
        version = str(version).strip().split("+git")[0]

        cpes: list = list(cpe or [])
        purls: list = list(purl or [])
        # 1`Handle "vendor:package" format
        if len(name.split(":")) == 2:
            vendor, bare_name = name.split(":", 1)
            name = bare_name
            cpes.append(f"cpe:2.3:a:{vendor}:{bare_name}:{version}:*:*:*:*:*:*:*")
            purls.append(f"pkg:generic/{vendor}/{bare_name}@{version}")

        super().__init__(**kwargs)
        self.name = name
        self.version = version
        self.cpe = []
        self.purl = []
        self.licences = licences or ""
        for c in cpes:
            self.add_cpe(c)
        for p in purls:
            self.add_purl(p)

    # ------------------------------------------------------------------
    # string_id returns the human-readable "name@version" identifier
    # ------------------------------------------------------------------

    @property
    def string_id(self) -> str:
        """Return the human-readable ``'name@version'`` identifier."""
        return f"{self.name}@{self.version}"

    # TODO: Remove in-memory logic in parsers to use DB directly. The following are concerned

    def add_cpe(self, cpe: str):
        """Add a single cpe (str) identifier to the package if not already present."""
        if not cpe:
            return
        current = list(self.cpe or [])
        if cpe not in current:
            current.append(cpe)
            self.cpe = current

    def add_purl(self, purl: str):
        """Add a PURL identifier if not already present."""
        if not purl:
            return
        current = list(self.purl or [])
        if purl not in current:
            current.append(purl)
            self.purl = current

    def generate_generic_cpe(self) -> str:
        """Build a generic cpe string for the package, add it to the cpe list and return it."""
        item = f"cpe:2.3:*:*:{self.name or '*'}:{self.version or '*'}:*:*:*:*:*:*:*"
        self.add_cpe(item)
        return item

    def generate_generic_purl(self) -> str:
        """Build a generic purl string for the package, add it to the purl list and return it."""
        item = f"pkg:generic/{self.name}@{self.version}"
        self.add_purl(item)
        return item

    def merge(self, other: "Package") -> bool:
        """Merge CPE/PURL identifiers from *other* into *self* if they represent the same package."""
        if self == other:
            for c in (other.cpe or []):
                self.add_cpe(c)
            for p in (other.purl or []):
                self.add_purl(p)
            return True
        return False

    # ------------------------------------------------------------------
    # Comparison operators
    # ------------------------------------------------------------------

    def _parse_version(self):
        return semver.Version.parse(self.version, optional_minor_and_patch=True)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Package):
            return NotImplemented
        try:
            return self.name == other.name and self._parse_version() == other._parse_version()
        except Exception:
            return self.name == other.name and self.version == other.version

    def __hash__(self) -> int:
        return hash((self.name, self.version))

    def __str__(self) -> str:
        return self.string_id

    def __repr__(self) -> str:
        return f"<Package id={self.id} string_id={self.string_id!r}>"

    def __lt__(self, other) -> bool:
        if self.name != other.name:
            return self.name < other.name
        try:
            return self._parse_version() < other._parse_version()
        except Exception:
            return self.version < other.version

    def __gt__(self, other) -> bool:
        if self.name != other.name:
            return self.name > other.name
        try:
            return self._parse_version() > other._parse_version()
        except Exception:
            return self.version > other.version

    def __le__(self, other) -> bool:
        return self < other or self == other

    def __ge__(self, other) -> bool:
        return self > other or self == other

    def __ne__(self, other) -> bool:
        return not self == other

    def __contains__(self, item) -> bool:
        if isinstance(item, Package):
            return item.string_id == self.string_id
        if isinstance(item, str):
            return (
                item == self.string_id
                or item in (self.cpe or [])
                or item in (self.purl or [])
                or item in (self.licences or "")
            )
        return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "cpe": list(self.cpe or []),
            "purl": list(self.purl or []),
            "licences": self.licences or "",
        }

    @staticmethod
    def from_dict(data: dict) -> "Package":
        return Package(
            name=data["name"],
            version=data["version"],
            cpe=data.get("cpe", []),
            purl=data.get("purl", []),
            licences=data.get("licences", ""),
        )

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    @staticmethod
    def create(
        name: str,
        version: str,
        cpe: Optional[list] = None,
        purl: Optional[list] = None,
        licences: str = "",
    ) -> "Package":
        """Create a new package, persist it and return it."""
        pkg = Package(name=name, version=version, cpe=cpe or [], purl=purl or [], licences=licences)
        db.session.add(pkg)
        db.session.commit()
        return pkg

    @staticmethod
    def find_or_create(
        name: str,
        version: str,
        cpe: Optional[list] = None,
        purl: Optional[list] = None,
        licences: str = "",
    ) -> "Package":
        """Return an existing Package for (name, version) or create a new one, merging identifiers."""
        existing = db.session.execute(
            db.select(Package).where(Package.name == name, Package.version == version)
        ).scalar_one_or_none()

        if existing is None:
            existing = Package(name=name, version=version, cpe=cpe or [], purl=purl or [], licences=licences)
            db.session.add(existing)
            db.session.flush()
        else:
            changed = False
            for c in (cpe or []):
                if c not in (existing.cpe or []):
                    existing.add_cpe(c)
                    changed = True
            for p in (purl or []):
                if p not in (existing.purl or []):
                    existing.add_purl(p)
                    changed = True
            if changed:
                db.session.flush()

        return existing

    @staticmethod
    def get_by_string_id(string_id: str) -> Optional["Package"]:
        """Return a package by ``'name@version'`` string id, or ``None``."""
        if "@" not in string_id:
            return None
        name, version = string_id.split("@", 1)
        return db.session.execute(
            db.select(Package).where(Package.name == name, Package.version == version)
        ).scalar_one_or_none()

    @staticmethod
    def get_all() -> list["Package"]:
        """Return all packages ordered by name."""
        return list(db.session.execute(
            db.select(Package).order_by(Package.name)
        ).scalars().all())

    def delete(self) -> None:
        """Delete this package from the database."""
        db.session.delete(self)
        db.session.commit()
