# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..models.package import Package


class PackagesController:
    """
    DB-backed controller for packages.

    During an active scan session the controller keeps a write-through session
    cache so that parsers can do O(1) look-ups without hitting the DB on every
    call.  When used inside a route (read-only), simply iterate ``Package.get_all()``
    directly; the session cache may be empty.
    """

    def __init__(self):
        self._cache: dict[str, Package] = {}
        self._current_sbom_document_id = None
        # Fast PK lookup: string_id → DB UUID.  Avoids SELECT in
        # get_by_string_id for packages we already persisted.
        self._db_id_cache: dict = {}
        # Shared (pkg_uuid, vuln_id) → Finding cache.  Populated by
        # _persist_vuln_to_db and reused by _persist_assessment_to_db to
        # avoid redundant Finding.get_or_create SELECTs.
        self._finding_cache: dict = {}

    def set_sbom_document(self, doc_id) -> None:
        """Set (or clear with ``None``) the SBOM document that subsequent :meth:`add` calls belong to."""
        self._current_sbom_document_id = doc_id

    # ------------------------------------------------------------------
    # Fast accessors for other controllers
    # ------------------------------------------------------------------

    def get_db_id(self, string_id: str):
        """Return the DB UUID primary key for *string_id*, or ``None``."""
        return self._db_id_cache.get(string_id)

    def get_or_resolve_db_id(self, string_id: str):
        """Return the DB UUID, falling back to a DB query only if not cached."""
        uid = self._db_id_cache.get(string_id)
        if uid is not None:
            return uid
        pkg = Package.get_by_string_id(string_id)
        if pkg is not None:
            self._db_id_cache[string_id] = pkg.id
            return pkg.id
        return None

    # ------------------------------------------------------------------
    # Core mutators
    # ------------------------------------------------------------------

    def add(self, package: Package):
        """Persist a Package to the DB and keep it in the session cache."""
        if package is None:
            return
        string_id = package.string_id  # "name@version"
        already_persisted = string_id in self._db_id_cache
        if string_id in self._cache:
            self._cache[string_id].merge(package)
        else:
            self._cache[string_id] = package

        # Write-through to DB (silently skip when no DB context).
        # Uses a SAVEPOINT so that a failure only rolls back this single
        # package instead of the whole ``batch_session()`` transaction.
        try:
            from ..extensions import db as _db
            from ..models.sbom_package import SBOMPackage

            if already_persisted:
                # Package already in DB — skip the expensive find_or_create
                # SELECT.  Dirty-tracking will flush in-memory CPE/PURL
                # changes automatically.  Only handle the SBOMPackage link.
                if self._current_sbom_document_id is not None:
                    with _db.session.begin_nested():
                        SBOMPackage.get_or_create(
                            self._current_sbom_document_id,
                            self._db_id_cache[string_id],
                        )
            else:
                with _db.session.begin_nested():
                    db_pkg = Package.find_or_create(
                        package.name,
                        package.version,
                        list(package.cpe or []),
                        list(package.purl or []),
                        package.licences or "",
                    )
                    # Keep caches in sync with DB object
                    self._cache[string_id] = db_pkg
                    self._db_id_cache[string_id] = db_pkg.id
                    # Link to the current SBOM document if one is active
                    if self._current_sbom_document_id is not None:
                        SBOMPackage.get_or_create(self._current_sbom_document_id, db_pkg.id)
        except Exception:
            pass

    def remove(self, package_id: str) -> bool:
        """Remove a package from the session cache and the DB."""
        removed = self._cache.pop(package_id, None) is not None
        try:
            from ..extensions import db as _db
            with _db.session.begin_nested():
                db_pkg = Package.get_by_string_id(package_id)
                if db_pkg:
                    db_pkg.delete()
                    removed = True
        except Exception:
            pass
        return removed

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get(self, package_id: str) -> Package | None:
        """Return a package by ``'name@version'`` id from cache or DB."""
        if package_id in self._cache:
            return self._cache[package_id]
        try:
            pkg = Package.get_by_string_id(package_id)
            if pkg:
                self._cache[package_id] = pkg
            return pkg
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return all packages as a ``{id: dict}`` mapping, preferring in-memory when available."""
        if self._cache:
            return {k: v.to_dict() for k, v in self._cache.items()}
        try:
            return {pkg.string_id: pkg.to_dict() for pkg in Package.get_all()}
        except Exception:
            return {}

    @staticmethod
    def from_dict(data: dict) -> "PackagesController":
        """Reconstruct a controller from a serialised dict, persisting each package to the DB."""
        ctrl = PackagesController()
        for _k, v in data.items():
            pkg = Package(
                v["name"],
                v.get("version", ""),
                v.get("cpe", []),
                v.get("purl", []),
                v.get("licences", ""),
            )
            ctrl.add(pkg)
        return ctrl

    # ------------------------------------------------------------------
    # Container protocol
    # ------------------------------------------------------------------

    def __contains__(self, item) -> bool:
        if isinstance(item, str):
            if item in self._cache:
                return True
            try:
                return Package.get_by_string_id(item) is not None
            except Exception:
                return False
        elif isinstance(item, Package):
            return self.__contains__(item.string_id)
        return False

    def __len__(self) -> int:
        try:
            from ..extensions import db
            return db.session.query(Package).count()
        except Exception:
            return len(self._cache)

    def __iter__(self):
        """Iterate over all packages.

        When the session cache is populated (during scan processing) it is
        used directly to avoid unnecessary DB round-trips.
        """
        if self._cache:
            yield from self._cache.values()
            return
        try:
            yield from Package.get_all()
        except Exception:
            pass

    # Backward-compat alias used by some older code paths
    @property
    def packages(self) -> dict:
        return self._cache
