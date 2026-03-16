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

    # ------------------------------------------------------------------
    # Core mutators
    # ------------------------------------------------------------------

    def add(self, package: Package):
        """Persist a Package to the DB and keep it in the session cache."""
        if package is None:
            return
        string_id = package.string_id  # "name@version"
        if string_id in self._cache:
            self._cache[string_id].merge(package)
        else:
            self._cache[string_id] = package

        # Write-through to DB (silently skip when no DB context)
        try:
            from ..extensions import db
            db_pkg = Package.find_or_create(
                package.name,
                package.version,
                list(package.cpe or []),
                list(package.purl or []),
                package.licences or "",
            )
            db.session.commit()
            # Keep cache in sync with DB object
            self._cache[string_id] = db_pkg
        except Exception:
            pass

    def remove(self, package_id: str) -> bool:
        """Remove a package from the session cache and the DB."""
        removed = self._cache.pop(package_id, None) is not None
        try:
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
        """Return all packages as a ``{id: dict}`` mapping, preferring the DB."""
        try:
            return {pkg.string_id: pkg.to_dict() for pkg in Package.get_all()}
        except Exception:
            return {k: v.to_dict() for k, v in self._cache.items()}

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
        """Iterate over all packages from the DB (fallback: session cache)."""
        try:
            yield from Package.get_all()
        except Exception:
            yield from self._cache.values()

    # Backward-compat alias used by some older code paths
    @property
    def packages(self) -> dict:
        return self._cache
