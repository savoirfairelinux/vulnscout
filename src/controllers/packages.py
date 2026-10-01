# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re

from sqlalchemy.orm import joinedload

from ..models import Package, Finding, SBOMDocument, SBOMPackage
from ..helpers.verbose import verbose
from ..extensions import db
from ._base import to_dict_with_fallback


def _epoch_base(version: str | None) -> str | None:
    match = re.fullmatch(r"[0-9]+_([0-9].*)", version or "")
    return match.group(1) if match else None


class PackagesController:
    """
    DB-backed controller for packages.

    During an active scan session the controller keeps a write-through session
    cache so that parsers can do O(1) look-ups without hitting the DB on every
    call.  When used inside a route (read-only), simply iterate ``Package.get_all()``
    directly; the session cache may be empty.
    """

    def __init__(self, scope=None):
        self._scope = scope
        self._cache: dict[str, Package] = {}
        self._current_sbom_document: SBOMDocument | None = None
        # Fast PK lookup: string_id → DB UUID.  Avoids SELECT in
        # get_by_string_id for packages we already persisted.
        self._db_id_cache: dict = {}
        # Shared (pkg_uuid, vuln_id) → Finding cache.  Populated by
        # _persist_vuln_to_db and reused by _persist_assessment_to_db to
        # avoid redundant Finding.get_or_create SELECTs.
        self._finding_cache: dict = {}
        self._document_packages: dict[tuple, list[Package]] = {}
        self._document_aliases: dict[str, str] = {}
        self._coalesced_bare: dict[str, Package] = {}
        self._provisional_epoch_metadata: dict[str, tuple[Package, Package]] = {}

    def _preload_cache(self) -> None:
        """Bulk-load all packages from the DB into the session caches.

        Call this once when the controller is created for a read-heavy path
        (e.g. route handlers, document generation) so that subsequent
        ``get()``, ``get_db_id()``, ``get_or_resolve_db_id()`` and
        ``__contains__`` calls are pure dict lookups — zero extra SELECTs.

        Also pre-populates ``_finding_cache`` so that
        :func:`Finding.get_or_create` avoids a SELECT on the first lookup
        for every known (package, vulnerability) pair.

        When an export *scope* is set only the in-scope packages (and their
        findings) are loaded, so every view built from this controller is
        restricted to the scoped project/variant.
        """
        allowed = self._scope.package_ids if self._scope is not None else None
        try:
            for pkg in Package.get_all():
                if allowed is not None and pkg.id not in allowed:
                    continue
                sid = pkg.string_id
                self._cache[sid] = pkg
                self._db_id_cache[sid] = pkg.id
        except Exception as e:
            verbose(f"[PackagesController._preload_cache packages] {e}")
        try:
            for f in Finding.get_all():
                if allowed is not None and f.package_id not in allowed:
                    continue
                self._finding_cache[(f.package_id, f.vulnerability_id)] = f
        except Exception as e:
            verbose(f"[PackagesController._preload_cache findings] {e}")

    @property
    def current_sbom_document(self) -> SBOMDocument | None:
        return self._current_sbom_document

    @current_sbom_document.setter
    def current_sbom_document(self, doc: SBOMDocument | None) -> None:
        """Set (or clear with ``None``) the SBOM document that subsequent :meth:`add` calls belong to."""
        self._current_sbom_document = doc
        self._document_packages = {}
        self._document_aliases = {}
        self._coalesced_bare = {}
        self._provisional_epoch_metadata = {}
        if doc is not None:
            for link in db.session.execute(
                db.select(SBOMPackage).options(joinedload(SBOMPackage.package))
                .where(SBOMPackage.sbom_document_id == doc.id)
            ).scalars():
                pkg = link.package
                self._document_packages.setdefault((pkg.name, pkg.supplier), []).append(pkg)
        verbose(f"[PackagesController] Now handling SBOM document {repr(doc)}")

    # ------------------------------------------------------------------
    # Fast accessors for other controllers
    # ------------------------------------------------------------------

    def get_db_id(self, string_id: str):
        """Return the DB UUID primary key for *string_id*, or ``None``."""
        return self._db_id_cache.get(self._document_aliases.get(string_id, string_id))

    def canonical_id(self, string_id: str) -> str:
        return self._document_aliases.get(string_id, string_id)

    def get_or_resolve_db_id(self, string_id: str):
        """Return the DB UUID, falling back to a DB query only if not cached."""
        string_id = self._document_aliases.get(string_id, string_id)
        uid = self._db_id_cache.get(string_id)
        if uid is not None:
            return uid
        pkg = Package.get_by_string_id(string_id)
        if pkg is not None:
            self._db_id_cache[string_id] = pkg.id
            return pkg.id
        return None

    @staticmethod
    def _merge_metadata(target: Package, source: Package) -> None:
        for cpe in source.cpe or []:
            target.add_cpe(cpe)
        for purl in source.purl or []:
            target.add_purl(purl)
        if not target.licences:
            target.licences = source.licences or ""

    @staticmethod
    def _copy_metadata(package: Package) -> Package:
        return Package(
            package.name or "", package.version or "", list(package.cpe or []),
            list(package.purl or []), package.licences or "", supplier=package.supplier,
        )

    def _track_document_package(self, package: Package, replaced: Package | None = None) -> None:
        doc = self._current_sbom_document
        assert doc is not None
        peers = self._document_packages.setdefault((package.name, package.supplier), [])
        if replaced is not None:
            old_id = replaced.string_id
            self._provisional_epoch_metadata[old_id] = (package, self._copy_metadata(package))
            self._merge_metadata(package, replaced)
            self._coalesced_bare[old_id] = self._copy_metadata(replaced)
            link = SBOMPackage.get(doc.id, replaced.id)
            if link is not None:
                db.session.delete(link)
                db.session.flush()
            peers[:] = [peer for peer in peers if peer is not replaced]
            self._document_aliases[old_id] = package.string_id
            if (not SBOMPackage.get_by_package(replaced.id) and not replaced.findings
                    and not replaced.sbom_observations):
                self._cache.pop(old_id, None)
                self._db_id_cache.pop(old_id, None)
                db.session.delete(replaced)
        if not any(peer.id == package.id for peer in peers):
            peers.append(package)
        base = _epoch_base(package.version)
        if base is not None and sum(_epoch_base(peer.version) == base for peer in peers) > 1:
            bare_id = f"{package.name}@{base}"
            if package.supplier:
                bare_id += f"::{package.supplier}"
            self._document_aliases.pop(bare_id, None)
            bare = self._coalesced_bare.pop(bare_id, None)
            provisional = self._provisional_epoch_metadata.pop(bare_id, None)
            if provisional is not None:
                epoch, metadata = provisional
                epoch.cpe = list(metadata.cpe or [])
                epoch.purl = list(metadata.purl or [])
                epoch.licences = metadata.licences
            if bare is not None:
                restored = Package.find_or_create(
                    bare.name, bare.version, bare.cpe, bare.purl,
                    bare.licences or "", supplier=bare.supplier,
                )
                self._merge_metadata(restored, bare)
                SBOMPackage.get_or_create(doc.id, restored.id)
                peers.append(restored)
                self._cache[bare_id] = restored
                self._db_id_cache[bare_id] = restored.id

    # ------------------------------------------------------------------
    # Core mutators
    # ------------------------------------------------------------------

    def add(self, package: Package) -> Package:
        """Persist a Package to the DB and keep it in the session cache."""
        if package is None:
            return
        string_id = package.string_id  # "name@version"
        replaced = None
        if self._current_sbom_document is not None:
            peers = self._document_packages.get((package.name, package.supplier), [])
            base = _epoch_base(package.version)
            matches = [] if base is not None and any(
                _epoch_base(peer.version) == base for peer in peers
            ) else [pkg for pkg in peers if (
                (base is not None and pkg.version == base)
                or (_epoch_base(pkg.version) == package.version)
            )]
            if base is None and len(matches) != 1:
                self._document_aliases.pop(string_id, None)
            if len(matches) == 1:
                peer = matches[0]
                if base is None:
                    self._provisional_epoch_metadata.setdefault(
                        string_id, (peer, self._copy_metadata(peer)),
                    )
                    self._merge_metadata(peer, package)
                    bare = self._coalesced_bare.get(string_id)
                    if bare is None:
                        self._coalesced_bare[string_id] = package
                    else:
                        self._merge_metadata(bare, package)
                    self._document_aliases[string_id] = peer.string_id
                    return peer
                if (
                    len(peer.sbom_packages) == 1
                    and not peer.findings
                    and not peer.sbom_observations
                    and package.name is not None
                    and package.version is not None
                    and not Package.exists(package.name, package.version, package.supplier)
                ):
                    old_id = peer.string_id
                    self._coalesced_bare[old_id] = self._copy_metadata(peer)
                    peer.version = package.version
                    epoch_cpe = (package.cpe or [peer.generate_generic_cpe()])[0]
                    epoch_purl = (package.purl or [peer.generate_generic_purl()])[0]
                    self._provisional_epoch_metadata[old_id] = (peer, Package(
                        peer.name or "", peer.version or "", list(package.cpe or [epoch_cpe]),
                        list(package.purl or [epoch_purl]), package.licences or "",
                        supplier=peer.supplier,
                    ))
                    self._merge_metadata(peer, package)
                    peer.cpe = [epoch_cpe, *(cpe for cpe in peer.cpe or [] if cpe != epoch_cpe)]
                    peer.purl = [epoch_purl, *(purl for purl in peer.purl or [] if purl != epoch_purl)]
                    self._cache.pop(old_id, None)
                    self._db_id_cache.pop(old_id, None)
                    self._cache[string_id] = peer
                    self._db_id_cache[string_id] = peer.id
                    self._document_aliases[old_id] = string_id
                    return peer
                replaced = peer
        already_persisted = string_id in self._db_id_cache
        if string_id in self._cache:
            if self._current_sbom_document is not None and base is not None:
                bare_id = f"{package.name}@{base}"
                if package.supplier:
                    bare_id += f"::{package.supplier}"
                provisional = self._provisional_epoch_metadata.get(bare_id)
                if provisional is not None and provisional[0] is self._cache[string_id]:
                    self._merge_metadata(provisional[1], package)
            self._merge_metadata(self._cache[string_id], package)
        else:
            self._cache[string_id] = package

        # Write-through to DB (silently skip when no DB context).
        # Uses a SAVEPOINT so that a failure only rolls back this single
        # package instead of the whole ``batch_session()`` transaction.
        try:
            if already_persisted:
                # Package already in DB — skip the expensive find_or_create
                # SELECT.  Dirty-tracking will flush in-memory CPE/PURL
                # changes automatically.  Only handle the SBOMPackage link.
                if self._current_sbom_document is not None:
                    with db.session.begin_nested():
                        SBOMPackage.get_or_create(
                            self._current_sbom_document.id,
                            self._db_id_cache[string_id],
                        )
                    self._track_document_package(self._cache[string_id], replaced)
                return self._cache[string_id]
            else:
                with db.session.begin_nested():
                    db_pkg = Package.find_or_create(
                        package.name,
                        package.version,
                        list(package.cpe or []),
                        list(package.purl or []),
                        package.licences or "",
                        supplier=package.supplier or "",
                    )
                    # Keep caches in sync with DB object
                    self._cache[string_id] = db_pkg
                    self._db_id_cache[string_id] = db_pkg.id
                    # Link to the current SBOM document if one is active
                    if self._current_sbom_document is not None:
                        SBOMPackage.get_or_create(self._current_sbom_document.id, db_pkg.id)
                if self._current_sbom_document is not None:
                    self._track_document_package(db_pkg, replaced)
                return db_pkg
        except Exception as e:
            verbose(f"[PackagesController.add {package.string_id!r}] {e}")
            return package  # TODO: better exception handling. Simply logging it is questionnable

    def remove(self, package_id: str) -> bool:
        """Remove a package from the session cache and the DB."""
        removed = self._cache.pop(package_id, None) is not None
        try:
            with db.session.begin_nested():
                db_pkg = Package.get_by_string_id(package_id)
                if db_pkg:
                    db_pkg.delete()
                    removed = True
        except Exception as e:
            verbose(f"[PackagesController.remove {package_id!r}] {e}")
        return removed

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get(self, package_id: str) -> Package | None:
        """Return a package by ``'name@version'`` id from cache or DB."""
        package_id = self._document_aliases.get(package_id, package_id)
        if package_id in self._cache:
            return self._cache[package_id]
        try:
            pkg = Package.get_by_string_id(package_id)
            if pkg is not None and self._scope is not None and pkg.id not in self._scope.package_ids:
                return None  # out of the export scope
            if pkg:
                self._cache[package_id] = pkg
            return pkg
        except Exception as e:
            verbose(f"[PackagesController.get {package_id!r}] {e}")
            return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return all packages as a ``{id: dict}`` mapping, preferring in-memory when available."""
        if self._scope is not None:
            # Scoped export/report: only the in-scope packages are pre-loaded
            # into the in-memory cache. Never fall back to the global DB set
            # (which would leak other projects/variants when the scope is empty).
            return {sid: pkg.to_dict() for sid, pkg in self._cache.items()}
        return to_dict_with_fallback(
            self._cache, Package.get_all,
            lambda pkg: pkg.string_id, "PackagesController",
        )

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
                supplier=v.get("supplier", ""),
            )
            ctrl.add(pkg)
        return ctrl

    # ------------------------------------------------------------------
    # Container protocol
    # ------------------------------------------------------------------

    def __contains__(self, item) -> bool:
        if isinstance(item, str):
            item = self._document_aliases.get(item, item)
            if item in self._cache:
                return True
            try:
                pkg = Package.get_by_string_id(item)
                if pkg is None:
                    return False
                if self._scope is not None and pkg.id not in self._scope.package_ids:
                    return False
                return True
            except Exception as e:
                verbose(f"[PackagesController.__contains__ {item!r}] {e}")
                return False
        elif isinstance(item, Package):
            return self.__contains__(item.string_id)
        return False

    def __len__(self) -> int:
        if self._cache:
            return len(self._cache)
        try:
            return db.session.query(Package).count()
        except Exception as e:
            verbose(f"[PackagesController.__len__] {e}")
            return 0

    def __iter__(self):
        """Iterate over all packages.

        When the session cache is populated (during scan processing) it is
        used directly to avoid unnecessary DB round-trips.
        """
        if self._cache:
            yield from self._cache.values()
            return
        if self._scope is not None:
            # Scoped export: never fall back to the global package set.
            return
        try:
            yield from Package.get_all()
        except Exception as e:
            verbose(f"[PackagesController.__iter__] {e}")

    # Backward-compat alias used by some older code paths
    @property
    def packages(self) -> dict:
        return self._cache
