# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from sqlalchemy import tuple_

from ..models import Package, Finding, SBOMDocument, SBOMPackage, PackageDependency
from ..helpers.verbose import verbose
from ..extensions import db
from ._base import to_dict_with_fallback

SpdxKey = tuple[str, str]


def _spdx_key(ref: str, namespace: str | None, external_documents: dict[str, str]) -> SpdxKey | None:
    """Qualify an SPDX 2 element reference with the namespace of the document defining it."""
    if ref.startswith("DocumentRef-"):
        document_ref, _, element = ref.partition(":")
        uri = external_documents.get(document_ref)
        return (uri, element) if uri and element else None
    return (namespace, ref) if namespace else None


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
        # (scan_id, namespace, SPDXID) -> (document_id, string_id) for packages read in this session.
        self._spdx_refs: dict[tuple[uuid.UUID, str, str], tuple[uuid.UUID, str]] = {}
        self._spdx_documents: dict[uuid.UUID, uuid.UUID] = {}
        self._spdx_edges: list[tuple[uuid.UUID, str, str]] = []
        self._pending_spdx_edges: list[tuple[uuid.UUID, SpdxKey, SpdxKey]] = []

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
        verbose(f"[PackagesController] Now handling SBOM document {repr(doc)}")

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

    def add_dependencies(self, references: dict[str, str], edges: set[tuple[str, str]]) -> None:
        """Persist source -> dependency references belonging to the active document."""
        document = self._current_sbom_document
        if document is None:
            return
        pairs: set[tuple[uuid.UUID, uuid.UUID]] = set()
        if edges:
            package_ids = set(db.session.execute(
                db.select(SBOMPackage.package_id).where(SBOMPackage.sbom_document_id == document.id)
            ).scalars())
            for source, target in edges:
                if source not in references or target not in references:
                    continue
                source_id = self.get_or_resolve_db_id(references[source])
                target_id = self.get_or_resolve_db_id(references[target])
                if source_id != target_id and source_id in package_ids and target_id in package_ids:
                    pairs.add((source_id, target_id))
        existing = {tuple(row) for row in db.session.execute(
            db.select(PackageDependency.package_id, PackageDependency.dependency_id)
            .where(PackageDependency.sbom_document_id == document.id)
        )}
        stale = existing - pairs
        added = pairs - existing
        if stale:
            db.session.execute(db.delete(PackageDependency).where(
                PackageDependency.sbom_document_id == document.id,
                tuple_(PackageDependency.package_id, PackageDependency.dependency_id).in_(stale),
            ))
        db.session.add_all(
            PackageDependency(sbom_document_id=document.id, package_id=source, dependency_id=target)
            for source, target in added
        )
        if stale or added:
            db.session.commit()

    def add_spdx_dependencies(self, namespace: str | None, references: dict[str, str],
                              external_documents: dict[str, str], edges: set[tuple[str, str]]) -> None:
        """Queue the active document's SPDX 2 edges; :meth:`flush_spdx_dependencies` persists them."""
        document = self._current_sbom_document
        if document is None:
            return
        self._spdx_documents[document.id] = document.scan_id
        if namespace:
            for ref, string_id in references.items():
                self._spdx_refs[(document.scan_id, namespace, ref)] = (document.id, string_id)
        for source, target in edges:
            if not source.startswith("DocumentRef-") and not target.startswith("DocumentRef-"):
                if source in references and target in references:
                    self._spdx_edges.append((document.id, references[source], references[target]))
                continue
            source_key = _spdx_key(source, namespace, external_documents)
            target_key = _spdx_key(target, namespace, external_documents)
            if source_key is not None and target_key is not None:
                self._pending_spdx_edges.append((document.scan_id, source_key, target_key))

    def flush_spdx_dependencies(self) -> None:
        """Replace the edges of every queued document; cross-document ones go to the dependent's document."""
        documents, self._spdx_documents = self._spdx_documents, {}
        edges, self._spdx_edges = self._spdx_edges, []
        pending, self._pending_spdx_edges = self._pending_spdx_edges, []
        if not documents:
            return
        for scan_id, source_key, target_key in pending:
            source_ref = self._spdx_refs.get((scan_id, *source_key))
            target_ref = self._spdx_refs.get((scan_id, *target_key))
            if source_ref is not None and target_ref is not None:
                edges.append((source_ref[0], source_ref[1], target_ref[1]))
        rows: set[tuple[uuid.UUID, uuid.UUID, uuid.UUID]] = set()
        for document_id, source, target in edges:
            source_id = self.get_or_resolve_db_id(source)
            target_id = self.get_or_resolve_db_id(target)
            if source_id is not None and target_id is not None and source_id != target_id:
                rows.add((document_id, source_id, target_id))
        existing = {tuple(row) for row in db.session.execute(
            db.select(PackageDependency.sbom_document_id, PackageDependency.package_id,
                      PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
            .where(SBOMDocument.scan_id.in_(set(documents.values())))
        ) if row[0] in documents}
        stale = sorted(existing - rows)
        added = rows - existing
        for start in range(0, len(stale), 500):
            db.session.execute(db.delete(PackageDependency).where(tuple_(
                PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id,
            ).in_(stale[start:start + 500])))
        db.session.add_all(
            PackageDependency(sbom_document_id=document_id, package_id=source, dependency_id=target)
            for document_id, source, target in added
        )
        if stale or added:
            db.session.commit()

    # ------------------------------------------------------------------
    # Core mutators
    # ------------------------------------------------------------------

    def add(self, package: Package) -> Package:
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
                return package
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
