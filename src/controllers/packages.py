# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re
import uuid

from ..models import Package, Finding, SBOMDocument, SBOMPackage, PackageDependency, Variant
from ..models.sbom_package import PackageEvidence
from ..helpers.active_scans import active_sbom_scan_ids_for_variant
from ..helpers.verbose import verbose
from ..helpers.spdx_sources import SPDXSources, SourceKey
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


def _spdx3_key(ref: str, namespaces: dict[str, str]) -> SpdxKey | None:
    """Expand SPDX 3 namespace prefixes; bare references remain document-local."""
    prefix, separator, element = ref.partition(":")
    if not separator:
        return None
    return ("", namespaces.get(prefix, f"{prefix}:") + element)


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
        # (scan_id, namespace, SPDXID) -> (document_id, string_id) for packages read in this session.
        self._spdx_refs: dict[tuple[uuid.UUID, str, str], tuple[uuid.UUID, str]] = {}
        self._spdx_documents: dict[uuid.UUID, uuid.UUID] = {}
        self._spdx_edges: list[tuple[uuid.UUID, str, str]] = []
        self._pending_spdx_edges: list[tuple[uuid.UUID, SpdxKey, SpdxKey]] = []
        self._source_provenance = SPDXSources()
        self._document_evidence: dict[uuid.UUID, dict[str, PackageEvidence]] = {}
        self._export_document_ids: set[uuid.UUID] = set()
        self._document_packages: dict[tuple, list[Package]] = {}
        self._document_aliases: dict[str, str] = {}

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
            document_ids = self._scope.active_sbom_document_ids if self._scope is not None else {
                document.id for variant in Variant.get_all()
                for scan_id in active_sbom_scan_ids_for_variant(variant.id)
                for document in SBOMDocument.get_by_scan(scan_id)
            }
            self._export_document_ids = set(document_ids)
            evidence = SBOMPackage.evidence_for_documents(document_ids)
            for pkg in Package.get_all():
                if allowed is not None and pkg.id not in allowed:
                    continue
                pkg = pkg.with_sbom_evidence(**evidence.get(pkg.id, PackageEvidence(cpe=[], purl=[], source_urls=[])))
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
        if doc is not None:
            for link in db.session.execute(
                db.select(SBOMPackage).where(SBOMPackage.sbom_document_id == doc.id)
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

    def dependency_edges(self) -> set[tuple[str, str]]:
        """Return ``(dependent, dependency)`` string IDs recorded by the preloaded documents."""
        if not self._export_document_ids:
            return set()
        exported = {package.id: string_id for string_id, package in self._cache.items() if package.id is not None}
        return {
            (exported[source], exported[target])
            for source, target in db.session.execute(
                db.select(PackageDependency.package_id, PackageDependency.dependency_id)
                .where(PackageDependency.sbom_document_id.in_(self._export_document_ids))
            )
            if source in exported and target in exported
        }

    def add_dependencies(self, references: dict[str, str], edges: set[tuple[str, str]]) -> None:
        """Persist source -> dependency references belonging to the active document."""
        document = self._current_sbom_document
        if document is None:
            return
        self._document_evidence.setdefault(document.id, {})
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
        PackageDependency.replace_for_documents(
            {document.id}, {(document.id, source, target) for source, target in pairs},
        )

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

    def add_spdx3_dependencies(self, references: dict[str, str], namespaces: dict[str, str],
                               edges: set[tuple[str, str]]) -> None:
        """Queue SPDX 3 URI references for resolution across documents of the same scan."""
        document = self._current_sbom_document
        if document is None:
            return
        self._spdx_documents[document.id] = document.scan_id
        local_namespace = str(document.id)
        for ref, string_id in references.items():
            key = _spdx3_key(ref, namespaces) or (local_namespace, ref)
            self._spdx_refs[(document.scan_id, *key)] = (document.id, string_id)
        for source, target in edges:
            if source in references and target in references:
                self._spdx_edges.append((document.id, references[source], references[target]))
                continue
            source_key = _spdx3_key(source, namespaces) or (local_namespace, source)
            target_key = _spdx3_key(target, namespaces) or (local_namespace, target)
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
        PackageDependency.replace_for_documents(set(documents), rows)

    def add_spdx_sources(self, namespace: str | None, references: dict[str, str],
                         external_documents: dict[str, str], urls: dict[str, str],
                         derivations: set[tuple[str, str]], inputs: set[tuple[str, str]]) -> None:
        """Queue SPDX 2 source/recipe provenance, including external recipe references."""
        document = self._current_sbom_document
        local_namespace = namespace or str(document.id if document else uuid.uuid4())

        def key(ref: str) -> SourceKey:
            return _spdx_key(ref, local_namespace, external_documents) or (local_namespace, ref)

        self._record_sources({key(ref): sid for ref, sid in references.items()},
                             {key(ref): url for ref, url in urls.items()},
                             {(key(derived), key(origin)) for derived, origin in derivations},
                             {(key(derived), key(origin)) for derived, origin in inputs})

    def add_spdx3_sources(self, references: dict[str, str], namespaces: dict[str, str], urls: dict[str, str],
                          derivations: set[tuple[str, str]], inputs: set[tuple[str, str]],
                          builds: set[str]) -> None:
        """Queue SPDX 3 source/build/output provenance using namespace-qualified URIs."""
        local_namespace = str(self._current_sbom_document.id if self._current_sbom_document else uuid.uuid4())

        def key(ref: str) -> SourceKey:
            return _spdx3_key(ref, namespaces) or (local_namespace, ref)

        self._record_sources({key(ref): sid for ref, sid in references.items()},
                             {key(ref): url for ref, url in urls.items()},
                             {(key(derived), key(origin)) for derived, origin in derivations},
                             {(key(derived), key(origin)) for derived, origin in inputs},
                             {key(ref) for ref in builds})

    def _record_sources(self, references: dict[SourceKey, str], urls: dict[SourceKey, str],
                        derivations: set[tuple[SourceKey, SourceKey]],
                        inputs: set[tuple[SourceKey, SourceKey]], builds: set[SourceKey] | None = None) -> None:
        document = self._current_sbom_document
        if document is not None:
            self._document_evidence.setdefault(document.id, {})
        self._source_provenance.record(document.scan_id if document else None, references, urls,
                                       derivations, inputs, builds, document.id if document else None)
        if document is None:
            self._apply_source_provenance()

    def _apply_source_provenance(self) -> None:
        for (document_id, package_id), urls in self._source_provenance.resolve().items():
            if document_id is not None:
                evidence = self._document_evidence.setdefault(document_id, {}).setdefault(
                    package_id, {"cpe": [], "purl": [], "source_urls": []},
                )
                evidence["source_urls"] = sorted(set(evidence["source_urls"]) | urls)
            else:
                package = self.get(package_id)
                if package is not None:
                    for url in sorted(urls):
                        package.add_source_url(url)

    def flush_spdx_sources(self) -> None:
        """Resolve companion documents after import; persist provenance through the scan transaction."""
        self._apply_source_provenance()
        for document_id, packages in self._document_evidence.items():
            by_id = {self.get_or_resolve_db_id(package_id): evidence for package_id, evidence in packages.items()}
            for link in SBOMPackage.get_by_document(document_id):
                evidence = by_id.get(link.package_id, {"cpe": [], "purl": [], "source_urls": []})
                link.cpe = evidence["cpe"]
                link.purl = evidence["purl"]
                link.source_urls = evidence["source_urls"]
        self._document_evidence = {}
        self._source_provenance = SPDXSources()

    def _track_document_package(self, package: Package, replaced: Package | None = None) -> None:
        doc = self._current_sbom_document
        assert doc is not None
        peers = self._document_packages.setdefault((package.name, package.supplier), [])
        if replaced is not None:
            old_id = replaced.string_id
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

    # ------------------------------------------------------------------
    # Core mutators
    # ------------------------------------------------------------------

    def add(self, package: Package) -> Package:
        """Persist a Package to the DB and keep it in the session cache."""
        if package is None:
            return
        if self._current_sbom_document is not None:
            evidence = self._document_evidence.setdefault(self._current_sbom_document.id, {}).setdefault(
                package.string_id, {"cpe": [], "purl": [], "source_urls": []},
            )
            evidence["cpe"] = sorted(set(evidence["cpe"]) | set(package.cpe or []))
            evidence["purl"] = sorted(set(evidence["purl"]) | set(package.purl or []))
            evidence["source_urls"] = sorted(set(evidence["source_urls"]) | set(package.source_urls))
            package.source_urls = []
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
                    for cpe in package.cpe or []:
                        peer.add_cpe(cpe)
                    for purl in package.purl or []:
                        peer.add_purl(purl)
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
                    peer.version = package.version
                    for cpe in package.cpe or []:
                        peer.add_cpe(cpe)
                    for purl in package.purl or []:
                        peer.add_purl(purl)
                    self._cache.pop(old_id, None)
                    self._db_id_cache.pop(old_id, None)
                    self._cache[string_id] = peer
                    self._db_id_cache[string_id] = peer.id
                    self._document_aliases[old_id] = string_id
                    return peer
                replaced = peer
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
                with db.session.begin_nested():
                    db_pkg = db.session.get(Package, self._db_id_cache[string_id])
                    if db_pkg is None:
                        raise RuntimeError(f"Cached package {string_id!r} no longer exists")
                    # Preloaded export snapshots are detached; merge identifiers into the stored row too.
                    if db_pkg is not self._cache[string_id]:
                        db_pkg.merge(package)
                    if self._current_sbom_document is not None:
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
                        source_urls=list(package.source_urls or []),
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
                if self._scope is not None:
                    evidence = SBOMPackage.evidence_for_documents(self._scope.active_sbom_document_ids)
                    pkg = pkg.with_sbom_evidence(**evidence.get(
                        pkg.id, PackageEvidence(cpe=[], purl=[], source_urls=[]),
                    ))
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
                source_urls=v.get("source_urls", []),
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
