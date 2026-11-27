# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import Flask
from flask.typing import ResponseReturnValue
from sqlalchemy import case, func

from ..extensions import db
from ..models import Finding, Observation, Package, Scan
from ..models.sbom_package import SBOMPackage, PackageEvidence
from ._scan_queries import _package_rows
from ._evidence_scope import package_evidence, resolve_evidence_scope


def _exact_package_ids(string_id: str) -> set[uuid.UUID]:
    # Package names and versions can themselves contain identifier separators.
    names = {string_id[:offset] for offset, char in enumerate(string_id) if char == "@"}
    if not names:
        return set()
    name_matches = [Package.name.in_(names)]
    if "None" in names:
        name_matches.append(Package.name.is_(None))
    supplier_suffix = case((Package.supplier != "", "::" + Package.supplier), else_="")
    identifier = func.coalesce(Package.name, "None") + "@" + func.coalesce(Package.version, "None") + supplier_suffix
    return set(db.session.scalars(db.select(Package.id).where(
        db.or_(*name_matches), identifier == string_id,
    )))


def _historical_package_links(
    keys: set[tuple[uuid.UUID, uuid.UUID]],
) -> dict[tuple[uuid.UUID, uuid.UUID], tuple[set[str], set[str]]]:
    links: dict[tuple[uuid.UUID, uuid.UUID], tuple[set[str], set[str]]] = {}
    if keys:
        rows = db.session.execute(
            db.select(Finding.package_id, Scan.variant_id, Finding.id, Finding.vulnerability_id)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(
                Finding.package_id.in_({pid for pid, _ in keys}),
                Scan.variant_id.in_({vid for _, vid in keys}),
                Scan.in_progress.is_(False),
            )
            .distinct()
        )
        for package_id, variant_id, finding_id, vuln_id in rows:
            key = (package_id, variant_id)
            if key in keys:
                findings, vulnerabilities = links.setdefault(key, (set(), set()))
                findings.add(str(finding_id))
                vulnerabilities.add(vuln_id)
    return links


def init_app(app: Flask) -> None:

    @app.route('/api/packages')
    def index_pkg() -> ResponseReturnValue:
        """List packages with optional project/variant comparison filters.

        Supports single-variant, project-wide, and multi-variant modes,
        including union/intersection/difference operations.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        query compare_variant_id uuid optional Compare against a second variant ID.
        query variant_ids string optional Comma-separated list of variant IDs.
        query operation string optional Comparison mode such as difference, intersection, or union.
        query format string optional Response format such as list or dict.
        query package_id string optional Filter by the package string ID.
        query include_source_files boolean optional Include parsed source file and build details.
        query include_outdated boolean optional Include superseded package evidence within the selected scope.
        query outdated_only boolean optional Return only superseded package evidence.
        response 200 PackageCollection Filtered package collection; an array by default, or a map with format=dict.
        response 400 Error Invalid identifiers or evidence scope.
        """
        from flask import request
        outdated_only = request.args.get('outdated_only', '').lower() in ('1', 'true', 'yes')
        if outdated_only and not any(request.args.get(key) for key in ("variant_id", "project_id", "variant_ids")):
            return {"error": "A variant or project scope is required for outdated packages"}, 400
        scope, err = resolve_evidence_scope(
            request.args, historical=True if outdated_only else None, allow_unscoped_cross_project=True,
        )
        if scope is None:
            return err if err is not None else ({"error": "Internal error"}, 500)
        package_filter = request.args.get('package_id')
        evidence = package_evidence(scope, None if package_filter is None else _exact_package_ids(package_filter))
        include_source_files = request.args.get('include_source_files', '').lower() in ('1', 'true', 'yes')
        pkg_lookup = _package_rows(evidence.ids) if evidence.ids else {}
        # Current package rows group active variants; historical-only memberships stay
        # separate so drill-down can select the exact variant even for repeated names.
        documents: dict[tuple[uuid.UUID, uuid.UUID | None], set[uuid.UUID]] = {}
        variants: dict[tuple[uuid.UUID, uuid.UUID | None], set[uuid.UUID]] = {}
        sources: dict[tuple[uuid.UUID, uuid.UUID | None], set[str]] = {}
        names: dict[tuple[uuid.UUID, uuid.UUID | None], set[str]] = {}
        contributors = set(scope.contributing_variants)
        for pid, doc, vid, scan, fmt, source in evidence.documents:
            if pid not in pkg_lookup or vid not in contributors:
                continue
            outdated = pid not in evidence.active_by_variant[vid]
            if outdated_only and not outdated:
                continue
            if not outdated and scan not in scope.active_sboms_by_variant[vid]:
                continue
            key = (pid, vid if outdated else None)
            documents.setdefault(key, set()).add(doc)
            variants.setdefault(key, set()).add(vid)
            if fmt:
                sources.setdefault(key, set()).add(fmt)
            if source:
                names.setdefault(key, set()).add(source)

        active_documents = set().union(*(docs for (_, vid), docs in documents.items() if vid is None))
        active_evidence = SBOMPackage.evidence_for_documents(
            active_documents, include_source_files=include_source_files, package_ids=set(pkg_lookup),
        )
        historical_links = _historical_package_links({(pid, vid) for pid, vid in documents if vid is not None})
        result = []
        for key in documents:
            pid, outdated_vid = key
            package = pkg_lookup[pid]
            snapshot = package.with_sbom_evidence(**active_evidence.get(
                pid, PackageEvidence(cpe=[], purl=[], source_urls=[]),
            ) if outdated_vid is None else PackageEvidence(cpe=[], purl=[], source_urls=[]))
            # The snapshot constructor normalizes missing values to empty strings.
            if package.name is None:
                snapshot.name = None
            if package.version is None:
                snapshot.version = None
            item = snapshot.to_dict()
            item.update({
                "variants": sorted({scope.variants[vid] for vid in variants[key]}),
                "inventory_variant_ids": sorted(str(vid) for vid in variants[key]),
                "sources": sorted(sources.get(key, set())),
                "sbom_documents": sorted(names.get(key, set())),
                "outdated": outdated_vid is not None,
            })
            if outdated_vid is not None:
                item["variant_id"] = str(outdated_vid)
                finding_ids, vulnerability_ids = historical_links.get((pid, outdated_vid), (set(), set()))
                item["finding_ids"] = sorted(finding_ids)
                item["vulnerability_ids"] = sorted(vulnerability_ids)
            if include_source_files:
                item["source_files"] = snapshot.source_files
            result.append(item)
        result.sort(key=lambda item: (
            item["name"] is not None, item["name"] or "", item["version"] is not None, item["version"] or "",
            item["outdated"], item["variants"],
        ))

        if request.args.get('format', 'list') == "dict":
            dict_result = {}
            for item in result:
                dict_key = f"{item['name']}@{item['version']}"
                if item["outdated"]:
                    dict_key += "@" + item["variant_id"]
                dict_result[dict_key] = item
            return dict_result
        return result
