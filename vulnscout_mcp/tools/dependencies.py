"""Read-only discovery and traversal of active, variant-scoped SBOM evidence."""

from collections import deque
import json

from vulnscout_mcp.client import VulnScoutClient, VulnScoutError


def _page(items: list, offset: int, limit: int) -> dict:
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("offset must be non-negative and limit must be between 1 and 500.")
    end = offset + limit
    return {"items": items[offset:end], "total": len(items), "offset": offset, "limit": limit,
            "next_offset": end if end < len(items) else None}


def _graph(client: VulnScoutClient, variant_id: str, document_id: str | None) -> tuple:
    documents = client.get_dependency_graph(variant_id)["documents"]
    selected = [doc for doc in documents if document_id is None or doc["id"] == document_id]
    if document_id is not None and not selected:
        raise ValueError("No active SBOM document found with that ID in this variant.")
    packages: dict[str, dict] = {}
    for doc in documents:
        for package in doc["packages"]:
            entry = packages.setdefault(package["id"], {"id": package["id"], "occurrences": []})
            entry["occurrences"].append({
                "document_id": doc["id"], "source_name": doc["source_name"],
                "dependencies_recorded": doc["dependencies_recorded"], **package,
            })
    # Companion documents can supply cross-document endpoint metadata, as in the frontend.
    members = {package["id"] for doc in selected for package in doc["packages"]}
    edges: dict[tuple[str, str], set[str]] = {}
    for doc in selected:
        for edge in doc["edges"]:
            source, target = edge["package_id"], edge["dependency_id"]
            if source in packages and target in packages:
                edges.setdefault((source, target), set()).add(doc["id"])
    coverage = {
        "variant_id": variant_id, "document_id": document_id,
        "document_count": len(selected),
        "unrecorded_document_ids": sorted(doc["id"] for doc in selected if not doc["dependencies_recorded"]),
        "evidence": "SBOM declarations, not proof of runtime usage or complete dependency coverage",
    }
    return selected, packages, members, edges, coverage


def _documents_impl(client: VulnScoutClient, variant_id: str, offset: int, limit: int) -> str:
    try:
        _page([], offset, limit)
        documents, _, _, _, coverage = _graph(client, variant_id, None)
        items = [
            {key: doc[key] for key in ("id", "source_name", "variant_id", "variant_name", "dependencies_recorded")}
            | {"package_count": len(doc["packages"]), "edge_count": len(doc["edges"])}
            for doc in sorted(documents, key=lambda doc: (doc["source_name"], doc["id"]))
        ]
        return json.dumps({**coverage, **_page(items, offset, limit)}, ensure_ascii=True)
    except (VulnScoutError, ValueError) as exc:
        return f"Error: {exc}"


def _packages_impl(client: VulnScoutClient, variant_id: str, query: str, document_id: str | None,
                   offset: int, limit: int) -> str:
    try:
        _page([], offset, limit)
        _, packages, members, _, coverage = _graph(client, variant_id, document_id)
        items = []
        for package_id in sorted(members):
            occurrences = packages[package_id]["occurrences"]
            if document_id is not None:
                occurrences = [row for row in occurrences if row["document_id"] == document_id]
            if not query or any(query.casefold() in str(row.get(key) or "").casefold()
                                for row in occurrences for key in ("id", "name", "version")):
                items.append({"id": package_id, "occurrences": occurrences})
        return json.dumps({**coverage, **_page(items, offset, limit)}, ensure_ascii=True)
    except (VulnScoutError, ValueError) as exc:
        return f"Error: {exc}"


def _walk(links: dict, package_id: str, max_depth: int) -> tuple:
    """Find shortest distances and predecessors without recursively expanding paths."""
    distances = {package_id: 0}
    parents: dict[str, str] = {}
    queue = deque([package_id])
    found = []
    depth_limited = False
    while queue:
        current = queue.popleft()
        if max_depth and distances[current] >= max_depth:
            depth_limited |= any(target not in distances for target in links.get(current, {}))
            continue
        for target in sorted(links.get(current, {})):
            if target in distances:
                continue
            distances[target] = distances[current] + 1
            parents[target] = current
            found.append(target)
            queue.append(target)
    return found, distances, parents, depth_limited


def _traverse_impl(client: VulnScoutClient, variant_id: str, package_id: str, direction: str,
                   max_depth: int, document_id: str | None, offset: int, limit: int) -> str:
    try:
        _page([], offset, limit)
        if direction not in {"dependencies", "dependents"}:
            raise ValueError("direction must be dependencies or dependents.")
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative (0 means all reachable packages).")
        _, packages, members, edges, coverage = _graph(client, variant_id, document_id)
        endpoints = {endpoint for edge in edges for endpoint in edge}
        if package_id not in members | endpoints:
            raise ValueError("Package not found in the selected active SBOM graph; use its exact package ID.")
        links: dict[str, dict[str, list[str]]] = {}
        for (source, target), documents in sorted(edges.items()):
            if direction == "dependents":
                source, target = target, source
            links.setdefault(source, {})[target] = sorted(documents)
        found, distances, parents, depth_limited = _walk(links, package_id, max_depth)
        page = _page(found, offset, limit)
        items = []
        # Materialize potentially long paths only for the requested page.
        for target in page["items"]:
            path = [target]
            while path[-1] != package_id:
                path.append(parents[path[-1]])
            path.reverse()
            items.append({
                **packages[target], "distance": distances[target], "direct": distances[target] == 1,
                "path": path,
                "path_document_ids": [links[source][dest] for source, dest in zip(path, path[1:])],
            })
        return json.dumps({
            **coverage, "root": packages[package_id], "direction": direction, "max_depth": max_depth,
            "depth_limited": depth_limited, **page, "items": items,
        }, ensure_ascii=True)
    except (VulnScoutError, ValueError) as exc:
        return f"Error: {exc}"


def register_tools(server, client: VulnScoutClient) -> None:
    @server.tool()
    def list_dependency_documents(variant_id: str, offset: int = 0, limit: int = 100) -> str:
        """List active SBOM sources and dependency-recording coverage for one variant.

        Resolve project/variant names using find_variant_id; never combine boards implicitly.
        JSON result uses items/total/next_offset. Follow next_offset until null.
        Recorded with zero edges differs from an old SBOM with dependencies_recorded=false.
        Errors use the Error: convention. Read-only; no lifecycle claims are inferred.
        """
        return _documents_impl(client, variant_id, offset, limit)

    @server.tool()
    def list_dependency_packages(variant_id: str, query: str = "", document_id: str | None = None,
                                 offset: int = 0, limit: int = 100) -> str:
        """Discover SBOM packages, including isolated nodes, in one variant.

        query is a case-insensitive substring of name, version or opaque package ID.
        Returns paginated unique IDs with per-document occurrences retaining original
        version, release_version, source_revision, version_evidence and conflict flags.
        Use exact returned IDs for traversal; names alone can match several releases.
        document_id optionally restricts discovery to one active source.
        Follow next_offset until null (limit 1..500); pages are not snapshot-isolated.
        No matches or no active SBOM yields items=[]; API failures yield Error: ...
        """
        return _packages_impl(client, variant_id, query, document_id, offset, limit)

    @server.tool()
    def get_package_dependencies(variant_id: str, package_id: str, direction: str = "dependencies",
                                 max_depth: int = 1, document_id: str | None = None,
                                 offset: int = 0, limit: int = 100) -> str:
        """Trace direct/transitive SBOM dependencies or reverse dependents of an exact package ID.

        direction is dependencies (package uses library) or dependents (library's users).
        max_depth=1 returns direct neighbours; 0 traverses all reachable nodes cycle-safely.
        Root is excluded from items. distance/direct reflect the shortest observed path;
        path_document_ids attributes each hop to source documents, not runtime evidence.
        By default edges are unioned across active documents of this variant, like the UI;
        a path can combine sources. document_id restricts edges to that source while
        companion documents still resolve endpoint metadata. No cross-variant traversal.
        Follow next_offset until null; depth_limited flags omitted deeper relationships.
        Missing relationships/unrecorded documents cannot prove absence or runtime usage.
        """
        return _traverse_impl(client, variant_id, package_id, direction, max_depth, document_id, offset, limit)
