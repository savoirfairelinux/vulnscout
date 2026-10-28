import type { DependencyDocument, DependencyEdge, DependencyPackage } from '../handlers/dependencies';
import { mergePackageVersionMetadata, packageVersionLabel } from './packageVersions';

export type DependencyDirection = 'dependencies' | 'dependents';
export type DependencyScope = {
    id: string;
    name: string;
    documents: DependencyDocument[];
    packages: Map<string, DependencyPackage>;
    outgoing: Map<string, string[]>;
    incoming: Map<string, string[]>;
    edges: DependencyEdge[];
    recorded: Set<string>;
    unresolvedEdges: number;
};

export function dependencyLinks(scope: DependencyScope, direction: DependencyDirection) {
    return direction === 'dependencies' ? scope.outgoing : scope.incoming;
}

export function buildDependencyScopes(documents: DependencyDocument[], sourceId: string): DependencyScope[] {
    const groups = new Map<string, DependencyDocument[]>();
    documents.filter(doc => sourceId === 'all' || doc.id === sourceId).forEach(doc => {
        const group = groups.get(doc.variant_id) ?? [];
        group.push(doc);
        groups.set(doc.variant_id, group);
    });
    return [...groups].map(([id, sources]) => {
        const packages = new Map<string, DependencyPackage>();
        const merge = (pkg: DependencyPackage) => {
            const previous = packages.get(pkg.id);
            packages.set(pkg.id, previous ? { ...pkg, ...mergePackageVersionMetadata(previous, pkg) } : pkg);
        };
        sources.forEach(doc => doc.packages.forEach(merge));
        const primaryIds = new Set(packages.keys());
        const endpointIds = new Set(sources.flatMap(doc => doc.edges.flatMap(edge => [edge.package_id, edge.dependency_id])));
        // Companion documents resolve endpoints, but cannot override the selected source's evidence.
        documents.filter(doc => doc.variant_id === id).forEach(doc => doc.packages.forEach(pkg => {
            if (!primaryIds.has(pkg.id) && endpointIds.has(pkg.id)) merge(pkg);
        }));
        const uniqueEdges = new Map<string, DependencyEdge>();
        const recorded = new Set(sources.filter(doc => doc.dependencies_recorded).flatMap(doc => doc.packages.map(pkg => pkg.id)));
        let unresolvedEdges = 0;
        sources.forEach(doc => doc.edges.forEach(edge => {
            if (!packages.has(edge.package_id) || !packages.has(edge.dependency_id)) {
                unresolvedEdges++;
                return;
            }
            uniqueEdges.set(JSON.stringify([edge.package_id, edge.dependency_id]), edge);
            recorded.add(edge.package_id);
            recorded.add(edge.dependency_id);
        }));
        const edges = [...uniqueEdges.values()];
        const outgoing = new Map([...packages.keys()].map(key => [key, [] as string[]]));
        const incoming = new Map([...packages.keys()].map(key => [key, [] as string[]]));
        edges.forEach(edge => {
            outgoing.get(edge.package_id)!.push(edge.dependency_id);
            incoming.get(edge.dependency_id)!.push(edge.package_id);
        });
        const compare = (left: string, right: string) =>
            packageVersionLabel(packages.get(left)!).localeCompare(packageVersionLabel(packages.get(right)!)) || left.localeCompare(right);
        outgoing.forEach(links => links.sort(compare));
        incoming.forEach(links => links.sort(compare));
        return { id, name: sources[0].variant_name, documents: sources, packages, outgoing, incoming, edges, recorded, unresolvedEdges };
    }).sort((left, right) => left.name.localeCompare(right.name));
}

// Source components of the condensed graph also cover rootless cycles.
export function dependencyRoots(scope: DependencyScope, direction: DependencyDirection): string[] {
    const links = dependencyLinks(scope, direction);
    const reverse = dependencyLinks(scope, direction === 'dependencies' ? 'dependents' : 'dependencies');
    const ids = [...scope.packages.keys()].sort((a, b) =>
        packageVersionLabel(scope.packages.get(a)!).localeCompare(packageVersionLabel(scope.packages.get(b)!)));
    const ranks = new Map(ids.map((id, index) => [id, index]));
    const compare = (a: string, b: string) => ranks.get(a)! - ranks.get(b)!;
    const visited = new Set<string>();
    const finished: string[] = [];
    for (const id of ids) {
        if (visited.has(id)) continue;
        visited.add(id);
        const stack = [{ id, next: 0 }];
        while (stack.length) {
            const current = stack[stack.length - 1];
            const children = links.get(current.id)!;
            if (current.next === children.length) {
                finished.push(current.id);
                stack.pop();
            } else {
                const child = children[current.next++];
                if (!visited.has(child)) {
                    visited.add(child);
                    stack.push({ id: child, next: 0 });
                }
            }
        }
    }
    const components = new Map<string, number>();
    const representatives: string[] = [];
    for (const id of finished.reverse()) {
        if (components.has(id)) continue;
        const component = representatives.length;
        const members: string[] = [];
        const stack = [id];
        components.set(id, component);
        while (stack.length) {
            const current = stack.pop()!;
            members.push(current);
            for (const parent of reverse.get(current)!) {
                if (!components.has(parent)) {
                    components.set(parent, component);
                    stack.push(parent);
                }
            }
        }
        representatives.push(members.sort(compare)[0]);
    }
    const hasParent = new Set<number>();
    links.forEach((children, id) => children.forEach(child => {
        if (components.get(id) !== components.get(child)) hasParent.add(components.get(child)!);
    }));
    const unlinked = (id: string) => !links.get(id)!.length && !reverse.get(id)!.length ? 1 : 0;
    return representatives.filter((_, index) => !hasParent.has(index))
        .sort((a, b) => unlinked(a) - unlinked(b) || compare(a, b));
}

export function reachablePackages(scope: DependencyScope, id: string, direction: DependencyDirection): Set<string> {
    const links = dependencyLinks(scope, direction);
    const visited = new Set([id]);
    const stack = [id];
    while (stack.length) {
        for (const child of links.get(stack.pop()!) ?? []) {
            if (!visited.has(child)) {
                visited.add(child);
                stack.push(child);
            }
        }
    }
    visited.delete(id);
    return visited;
}

export const TREE_PAGE_SIZE = 40;
export const treePathKey = (scopeId: string, path: string[]) => JSON.stringify([scopeId, ...path]);
export const treeRootKey = (scopeId: string) => JSON.stringify([scopeId, 'roots']);

export type DependencyTreeRow =
    | { kind: 'package'; key: string; id: string; parentKey?: string; depth: number; path: string[]; cycle: boolean }
    | { kind: 'more'; key: string; parentKey?: string; depth: number; limitKey: string; shown: number; total: number };

export function dependencyTreeRows(scope: DependencyScope, roots: string[], direction: DependencyDirection,
    expanded: Set<string>, limits: Map<string, number>, budget: number): { rows: DependencyTreeRow[]; hasMore: boolean } {
    const links = dependencyLinks(scope, direction);
    const stack: DependencyTreeRow[] = [];
    const pushChildren = (children: string[], path: string[], parentKey: string | undefined, limitKey: string) => {
        const shown = Math.min(children.length, limits.get(limitKey) ?? TREE_PAGE_SIZE);
        if (shown < children.length) stack.push({
            kind: 'more', key: `${limitKey}:more`, parentKey, depth: path.length, limitKey, shown, total: children.length,
        });
        for (let index = shown - 1; index >= 0; index--) {
            const id = children[index];
            const nextPath = [...path, id];
            stack.push({ kind: 'package', key: treePathKey(scope.id, nextPath), id, parentKey,
                depth: path.length, path: nextPath, cycle: path.includes(id) });
        }
    };
    pushChildren(roots, [], undefined, treeRootKey(scope.id));
    const rows: DependencyTreeRow[] = [];
    while (stack.length && rows.length < budget) {
        const row = stack.pop()!;
        rows.push(row);
        if (row.kind === 'package' && !row.cycle && expanded.has(row.key)) {
            pushChildren(links.get(row.id) ?? [], row.path, row.key, row.key);
        }
    }
    return { rows, hasMore: stack.length > 0 };
}

export function dependencyNeighborhood(scope: DependencyScope, id: string, direction: DependencyDirection,
    depth: number, limit: number) {
    const links = dependencyLinks(scope, direction);
    const distances = new Map([[id, 0]]);
    const queue = [id];
    for (let index = 0; index < queue.length; index++) {
        const current = queue[index];
        const distance = distances.get(current)!;
        if (distance >= depth) continue;
        for (const child of links.get(current) ?? []) {
            if (!distances.has(child)) {
                distances.set(child, distance + 1);
                queue.push(child);
            }
        }
    }
    const ids = queue.slice(0, limit);
    const visible = new Set(ids);
    return { ids, total: queue.length, edges: scope.edges.filter(edge => visible.has(edge.package_id) && visible.has(edge.dependency_id)) };
}
