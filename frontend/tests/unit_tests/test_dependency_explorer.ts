import { buildDependencyScopes, dependencyNeighborhood, dependencyRoots, dependencyTreeRows,
    exclusiveDirectDependencies, reachablePackages, treePathKey } from '../../src/helpers/dependencyExplorer';
import type { DependencyDocument } from '../../src/handlers/dependencies';

function document(ids: string[], edges: [string, string][], variant = 'v1'): DependencyDocument {
    return { id: variant, source_name: `${variant}.spdx.json`, variant_id: variant, variant_name: variant,
        dependencies_recorded: true, packages: ids.map(id => ({ id, name: id, version: '1' })),
        edges: edges.map(([package_id, dependency_id]) => ({ package_id, dependency_id })) };
}

test('discovers only CURL exclusive direct dependencies, deduplicating declarations and excluding shared and transitive packages', () => {
    const doc = document(['CURL', 'A', 'B', 'C', 'D', 'other', 'transitive'], [
        ['CURL', 'A'], ['CURL', 'B'], ['CURL', 'C'], ['CURL', 'D'],
        ['other', 'A'], ['other', 'D'], ['B', 'transitive'],
    ]);
    const [scope] = buildDependencyScopes([doc, { ...doc, id: 'duplicate' }], 'all');
    expect(exclusiveDirectDependencies(scope, 'CURL').map(pkg => pkg.id)).toEqual(['B', 'C']);
    expect(exclusiveDirectDependencies(scope, 'transitive')).toEqual([]);
    expect(exclusiveDirectDependencies(scope, 'missing')).toEqual([]);
});

test('checks companion-source evidence without mixing variants or changing the visible direct dependency selection', () => {
    const doc = document(['CURL', 'B', 'C'], [['CURL', 'B'], ['CURL', 'C']]);
    const companion = { ...document(['other', 'C'], [['other', 'C']]), id: 'companion' };
    const foreign = document(['other', 'B'], [['other', 'B']], 'v2');
    const documents = [doc, companion, foreign];
    const [selected] = buildDependencyScopes(documents, doc.id);
    const evidence = buildDependencyScopes(documents, 'all').find(scope => scope.id === selected.id)!;
    expect(exclusiveDirectDependencies(selected, 'CURL', evidence).map(pkg => pkg.id)).toEqual(['B']);
    expect(selected.outgoing.get('CURL')).toEqual(['B', 'C']);
});

test('retains backend incoming evidence for dependents hidden by comparison filters', () => {
    const doc = document(['CURL', 'B', 'C'], [['CURL', 'B'], ['CURL', 'C']]);
    doc.dependent_counts = { CURL: 0, B: 1, C: 2 };
    const [scope] = buildDependencyScopes([doc], 'all');
    expect(exclusiveDirectDependencies(scope, 'CURL').map(pkg => pkg.id)).toEqual(['B']);
});

test('does not perform cascade analysis, excludes the selected package and counts dependency self edges as other dependents', () => {
    const [scope] = buildDependencyScopes([document(['CURL', 'B', 'C'], [
        ['CURL', 'CURL'], ['CURL', 'B'], ['B', 'CURL'], ['CURL', 'C'], ['C', 'C'],
    ])], 'all');
    expect(exclusiveDirectDependencies(scope, 'CURL').map(pkg => pkg.id)).toEqual(['B']);
});

test('keeps transitive paths within each variant instead of stitching unrelated edges', () => {
    const scopes = buildDependencyScopes([
        document(['app', 'lib'], [['app', 'lib']]),
        document(['lib', 'util'], [['lib', 'util']], 'v2'),
    ], 'all');
    expect([...reachablePackages(scopes[0], 'app', 'dependencies')]).toEqual(['lib']);
    expect([...reachablePackages(scopes[1], 'util', 'dependents')]).toEqual(['lib']);
});

test('finds roots for every disconnected component, including rootless cycles and isolated nodes', () => {
    const [scope] = buildDependencyScopes([document(['app', 'lib', 'a', 'b', 'leaf', 'alone', 'self'], [
        ['app', 'lib'], ['a', 'b'], ['b', 'a'], ['b', 'leaf'], ['self', 'self'],
    ])], 'all');
    const roots = dependencyRoots(scope, 'dependencies');
    expect(roots).toEqual(['a', 'app', 'self', 'alone']);
    const reachable = new Set(roots.flatMap(root => [root, ...reachablePackages(scope, root, 'dependencies')]));
    expect(reachable.size).toBe(scope.packages.size);
    const reverseRoots = dependencyRoots(scope, 'dependents');
    const reverseReachable = new Set(reverseRoots.flatMap(root => [root, ...reachablePackages(scope, root, 'dependents')]));
    expect(reverseReachable.size).toBe(scope.packages.size);
});

test('uses companion endpoints only within a variant and preserves selected-source metadata', () => {
    const main = document(['app', 'lib'], [['app', 'lib'], ['app', 'util'], ['app', 'missing']]);
    main.packages[1].source_revision = 'a'.repeat(40);
    const companion = { ...document(['lib', 'util'], []), id: 'companion' };
    companion.packages[0].source_revision = 'b'.repeat(40);
    const foreign = document(['missing'], [], 'v2');
    const [scope] = buildDependencyScopes([main, companion, foreign], 'v1');
    expect(scope.packages.get('lib')?.source_revision).toBe('a'.repeat(40));
    expect(scope.packages.has('util')).toBe(true);
    expect(scope.packages.has('missing')).toBe(false);
    expect(scope.unresolvedEdges).toBe(1);
    expect(scope.edges).toHaveLength(2);
});

test('deduplicates edges and counts unique reachable packages without counting cycle roots', () => {
    const doc = document(['app', 'lib', 'util'], [['app', 'lib'], ['app', 'util'], ['lib', 'util'], ['util', 'app']]);
    const [scope] = buildDependencyScopes([doc, { ...doc, id: 'other' }], 'all');
    expect(scope.edges).toHaveLength(4);
    expect([...reachablePackages(scope, 'app', 'dependencies')].sort()).toEqual(['lib', 'util']);
    expect([...reachablePackages(scope, 'util', 'dependents')].sort()).toEqual(['app', 'lib']);
});

test('renders a cycle as a terminal occurrence and shared packages on every valid path', () => {
    const [scope] = buildDependencyScopes([document(['app', 'lib', 'util'], [
        ['app', 'lib'], ['app', 'util'], ['lib', 'util'], ['util', 'app'],
    ])], 'all');
    const expanded = new Set([
        treePathKey('v1', ['app']), treePathKey('v1', ['app', 'lib']), treePathKey('v1', ['app', 'lib', 'util']),
    ]);
    const { rows } = dependencyTreeRows(scope, ['app'], 'dependencies', expanded, new Map(), 500);
    expect(rows.filter(row => row.kind === 'package' && row.id === 'util')).toHaveLength(2);
    expect(rows.filter(row => row.kind === 'package' && row.cycle)).toHaveLength(1);
    expect(rows).toHaveLength(5);
});

test('preserves declarations from every source while deduplicating package pairs', () => {
    const typed = document(['app', 'lib'], [['app', 'lib']]);
    typed.edges[0].declarations = [{
        relationship_type: 'dependsOn', lifecycle_scope: 'runtime',
        source_document_id: typed.id, source_name: typed.source_name,
    }];
    const legacy = { ...document(['app', 'lib'], [['app', 'lib']]), id: 'legacy', source_name: 'legacy.json' };
    const [scope] = buildDependencyScopes([typed, legacy], 'all');
    expect(scope.outgoing.get('app')).toEqual(['lib']);
    expect(scope.edges).toHaveLength(1);
    expect(scope.edges[0].declarations).toEqual([
        ...typed.edges[0].declarations,
        { relationship_type: '', lifecycle_scope: '', source_document_id: 'legacy', source_name: 'legacy.json' },
    ]);
    expect(typed.edges[0].declarations).toHaveLength(1);
    expect(legacy.edges[0].declarations).toBeUndefined();
});

test('handles deep dependency chains iteratively and bounds rendered rows without discarding data', () => {
    const ids = Array.from({ length: 3000 }, (_, index) => `pkg-${String(index).padStart(4, '0')}`);
    const [scope] = buildDependencyScopes([document(ids, ids.slice(1).map((id, index) => [ids[index], id]))], 'all');
    expect(dependencyRoots(scope, 'dependencies')).toEqual([ids[0]]);
    expect(reachablePackages(scope, ids[0], 'dependencies').size).toBe(2999);
    const expanded = new Set(ids.slice(0, 600).map((_, index) => treePathKey('v1', ids.slice(0, index + 1))));
    const first = dependencyTreeRows(scope, [ids[0]], 'dependencies', expanded, new Map(), 500);
    expect(first.rows).toHaveLength(500);
    expect(first.hasMore).toBe(true);
    const more = dependencyTreeRows(scope, [ids[0]], 'dependencies', expanded, new Map(), 1000);
    expect(more.rows).toHaveLength(601);
    expect(more.hasMore).toBe(false);
});

test('bounds diagrams explicitly while the full transitive tree stays available', () => {
    const ids = Array.from({ length: 200 }, (_, index) => `pkg-${index}`);
    const [scope] = buildDependencyScopes([document(ids, ids.slice(1).map(id => [ids[0], id]))], 'all');
    const graph = dependencyNeighborhood(scope, ids[0], 'dependencies', 1, 120);
    expect(graph.total).toBe(200);
    expect(graph.ids).toHaveLength(120);
    expect(graph.edges).toHaveLength(119);
    expect(reachablePackages(scope, ids[0], 'dependencies').size).toBe(199);
    expect(dependencyNeighborhood(scope, ids[1], 'dependents', 1, 120).ids).toEqual([ids[1], ids[0]]);
});
