import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBox, faChevronDown, faChevronRight, faDiagramProject, faMagnifyingGlass, faRotateRight } from '@fortawesome/free-solid-svg-icons';
import { ReactFlow, Background, Controls, MarkerType, Position } from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';
import dagre from 'dagre';
import '@xyflow/react/dist/style.css';
import type { DependencyDocument, DependencyPackage } from '../handlers/dependencies';
import { packageVersionLabel, versionEvidenceTitle } from '../helpers/packageVersions';
import { buildDependencyScopes, dependencyLinks, dependencyNeighborhood, dependencyRoots, dependencyTreeRows,
    reachablePackages, TREE_PAGE_SIZE, treePathKey } from '../helpers/dependencyExplorer';
import type { DependencyDirection, DependencyScope, DependencyTreeRow } from '../helpers/dependencyExplorer';

type Props = {
    documents: DependencyDocument[];
    focusedPackageId?: string;
    loading?: boolean;
    error?: string;
    onRetry?: () => void;
};
type Selection = { id: string; variantId: string; path?: string[]; direction?: DependencyDirection };
const buttonClass = 'rounded-md border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-600 dark:border-neutral-600 dark:hover:bg-neutral-700 disabled:cursor-not-allowed disabled:opacity-40';
const mutedClass = 'text-gray-500 dark:text-neutral-400';

function PackageLabel({ pkg }: Readonly<{ pkg: DependencyPackage }>) {
    return <span title={versionEvidenceTitle(pkg)} className="min-w-0 break-words [overflow-wrap:anywhere]">{packageVersionLabel(pkg)}</span>;
}

function ExplorerTree({ scope, direction, rootId, selected, onSelect }: Readonly<{
    scope: DependencyScope; direction: DependencyDirection; rootId?: string; selected?: Selection;
    onSelect: (selection: Selection) => void;
}>) {
    const roots = useMemo(() => rootId ? [rootId] : dependencyRoots(scope, direction), [scope, direction, rootId]);
    const [expanded, setExpanded] = useState(() => new Set(rootId ? [treePathKey(scope.id, [rootId])] : []));
    const [limits, setLimits] = useState(new Map<string, number>());
    const [budget, setBudget] = useState(500);
    const [activeKey, setActiveKey] = useState('');
    const elements = useRef(new Map<string, HTMLDivElement>());
    const pendingFocus = useRef<number>();
    const links = dependencyLinks(scope, direction);
    const reverse = dependencyLinks(scope, direction === 'dependencies' ? 'dependents' : 'dependencies');
    const { rows, hasMore } = useMemo(() =>
        dependencyTreeRows(scope, roots, direction, expanded, limits, budget), [scope, roots, direction, expanded, limits, budget]);
    const activeExists = rows.some(row => row.key === activeKey);
    const toggle = (key: string) => setExpanded(previous => {
        const next = new Set(previous);
        if (!next.delete(key)) next.add(key);
        return next;
    });
    const loadMore = (row: Extract<DependencyTreeRow, { kind: 'more' }>) => {
        pendingFocus.current = rows.findIndex(item => item.key === row.key);
        setLimits(previous => new Map(previous).set(row.limitKey, row.shown + TREE_PAGE_SIZE));
    };
    useEffect(() => {
        if (pendingFocus.current === undefined) return;
        const row = rows[pendingFocus.current];
        if (row) elements.current.get(row.key)?.focus();
        pendingFocus.current = undefined;
    }, [rows]);
    function handleKey(event: KeyboardEvent<HTMLDivElement>, row: DependencyTreeRow, index: number) {
        const focus = (key?: string) => { if (key) elements.current.get(key)?.focus(); };
        switch (event.key) {
            case 'ArrowDown': focus(rows[Math.min(rows.length - 1, index + 1)]?.key); break;
            case 'ArrowUp': focus(rows[Math.max(0, index - 1)]?.key); break;
            case 'Home': focus(rows[0]?.key); break;
            case 'End': focus(rows[rows.length - 1]?.key); break;
            case 'ArrowRight':
                if (row.kind === 'package' && !row.cycle && links.get(row.id)?.length) {
                    if (!expanded.has(row.key)) toggle(row.key);
                    else focus(rows[index + 1]?.key);
                }
                break;
            case 'ArrowLeft':
                if (expanded.has(row.key)) toggle(row.key);
                else focus(row.parentKey);
                break;
            case 'Enter':
            case ' ':
                if (row.kind === 'more') loadMore(row);
                else onSelect({ id: row.id, variantId: scope.id, path: row.path, direction });
                break;
            default: return;
        }
        event.preventDefault();
    }
    return <section aria-label={`Dependency tree for ${scope.name}`} className="mb-4">
        <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-gray-200 bg-gray-50 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800">
            <span className="h-2 w-2 rounded-full bg-cyan-600" aria-hidden="true" />
            <h3 className="font-semibold">{scope.name}</h3>
            <span className={mutedClass}>{scope.packages.size} packages</span>
            <button type="button" className={`ml-auto text-xs underline ${mutedClass}`} onClick={() => setExpanded(new Set())}>Collapse all</button>
        </div>
        <div role="tree" aria-label={`${scope.name}: ${direction === 'dependencies' ? 'Depends on' : 'Required by'}`}>
            {rows.map((row, index) => {
                const pkg = row.kind === 'package' ? scope.packages.get(row.id)! : undefined;
                const childCount = row.kind === 'package' ? links.get(row.id)?.length ?? 0 : 0;
                const expandable = row.kind === 'package' && childCount > 0 && !row.cycle;
                const isSelected = row.kind === 'package' && selected?.id === row.id && selected.variantId === scope.id
                    && (selected.path ? treePathKey(scope.id, selected.path) === row.key : row.depth === 0);
                const label = pkg ? packageVersionLabel(pkg) : `Show more packages (${row.kind === 'more' ? row.shown : 0} shown)`;
                return <div key={row.key} ref={element => { if (element) elements.current.set(row.key, element); else elements.current.delete(row.key); }}
                    role="treeitem" aria-level={row.depth + 1} aria-label={label}
                    aria-expanded={expandable ? expanded.has(row.key) : undefined}
                    aria-selected={row.kind === 'package' ? isSelected : undefined}
                    tabIndex={activeKey === row.key || (!activeExists && index === 0) ? 0 : -1}
                    onFocus={() => setActiveKey(row.key)} onKeyDown={event => handleKey(event, row, index)}
                    onClick={() => { elements.current.get(row.key)?.focus(); if (row.kind === 'more') loadMore(row); else onSelect({ id: row.id, variantId: scope.id, path: row.path, direction }); }}
                    style={{ paddingLeft: 12 + row.depth * 22 }}
                    className={`flex min-h-11 cursor-pointer items-center gap-2 border-b border-gray-100 py-2 pr-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-600 dark:border-neutral-800 ${isSelected ? 'bg-cyan-50 dark:bg-cyan-950' : 'hover:bg-gray-50 dark:hover:bg-neutral-800'}`}>
                    {row.kind === 'more' ? <span className="text-cyan-700 dark:text-cyan-300">Show {Math.min(TREE_PAGE_SIZE, row.total - row.shown)} more ({row.shown} of {row.total})</span> : <>
                        <button type="button" tabIndex={-1} disabled={!expandable}
                            aria-label={`${expanded.has(row.key) ? 'Collapse' : 'Expand'} ${label}`}
                            className="flex h-6 w-6 shrink-0 items-center justify-center rounded hover:bg-gray-200 disabled:invisible dark:hover:bg-neutral-600"
                            onClick={event => { event.stopPropagation(); toggle(row.key); elements.current.get(row.key)?.focus(); }}>
                            <FontAwesomeIcon icon={expanded.has(row.key) ? faChevronDown : faChevronRight} className="text-xs" />
                        </button>
                        <FontAwesomeIcon icon={faBox} className="shrink-0 text-cyan-700 dark:text-cyan-400" />
                        {pkg && <PackageLabel pkg={pkg} />}
                        {row.cycle && <span className="shrink-0 rounded bg-amber-100 px-1.5 text-xs text-amber-900" title="Already in this path. Expansion stops here to avoid an infinite loop.">Cycle</span>}
                        {!row.cycle && (reverse.get(row.id)?.length ?? 0) > 1 && <span className={`shrink-0 text-xs ${mutedClass}`} title="This package appears under more than one parent.">Shared</span>}
                        {!childCount && !(reverse.get(row.id)?.length) && <span className={`shrink-0 text-xs ${mutedClass}`}>Unlinked</span>}
                        <span className={`ml-auto shrink-0 tabular-nums ${mutedClass}`} title={`${childCount} direct ${direction}`}>{childCount || ''}</span>
                    </>}
                </div>;
            })}
        </div>
        {hasMore && <div className="p-3">
            <p className={`mb-2 text-xs ${mutedClass}`}>Showing the first {budget} expanded rows. Collapse a branch or load more to continue.</p>
            <button type="button" className={buttonClass} onClick={() => setBudget(previous => previous + 500)}>Show 500 more tree rows</button>
        </div>}
    </section>;
}

function NeighborhoodGraph({ scope, selection, direction, onSelect }: Readonly<{
    scope: DependencyScope; selection: Selection; direction: DependencyDirection; onSelect: (selection: Selection) => void;
}>) {
    const [depth, setDepth] = useState(1);
    const graph = useMemo(() => {
        const neighborhood = dependencyNeighborhood(scope, selection.id, direction, depth, 120);
        const layout = new dagre.graphlib.Graph();
        layout.setGraph({ rankdir: 'LR', nodesep: 24, ranksep: 80 });
        layout.setDefaultEdgeLabel(() => ({}));
        neighborhood.ids.forEach(id => layout.setNode(id, { width: 220, height: 66 }));
        neighborhood.edges.forEach(edge => layout.setEdge(edge.package_id, edge.dependency_id));
        dagre.layout(layout);
        const nodes: Node[] = neighborhood.ids.map(id => {
            const position = layout.node(id);
            return { id, position: { x: position.x - 110, y: position.y - 33 },
                data: { label: packageVersionLabel(scope.packages.get(id)!) },
                sourcePosition: Position.Right, targetPosition: Position.Left,
                style: { width: 220, minHeight: 66, overflowWrap: 'anywhere', color: '#111827',
                    background: id === selection.id ? '#cffafe' : '#f8fafc', borderColor: id === selection.id ? '#0891b2' : '#94a3b8' } };
        });
        const edges: Edge[] = neighborhood.edges.map(edge => ({
            id: JSON.stringify([edge.package_id, edge.dependency_id]), source: edge.package_id, target: edge.dependency_id,
            markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: '#64748b' },
        }));
        return { nodes, edges, total: neighborhood.total };
    }, [scope, selection.id, direction, depth]);
    return <div className="flex h-full min-h-[420px] flex-col">
        <div className="flex flex-wrap items-center gap-3 p-3 text-sm">
            <span className="font-semibold">Variant: {scope.name}</span>
            <label>Depth <select aria-label="Graph depth" value={depth} onChange={event => setDepth(Number(event.target.value))}
                className="rounded border bg-white p-1 dark:border-neutral-600 dark:bg-neutral-800">
                {[1, 2, 3].map(value => <option key={value} value={value}>{value} {value === 1 ? 'level' : 'levels'}</option>)}
            </select></label>
            <span className={mutedClass}>Arrows mean “depends on”. Select a node to explore its neighborhood.</span>
            <span className={mutedClass}>{graph.nodes.length} of {graph.total} packages within {depth} {depth === 1 ? 'level' : 'levels'}</span>
        </div>
        {graph.total > graph.nodes.length && <p role="status" className="px-3 pb-2 text-sm text-amber-700 dark:text-amber-300">Diagram limited to 120 packages for readability. Every branch remains available in Tree view.</p>}
        <div className="min-h-[360px] flex-1" aria-label="Dependency diagram">
            <ReactFlow key={`${selection.id}:${direction}:${depth}`} nodes={graph.nodes} edges={graph.edges} fitView
                nodesDraggable={false} onlyRenderVisibleElements minZoom={0.05} maxZoom={1.5}
                style={{ '--xy-controls-button-background-color': '#f8fafc', '--xy-controls-button-color': '#111827',
                    '--xy-controls-button-border-color': '#94a3b8' } as CSSProperties}
                onNodeClick={(_, node) => onSelect({ id: node.id, variantId: scope.id })}>
                <Background /><Controls showInteractive={false} />
            </ReactFlow>
        </div>
    </div>;
}

function PackageDetails({ scope, selection, onExplore }: Readonly<{
    scope: DependencyScope; selection: Selection; onExplore: (id: string, variantId: string, direction: DependencyDirection) => void;
}>) {
    const { id } = selection;
    const pkg = scope.packages.get(id)!;
    const counts = useMemo(() => (['dependencies', 'dependents'] as const).map(direction => {
        const direct = new Set(dependencyLinks(scope, direction).get(id) ?? []);
        direct.delete(id);
        const reachable = reachablePackages(scope, id, direction);
        return { direction, direct: direct.size, transitive: [...reachable].filter(key => !direct.has(key)).length };
    }), [scope, id]);
    const sources = scope.documents.filter(doc => doc.packages.some(item => item.id === id)
        || doc.edges.some(edge => edge.package_id === id || edge.dependency_id === id));
    return <div className="space-y-5">
        <div><p className={`mb-2 text-xs font-semibold uppercase tracking-wide ${mutedClass}`}>Package details</p>
            <h2 className="text-lg font-semibold"><PackageLabel pkg={pkg} /></h2>
            <p className={`mt-1 text-sm ${mutedClass}`}>Variant: {scope.name}</p>
        </div>
        {!scope.recorded.has(id) && <p role="status" className="rounded bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">Dependencies not recorded. Re-import the SBOM before interpreting missing relationships.</p>}
        {selection.path && selection.path.length > 1 && <div>
            <h3 className="mb-2 text-sm font-semibold">Selected path</h3>
            <p className={`mb-2 text-xs ${mutedClass}`}>{selection.direction === 'dependents' ? 'Each next package requires the previous one.' : 'Each package depends on the next one.'}</p>
            <ol aria-label="Selected dependency path" className="space-y-1 border-l-2 border-cyan-600 pl-3">
                {selection.path.map((pathId, index) => <li key={`${index}:${pathId}`}>
                    <button type="button" className="text-left text-xs text-cyan-700 underline dark:text-cyan-300"
                        onClick={() => onExplore(pathId, scope.id, selection.direction ?? 'dependencies')}>
                        <PackageLabel pkg={scope.packages.get(pathId)!} />
                    </button>
                </li>)}
            </ol>
        </div>}
        <div className="space-y-2">
            {counts.map(({ direction, direct, transitive }) => <button key={direction} type="button"
                onClick={() => onExplore(id, scope.id, direction)}
                className="flex w-full items-center justify-between rounded-lg border border-gray-200 p-3 text-left hover:border-cyan-600 dark:border-neutral-700">
                <span><span className="block text-sm font-semibold">{direction === 'dependencies' ? 'Explore dependencies' : 'Trace dependents'}</span>
                    <span className={`text-xs ${mutedClass}`}>{direct} direct · {transitive} transitive only</span></span>
                <FontAwesomeIcon icon={faChevronRight} className="text-xs" />
            </button>)}
        </div>
        <div><h3 className="mb-2 text-sm font-semibold">SBOM evidence</h3>
            <ul className={`space-y-2 text-sm ${mutedClass}`}>{sources.map(source => <li key={source.id} className="break-all">
                {source.source_name}<span className="block text-xs">{source.dependencies_recorded ? 'Dependencies recorded' : 'Dependencies not recorded'}</span>
            </li>)}</ul>
        </div>
        {versionEvidenceTitle(pkg) && <div><h3 className="mb-2 text-sm font-semibold">Version evidence</h3>
            <p className={`whitespace-pre-line break-all text-xs ${mutedClass}`}>{versionEvidenceTitle(pkg)}</p></div>}
        <p className={`text-xs ${mutedClass}`}>Counts describe unique packages in this variant and source selection. A shared package can appear on several paths. SBOM relationships do not prove runtime use.</p>
    </div>;
}

export default function DependencyExplorer({ documents, loading = false, error = '', onRetry,
    focusedPackageId }: Readonly<Props>) {
    const [documentId, setDocumentId] = useState('all');
    const sourceId = documents.some(doc => doc.id === documentId) ? documentId : 'all';
    const allScopes = useMemo(() => buildDependencyScopes(documents, sourceId), [documents, sourceId]);
    const [hiddenVariants, setHiddenVariants] = useState(new Set<string>());
    const scopes = useMemo(() => allScopes.filter(scope => !hiddenVariants.has(scope.id)), [allScopes, hiddenVariants]);
    const [direction, setDirection] = useState<DependencyDirection>('dependencies');
    const [mode, setMode] = useState<'tree' | 'graph'>('tree');
    const [query, setQuery] = useState('');
    const [searchLimit, setSearchLimit] = useState(TREE_PAGE_SIZE);
    const [rootId, setRootId] = useState(focusedPackageId);
    const [selection, setSelection] = useState<(Selection & { rootId?: string })>();
    useEffect(() => {
        setRootId(focusedPackageId);
        setSelection(undefined);
        setQuery('');
        setMode('tree');
    }, [focusedPackageId]);
    const contextualSelection = selection?.rootId === rootId ? selection : undefined;
    const selectedScope = scopes.find(scope => scope.id === contextualSelection?.variantId && scope.packages.has(contextualSelection.id))
        ?? scopes.find(scope => rootId && scope.packages.has(rootId));
    const selected = selectedScope && contextualSelection && selectedScope.id === contextualSelection.variantId
        && selectedScope.packages.has(contextualSelection.id) ? contextualSelection
        : selectedScope && rootId ? { id: rootId, variantId: selectedScope.id } : undefined;
    const viewMode = selected ? mode : 'tree';
    const rootPackage = rootId ? scopes.find(scope => scope.packages.has(rootId))?.packages.get(rootId) : undefined;
    const packageCount = useMemo(() => new Set(scopes.flatMap(scope => [...scope.packages.keys()])).size, [scopes]);
    const relationshipCount = scopes.reduce((count, scope) => count + scope.edges.length, 0);
    const rootExists = !rootId || scopes.some(scope => scope.packages.has(rootId));
    const searchResults = useMemo(() => {
        const terms = query.toLocaleLowerCase().trim().split(/\s+/);
        if (!query.trim()) return [];
        return scopes.flatMap(scope => [...scope.packages.values()].filter(pkg => {
            const text = `${packageVersionLabel(pkg)} ${pkg.id} ${pkg.source_revision ?? ''} ${versionEvidenceTitle(pkg)}`.toLocaleLowerCase();
            return terms.every(term => text.includes(term));
        }).map(pkg => ({ scope, pkg }))).sort((a, b) => packageVersionLabel(a.pkg).localeCompare(packageVersionLabel(b.pkg)));
    }, [scopes, query]);
    function explore(id: string, variantId: string, nextDirection: DependencyDirection) {
        setSelection({ id, variantId, rootId: id });
        setDirection(nextDirection);
        setQuery('');
        setMode('tree');
        setRootId(id);
    }
    function overview() {
        setRootId(undefined);
        setSelection(undefined);
        setQuery('');
        setMode('tree');
    }
    return <section aria-label="Dependency explorer" className="flex h-full min-h-0 flex-col text-gray-900 dark:text-neutral-100">
        <header className="mb-4 flex flex-wrap items-start justify-between gap-4">
            <div><h2 className="flex items-center gap-2 text-xl font-semibold"><FontAwesomeIcon icon={faDiagramProject} className="text-cyan-700 dark:text-cyan-400" />Explore SBOM relationships</h2>
                <p className={`mt-1 text-sm ${mutedClass}`}>Find what a package needs and what brings it in, without leaving the SBOM.</p>
            </div>
            <label className="flex min-w-0 max-w-full items-center gap-2 text-sm">SBOM source
                <select aria-label="SBOM source" value={sourceId} className="min-w-0 max-w-72 rounded-md border border-gray-300 bg-white px-2 py-2 dark:border-neutral-600 dark:bg-neutral-800"
                    onChange={event => { setDocumentId(event.target.value); setSelection(undefined); overview(); }}>
                    <option value="all">All SBOM sources</option>
                    {documents.map(doc => <option key={doc.id} value={doc.id}>{doc.variant_name}: {doc.source_name}</option>)}
                </select>
            </label>
        </header>
        {loading ? <p role="status">Loading dependency tree...</p> : error ? <div role="alert">{error} <button type="button" onClick={onRetry} className={buttonClass} aria-label="Retry loading dependencies"><FontAwesomeIcon icon={faRotateRight} /> Retry</button></div>
            : !allScopes.some(scope => scope.packages.size > 0) ? <p>No packages in this SBOM scope.</p> : <>
                <fieldset className="mb-3 flex flex-wrap items-center gap-3 text-sm">
                    <legend className="mb-1 font-semibold">Variants</legend>
                    {allScopes.map(scope => <label key={scope.id} className="flex items-center gap-2 rounded-md border border-gray-200 px-3 py-2 dark:border-neutral-700">
                        <input type="checkbox" checked={!hiddenVariants.has(scope.id)} onChange={() => setHiddenVariants(previous => {
                            const next = new Set(previous);
                            if (!next.delete(scope.id)) next.add(scope.id);
                            return next;
                        })} />
                        <span>{scope.name}</span>
                        {rootId && scope.packages.has(rootId) && <span className={`text-xs ${mutedClass}`}>
                            {scope.recorded.has(rootId)
                                ? `Deps: ${scope.outgoing.get(rootId)?.length ?? 0} / Req by: ${scope.incoming.get(rootId)?.length ?? 0}`
                                : 'Not recorded'}
                        </span>}
                    </label>)}
                </fieldset>
                <div className={`mb-3 flex flex-wrap gap-x-5 gap-y-1 text-sm ${mutedClass}`} aria-label="Scope summary">
                    <span><strong className="text-gray-900 dark:text-neutral-100">{packageCount.toLocaleString()}</strong> packages</span>
                    <span><strong className="text-gray-900 dark:text-neutral-100">{relationshipCount.toLocaleString()}</strong> recorded relationships</span>
                    <span>{scopes.length} {scopes.length === 1 ? 'variant' : 'variants'} · Paths stay within each variant</span>
                </div>
                {scopes.some(scope => scope.documents.some(doc => !doc.dependencies_recorded)) &&
                    <p role="status" className="mb-3 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">Some SBOM sources have no recorded dependencies. Re-import them to record dependencies; an unlinked package is not necessarily unused.</p>}
                {scopes.some(scope => scope.unresolvedEdges > 0) && <p role="alert" className="mb-3 text-sm text-amber-700 dark:text-amber-300">
                    {scopes.reduce((count, scope) => count + scope.unresolvedEdges, 0)} relationships reference packages missing from their variant and cannot be explored.</p>}
                <div className="mb-3 flex flex-wrap items-center gap-3">
                    <div className="relative min-w-56 flex-1">
                        <FontAwesomeIcon icon={faMagnifyingGlass} className={`absolute left-3 top-3 text-sm ${mutedClass}`} />
                        <input type="search" aria-label="Find a package" placeholder="Find a package by name, version or revision…"
                            value={query} onChange={event => { setQuery(event.target.value); setSearchLimit(TREE_PAGE_SIZE); }}
                            className="w-full rounded-md border border-gray-300 bg-white py-2 pl-9 pr-3 text-sm dark:border-neutral-600 dark:bg-neutral-900" />
                    </div>
                    <div className="flex gap-1" role="group" aria-label="Relationship direction">
                        {(['dependencies', 'dependents'] as const).map(value => <button key={value} type="button" aria-pressed={direction === value}
                            className={`${buttonClass} ${direction === value ? 'border-cyan-600 bg-cyan-50 text-cyan-900 dark:bg-cyan-950 dark:text-cyan-200' : ''}`}
                            onClick={() => {
                                setDirection(value);
                                setSelection(previous => previous ? { id: previous.id, variantId: previous.variantId, rootId: previous.rootId } : undefined);
                            }}>{value === 'dependencies' ? 'Depends on' : 'Required by'}</button>)}
                    </div>
                    <div className="flex gap-1" role="group" aria-label="Explorer view">
                        <button type="button" aria-pressed={viewMode === 'tree'} className={buttonClass} onClick={() => setMode('tree')}>Tree</button>
                        <button type="button" aria-pressed={viewMode === 'graph'} className={buttonClass} disabled={!selected || !!query.trim()}
                            title={!selected ? 'Select a package to view its neighborhood' : 'A focused diagram, not the whole SBOM'} onClick={() => setMode('graph')}>Graph</button>
                    </div>
                </div>
                <div className="mb-3 flex min-h-8 flex-wrap items-center gap-2 text-sm" aria-label="Exploration root">
                    <button type="button" className="text-cyan-700 underline dark:text-cyan-300" onClick={overview}>All packages</button>
                    {rootId && <><FontAwesomeIcon icon={faChevronRight} className={`text-xs ${mutedClass}`} />
                        <span className="min-w-0 break-all font-medium">{rootPackage ? packageVersionLabel(rootPackage) : rootId}</span></>}
                    <span className={`ml-auto text-xs ${mutedClass}`}>{direction === 'dependencies' ? 'Package → its dependencies' : 'Package → packages that require it'}</span>
                </div>
                {scopes.length === 0 ? <p role="status" className="mb-3 text-sm">No variants selected. Select a variant to explore its relationships.</p>
                    : !rootExists && <p role="alert" className="mb-3 text-sm">This package is not in the selected scope. Choose All packages or search for another package.</p>}
                <div className="grid flex-1 grid-cols-1 items-start gap-4 lg:min-h-0 lg:grid-cols-[minmax(0,1fr)_300px] lg:items-stretch">
                    <div className="h-[55vh] min-h-[280px] overflow-auto rounded-lg border border-gray-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 lg:h-auto lg:min-h-0">
                        {query.trim() ? <div className="p-3">
                            <div className="mb-3 flex items-center justify-between gap-2"><h2 className="text-sm font-semibold">{searchResults.length} package matches</h2>
                                <button type="button" className="text-sm text-cyan-700 underline dark:text-cyan-300" onClick={() => { setQuery(''); setMode('tree'); }}>Back to tree</button></div>
                            {!searchResults.length && <p className={`text-sm ${mutedClass}`}>No packages match “{query}”. Try a name, version or source revision.</p>}
                            <ul aria-label="Package search results" className="space-y-1">{searchResults.slice(0, searchLimit).map(({ scope, pkg }) => <li key={JSON.stringify([scope.id, pkg.id])}>
                                <button type="button" onClick={() => explore(pkg.id, scope.id, direction)}
                                    className="flex w-full items-center gap-3 rounded-md p-3 text-left text-sm hover:bg-cyan-50 dark:hover:bg-cyan-950">
                                    <FontAwesomeIcon icon={faBox} className="text-cyan-600" /><span className="min-w-0 flex-1"><PackageLabel pkg={pkg} /><span className={`block text-xs ${mutedClass}`}>{scope.name}</span></span>
                                    <span className="shrink-0 text-xs text-cyan-700 dark:text-cyan-300">Explore</span>
                                </button>
                            </li>)}</ul>
                            {searchResults.length > searchLimit && <button type="button" className={`${buttonClass} mt-3`} onClick={() => setSearchLimit(previous => previous + TREE_PAGE_SIZE)}>Show more results ({searchLimit} of {searchResults.length})</button>}
                        </div> : <>
                            <div hidden={viewMode !== 'tree'}>
                                <p className={`border-b border-gray-200 px-3 py-2 text-xs dark:border-neutral-700 ${mutedClass}`}>
                                    {rootId ? 'Expand any branch to follow the complete path.' : `Entry points have no recorded ${direction === 'dependencies' ? 'dependents' : 'dependencies'}. Cyclic groups and unlinked packages are included.`}
                                    {' '}Select a row to inspect it. Use arrow keys to navigate and expand.
                                </p>
                                {rootExists && scopes.filter(scope => !rootId || scope.packages.has(rootId)).map(scope =>
                                    <ExplorerTree key={`${scope.id}:${sourceId}:${direction}:${rootId ?? ''}`} scope={scope} direction={direction}
                                        rootId={rootId} selected={selected} onSelect={next => setSelection({ ...next, rootId })} />)}
                            </div>
                            {viewMode === 'graph' && selected && selectedScope && <NeighborhoodGraph scope={selectedScope} selection={selected} direction={direction} onSelect={next => setSelection({ ...next, rootId })} />}
                        </>}
                    </div>
                    <aside aria-label="Package inspector" className="rounded-lg border border-gray-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900 lg:min-h-0 lg:overflow-auto">
                        {selected && selectedScope ? <PackageDetails scope={selectedScope} selection={selected} onExplore={explore} />
                            : <div className="py-8 text-center"><FontAwesomeIcon icon={faBox} className={`mb-3 text-2xl ${mutedClass}`} />
                                <h2 className="text-sm font-semibold">Inspect a package</h2><p className={`mt-2 text-sm ${mutedClass}`}>Select a tree row to see direct and transitive relationships, source evidence, and reverse dependency paths.</p></div>}
                    </aside>
                </div>
            </>}
    </section>;
}
