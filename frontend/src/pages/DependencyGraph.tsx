import { useEffect, useMemo, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowRight, faDiagramProject, faMagnifyingGlass, faRotateRight } from '@fortawesome/free-solid-svg-icons';
import { ReactFlow, Background, Controls, MarkerType } from '@xyflow/react';
import type { Edge, Node } from '@xyflow/react';
import dagre from 'dagre';
import '@xyflow/react/dist/style.css';
import { listDependencies } from '../handlers/dependencies';
import type { DependencyDocument, DependencyEdge, DependencyPackage } from '../handlers/dependencies';

type Props = {
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
    operation?: string;
    dataRevision?: number;
    focusedPackageId?: string;
    onFocusPackage?: (packageId: string) => void;
    onClearFocus?: () => void;
};
type ViewProps = Pick<Props, 'focusedPackageId' | 'onFocusPackage' | 'onClearFocus'> & {
    documents: DependencyDocument[];
    loading?: boolean;
    error?: string;
    onRetry?: () => void;
};

const PAGE_SIZE = 50;
const MAX_GRAPH_PACKAGES = 200;
const MAX_GRAPH_NODES = 200;
const MAX_GRAPH_EDGES = 400;
const NODE_WIDTH = 190;
const NODE_HEIGHT = 60;

function DependencyGraph({ variantId, projectId, variantIds, compareVariantId, operation, dataRevision,
    focusedPackageId, onFocusPackage, onClearFocus }: Readonly<Props>) {
    const [documents, setDocuments] = useState<DependencyDocument[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        listDependencies(variantId, projectId, variantIdsKey ? variantIdsKey.split(',') : undefined,
            compareVariantId, operation)
            .then(result => { if (!cancelled) setDocuments(result); })
            .catch(() => { if (!cancelled) setError('Unable to load dependencies'); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision, retry]);

    return <DependencyGraphView documents={documents} loading={loading} error={error}
        onRetry={() => setRetry(value => value + 1)} focusedPackageId={focusedPackageId}
        onFocusPackage={onFocusPackage} onClearFocus={onClearFocus} />;
}

export function DependencyGraphView({ documents, loading = false, error = '', onRetry,
    focusedPackageId, onFocusPackage, onClearFocus }: Readonly<ViewProps>) {
    const [documentId, setDocumentId] = useState('all');
    const [excluded, setExcluded] = useState<Set<string>>(new Set());
    const [page, setPage] = useState(0);

    useEffect(() => {
        if (documentId !== 'all' && !documents.some(doc => doc.id === documentId)) {
            setDocumentId('all');
            setExcluded(new Set());
            setPage(0);
            onClearFocus?.();
        }
    }, [documents, documentId, onClearFocus]);

    const scope = useMemo(() => documents.filter(doc => documentId === 'all' || doc.id === documentId), [documents, documentId]);
    const packages = useMemo(() => {
        const entries = new Map<string, DependencyPackage>();
        scope.forEach(doc => doc.packages.forEach(pkg => entries.set(pkg.id, pkg)));
        return entries;
    }, [scope]);
    const edges = useMemo(() => {
        const entries = new Map<string, DependencyEdge>();
        scope.forEach(doc => doc.edges.forEach(edge => {
            if (packages.has(edge.package_id) && packages.has(edge.dependency_id)) {
                entries.set(`${edge.package_id}:${edge.dependency_id}`, edge);
            }
        }));
        return [...entries.values()];
    }, [scope, packages]);
    const dependencies = useMemo(() => {
        const bySource = new Map<string, string[]>();
        edges.forEach(edge => {
            const targets = bySource.get(edge.package_id);
            if (targets) targets.push(edge.dependency_id);
            else bySource.set(edge.package_id, [edge.dependency_id]);
        });
        return bySource;
    }, [edges]);
    const ordered = useMemo(() => [...packages.values()].sort((left, right) =>
        (dependencies.get(right.id)?.length ?? 0) - (dependencies.get(left.id)?.length ?? 0)
        || left.name.localeCompare(right.name) || left.version.localeCompare(right.version) || left.id.localeCompare(right.id)
    ), [packages, dependencies]);
    const focused = focusedPackageId && packages.has(focusedPackageId) ? focusedPackageId : undefined;
    const visible = useMemo(() => ordered.filter(pkg => focused ? pkg.id === focused : !excluded.has(pkg.id)),
        [ordered, focused, excluded]);
    const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
    const currentPage = Math.min(page, pageCount - 1);
    const displayed = useMemo(() => visible.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE),
        [visible, currentPage]);
    const needsFocus = visible.length > MAX_GRAPH_PACKAGES && !focused;
    const graph = useMemo(() => {
        const graphSources = needsFocus ? [] : displayed;
        if (graphSources.length === 0) return { nodes: [], edges: [], limited: false };
        const layout = new dagre.graphlib.Graph();
        layout.setGraph({ rankdir: 'LR', nodesep: 30, ranksep: 90 });
        layout.setDefaultEdgeLabel(() => ({}));
        const nodeIds = new Set(graphSources.map(pkg => pkg.id));
        const graphEdges: Edge[] = [];
        let limited = false;
        graphSources.forEach(pkg => (dependencies.get(pkg.id) ?? []).forEach(id => {
            if (graphEdges.length >= MAX_GRAPH_EDGES || (!nodeIds.has(id) && nodeIds.size >= MAX_GRAPH_NODES)) {
                limited = true;
                return;
            }
            nodeIds.add(id);
            graphEdges.push({ id: `${pkg.id}:${id}`, source: pkg.id, target: id,
                markerEnd: { type: MarkerType.ArrowClosed }, animated: false });
        }));
        nodeIds.forEach(id => layout.setNode(id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
        graphEdges.forEach(edge => layout.setEdge(edge.source, edge.target));
        dagre.layout(layout);
        const nodes: Node[] = [...nodeIds].map(id => {
            const pkg = packages.get(id)!;
            const position = layout.node(id);
            return { id, data: { label: `${pkg.name}@${pkg.version}` },
                position: { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 },
                style: { width: NODE_WIDTH, minHeight: NODE_HEIGHT, overflowWrap: 'anywhere',
                    borderColor: id === focused ? '#0e7490' : '#9ca3af' } };
        });
        return { nodes, edges: graphEdges, limited };
    }, [needsFocus, displayed, dependencies, packages, focused]);
    const visibleEdges = graph.edges.length;

    const toggle = (id: string) => {
        if (focused) onClearFocus?.();
        setExcluded(previous => {
            const next = new Set(previous);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
        setPage(0);
    };

    return (
        <section className="flex flex-col h-full min-h-0 text-gray-900 dark:text-neutral-100" aria-label="Dependency graph">
            <div className="flex flex-wrap items-center gap-3 border-b border-gray-300 dark:border-neutral-600 pb-3 mb-4">
                <FontAwesomeIcon icon={faDiagramProject} className="text-cyan-700 dark:text-cyan-300" />
                <h1 className="text-xl font-semibold">Dependencies</h1>
                <label className="ml-auto flex items-center gap-2 text-sm">
                    SBOM source
                    <select aria-label="SBOM source" className="border rounded bg-white dark:bg-neutral-800 px-2 py-1 max-w-56" value={documentId}
                        onChange={event => { setDocumentId(event.target.value); setExcluded(new Set()); setPage(0); onClearFocus?.(); }}>
                        <option value="all">All SBOM sources</option>
                        {documents.map(doc => <option value={doc.id} key={doc.id}>{doc.source_name}</option>)}
                    </select>
                </label>
            </div>
            {loading && <p role="status">Loading dependency graph...</p>}
            {!loading && error && <div role="alert">{error} <button type="button" onClick={onRetry} aria-label="Retry loading dependencies"><FontAwesomeIcon icon={faRotateRight} /></button></div>}
            {!loading && !error && ordered.length === 0 && <p>No packages in this SBOM scope.</p>}
            {!loading && !error && ordered.length > 0 && <div className="flex flex-col md:flex-row gap-4 flex-1 min-h-0">
                <aside className="md:w-72 md:shrink-0 flex flex-col min-h-0 border-r border-gray-300 dark:border-neutral-600 pr-3" aria-label="Package selector">
                    <div className="flex justify-between items-center text-sm mb-2">
                        <strong>Packages ({visible.length}/{ordered.length})</strong>
                        <div className="flex gap-2">
                            <button type="button" className="text-cyan-800 dark:text-cyan-300 underline" onClick={() => { onClearFocus?.(); setExcluded(new Set()); setPage(0); }}>All</button>
                            <button type="button" className="text-cyan-800 dark:text-cyan-300 underline" onClick={() => { onClearFocus?.(); setExcluded(new Set(ordered.map(pkg => pkg.id))); setPage(0); }}>None</button>
                        </div>
                    </div>
                    <div className="overflow-y-auto max-h-48 md:max-h-none md:flex-1 space-y-1">
                        {ordered.map(pkg => <label key={pkg.id} className="flex items-start gap-2 py-1 text-sm cursor-pointer hover:bg-gray-100 dark:hover:bg-neutral-700">
                            <input type="checkbox" className="mt-1" aria-label={`Show ${pkg.name}@${pkg.version}`} checked={focused ? focused === pkg.id : !excluded.has(pkg.id)} onChange={() => toggle(pkg.id)} />
                            <span className="min-w-0 break-all">{pkg.name}<span className="text-gray-500 dark:text-gray-400">@{pkg.version}</span></span>
                            <span className="ml-auto tabular-nums text-gray-500 dark:text-gray-400">{dependencies.get(pkg.id)?.length ?? 0}</span>
                            {onFocusPackage && <button type="button" title={`Focus ${pkg.name}@${pkg.version}`}
                                aria-label={`Focus ${pkg.name}@${pkg.version}`} onClick={() => onFocusPackage(pkg.id)}>
                                <FontAwesomeIcon icon={faMagnifyingGlass} />
                            </button>}
                        </label>)}
                    </div>
                </aside>
                <div className="flex-1 min-w-0 overflow-auto" aria-label="Directed dependencies">
                    <div className="flex flex-wrap items-center gap-3 text-sm mb-3 text-gray-600 dark:text-gray-300">
                        {!needsFocus && <span>{visibleEdges} dependencies from {visible.length} selected packages</span>}
                        {focused && <button type="button" className="underline text-cyan-800 dark:text-cyan-300" onClick={onClearFocus}>Show whole graph</button>}
                        {visible.length > PAGE_SIZE && <span>Displaying {currentPage * PAGE_SIZE + 1}-{Math.min((currentPage + 1) * PAGE_SIZE, visible.length)} of {visible.length} packages</span>}
                    </div>
                    {visible.length === 0 && <p>Select packages to display their dependencies.</p>}
                    {needsFocus && <p>Focus a package from the list to display its dependency graph.</p>}
                    {!needsFocus && visibleEdges === 0 && visible.length > 0 && <p>No dependency relationships recorded for the selected packages.</p>}
                    {graph.limited && <p role="status">Graph limited to {MAX_GRAPH_NODES} packages and {MAX_GRAPH_EDGES} relationships.</p>}
                    {!needsFocus && visible.length > 0 && <div className="h-[min(68vh,740px)] min-h-[360px] w-full border border-gray-300 dark:border-neutral-600" aria-label="Dependency diagram">
                        <ReactFlow key={`${documentId}:${focused ?? ''}:${currentPage}:${graph.nodes.map(node => node.id).join(',')}`}
                            nodes={graph.nodes} edges={graph.edges} fitView nodesDraggable={false} onlyRenderVisibleElements
                            minZoom={0.1} maxZoom={1.5} onNodeClick={(_, node) => onFocusPackage?.(node.id)}>
                            <Background />
                            <Controls showInteractive={false} />
                        </ReactFlow>
                    </div>}
                    <div className="space-y-2">
                        {displayed.map(pkg => <div key={pkg.id} className="border-b border-gray-200 dark:border-neutral-700 pb-2">
                            <div className="font-medium break-all">{pkg.name}<span className="text-gray-500 dark:text-gray-400">@{pkg.version}</span></div>
                            <div className="ml-3 border-l-2 border-cyan-700 pl-3 space-y-1">
                                {(dependencies.get(pkg.id) ?? []).map(id => {
                                    const target = packages.get(id);
                                    return target && <div key={id} className="flex items-center gap-2 text-sm" role="listitem">
                                        <FontAwesomeIcon icon={faArrowRight} aria-label="depends on" className="text-cyan-700 dark:text-cyan-300 shrink-0" />
                                        <span className="break-all">{target.name}@{target.version}</span>
                                    </div>;
                                })}
                            </div>
                        </div>)}
                    </div>
                    {pageCount > 1 && <div className="flex items-center gap-3 py-3">
                        <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
                        <span>Page {currentPage + 1} of {pageCount}</span>
                        <button type="button" disabled={currentPage === pageCount - 1} onClick={() => setPage(currentPage + 1)}>Next</button>
                    </div>}
                </div>
            </div>}
        </section>
    );
}

export default DependencyGraph;