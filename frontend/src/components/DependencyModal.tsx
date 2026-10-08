import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChevronDown, faChevronRight, faRotateRight } from '@fortawesome/free-solid-svg-icons';
import { ReactFlow, Background, Controls, MarkerType, Position } from '@xyflow/react';
import type { Edge, Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import ModalShell from './ModalShell';
import { listDependencies } from '../handlers/dependencies';
import type { DependencyDocument, DependencyPackage } from '../handlers/dependencies';

type Props = {
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
    operation?: string;
    dataRevision?: number;
    packageId: string;
    onClose: () => void;
};
type ViewProps = {
    documents: DependencyDocument[];
    packageId: string;
    onSelectPackage: (id: string) => void;
    loading?: boolean;
    error?: string;
    onRetry?: () => void;
};

const NODE_WIDTH = 190;
const NODE_HEIGHT = 60;
const COLUMN_GAP = 90;
const ROW_GAP = 20;
// Light shades keep the dark node label readable.
const VARIANT_COLORS = ['#7dd3fc', '#fda4af', '#86efac', '#fcd34d', '#c4b5fd', '#f9a8d4', '#5eead4', '#fdba74',
    '#a5b4fc', '#bef264'];

function addLink(links: Map<string, Set<string>>, key: string, value: string) {
    if (!links.has(key)) links.set(key, new Set());
    links.get(key)!.add(value);
}

// Wrap one side of the center into columns so packages with many neighbours keep a readable shape.
function sidePositions(ids: string[], direction: number): [string, { x: number; y: number }][] {
    const rows = Math.ceil(ids.length / Math.max(1, Math.ceil(Math.sqrt(ids.length / 8))));
    return ids.map((id, index) => [id, {
        x: direction * (Math.floor(index / rows) + 1) * (NODE_WIDTH + COLUMN_GAP),
        y: (index % rows - (rows - 1) / 2) * (NODE_HEIGHT + ROW_GAP),
    }]);
}

function variantBackground(colors: string[]): string {
    if (colors.length === 1) return colors[0];
    const stops = colors.map((color, index) =>
        `${color} ${(index * 100 / colors.length).toFixed(2)}% ${((index + 1) * 100 / colors.length).toFixed(2)}%`);
    return `linear-gradient(90deg, ${stops.join(', ')})`;
}

// Opening several packages of the same scope reuses one graph download until the data changes.
let cachedGraph: { key: string; request: Promise<DependencyDocument[]> } | undefined;

function loadGraph(key: string, load: () => Promise<DependencyDocument[]>): Promise<DependencyDocument[]> {
    if (cachedGraph?.key !== key) {
        const request = load();
        request.catch(() => { if (cachedGraph?.request === request) cachedGraph = undefined; });
        cachedGraph = { key, request };
    }
    return cachedGraph.request;
}

function DependencyModal({ variantId, projectId, variantIds, compareVariantId, operation, dataRevision,
    packageId, onClose }: Readonly<Props>) {
    const [documents, setDocuments] = useState<DependencyDocument[]>([]);
    const [selectedPackage, setSelectedPackage] = useState(packageId);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');

    useEffect(() => { setSelectedPackage(packageId); }, [packageId]);
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        const key = JSON.stringify([variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision]);
        loadGraph(key, () => listDependencies(variantId, projectId, variantIdsKey?.split(','), compareVariantId, operation))
            .then(result => { if (!cancelled) setDocuments(result); })
            .catch(() => { if (!cancelled) setError('Unable to load dependencies'); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision, retry]);

    return <ModalShell isOpen title={`Dependencies: ${selectedPackage}`} size="fullscreen" onClose={onClose}
        testId="dependency-modal" contentClassName="flex flex-1 flex-col min-h-0">
        <DependencyModalView documents={documents} packageId={selectedPackage} onSelectPackage={setSelectedPackage}
            loading={loading} error={error} onRetry={() => setRetry(value => value + 1)} />
    </ModalShell>;
}

function DependencyTree({ packageId, packages, links, onSelectPackage, ancestors = [], root = false }: Readonly<{
    packageId: string;
    packages: Map<string, DependencyPackage>;
    links: Map<string, string[]>;
    onSelectPackage: (id: string) => void;
    ancestors?: string[];
    root?: boolean;
}>) {
    const [expanded, setExpanded] = useState(root);
    const children = links.get(packageId) ?? [];
    const cyclic = ancestors.includes(packageId);
    const pkg = packages.get(packageId);
    return <li role="treeitem" aria-expanded={children.length && !cyclic ? expanded : undefined} className="min-w-0">
        <div className="flex items-center gap-1 py-1 text-sm">
            {children.length > 0 && !cyclic ? <button type="button" onClick={() => setExpanded(value => !value)}
                aria-label={`${expanded ? 'Collapse' : 'Expand'} ${packageId}`} className="h-6 w-6 shrink-0 text-neutral-400">
                <FontAwesomeIcon icon={expanded ? faChevronDown : faChevronRight} />
            </button> : <span className="w-6 shrink-0" />}
            <button type="button" onClick={() => onSelectPackage(packageId)}
                className="min-w-0 break-all text-left text-cyan-300 hover:underline">
                {pkg ? `${pkg.name}@${pkg.version}` : packageId}
            </button>
            {children.length > 0 && <span className="ml-auto tabular-nums text-neutral-400">{children.length}</span>}
        </div>
        {expanded && !cyclic && children.length > 0 && <ul role="group" className="ml-3 border-l border-neutral-700 pl-2">
            {children.map(child => <DependencyTree key={child} packageId={child} packages={packages} links={links}
                onSelectPackage={onSelectPackage} ancestors={[...ancestors, packageId]} />)}
        </ul>}
    </li>;
}

export function DependencyModalView({ documents, packageId, onSelectPackage, loading = false, error = '', onRetry }: Readonly<ViewProps>) {
    const [hiddenVariants, setHiddenVariants] = useState<Set<string>>(new Set());
    const [documentId, setDocumentId] = useState('all');
    const [diagramWidth, setDiagramWidth] = useState(0);
    const diagramRef = useRef<HTMLDivElement>(null);
    const packages = useMemo(() => {
        const packages = new Map<string, DependencyPackage>();
        documents.forEach(doc => doc.packages.forEach(pkg => packages.set(pkg.id, pkg)));
        return packages;
    }, [documents]);
    const variants = useMemo(() => {
        const names = new Map<string, string>();
        documents.forEach(doc => names.set(doc.variant_id, doc.variant_name));
        return [...names].sort(([, left], [, right]) => left.localeCompare(right))
            .map(([id, name], index) => ({ id, name, color: VARIANT_COLORS[index % VARIANT_COLORS.length] }));
    }, [documents]);
    const packageVariants = useMemo(() => variants.filter(variant => documents.some(doc =>
        doc.variant_id === variant.id && doc.packages.some(pkg => pkg.id === packageId))), [variants, documents, packageId]);
    const sources = useMemo(() => documents.filter(doc => !hiddenVariants.has(doc.variant_id)
        && doc.packages.some(pkg => pkg.id === packageId)), [documents, hiddenVariants, packageId]);

    useEffect(() => {
        if (documentId !== 'all' && !sources.some(doc => doc.id === documentId)) setDocumentId('all');
    }, [sources, documentId]);

    // Dependencies may live in another document of the same scan, so every document in scope contributes edges.
    const scoped = useMemo(() => documents.filter(doc => documentId === 'all' || doc.id === documentId),
        [documents, documentId]);
    const visible = useMemo(() => scoped.filter(doc => !hiddenVariants.has(doc.variant_id)), [scoped, hiddenVariants]);
    const { dependencyVariants, dependentVariants } = useMemo(() => {
        const dependencyVariants = new Map<string, Set<string>>();
        const dependentVariants = new Map<string, Set<string>>();
        scoped.forEach(doc => doc.edges.forEach(edge => {
            if (!packages.has(edge.package_id) || !packages.has(edge.dependency_id)) return;
            if (edge.package_id === packageId) addLink(dependencyVariants, edge.dependency_id, doc.variant_id);
            if (edge.dependency_id === packageId) addLink(dependentVariants, edge.package_id, doc.variant_id);
        }));
        return { dependencyVariants, dependentVariants };
    }, [scoped, packages, packageId]);
    const { outgoing, incoming } = useMemo(() => {
        const outgoing = new Map<string, Set<string>>();
        const incoming = new Map<string, Set<string>>();
        visible.forEach(doc => doc.edges.forEach(edge => {
            if (!packages.has(edge.package_id) || !packages.has(edge.dependency_id)) return;
            addLink(outgoing, edge.package_id, edge.dependency_id);
            addLink(incoming, edge.dependency_id, edge.package_id);
        }));
        const sorted = (links: Map<string, Set<string>>) => new Map([...links].map(([id, targets]) => [id, [...targets].sort()]));
        return { outgoing: sorted(outgoing), incoming: sorted(incoming) };
    }, [visible, packages]);
    const dependencies = useMemo(() => outgoing.get(packageId) ?? [], [outgoing, packageId]);
    const dependents = useMemo(() => incoming.get(packageId) ?? [], [incoming, packageId]);
    // In counts the dependencies a package pulls in, Out the packages it flows out to.
    const legend = useMemo(() => packageVariants.map(variant => ({
        ...variant,
        recorded: documents.some(doc => doc.variant_id === variant.id && doc.dependencies_recorded
            && doc.packages.some(pkg => pkg.id === packageId)),
        in: [...dependencyVariants.values()].filter(linked => linked.has(variant.id)).length,
        out: [...dependentVariants.values()].filter(linked => linked.has(variant.id)).length,
    })), [packageVariants, documents, packageId, dependencyVariants, dependentVariants]);
    const toggleVariant = (id: string) => setHiddenVariants(previous => {
        const next = new Set(previous);
        if (!next.delete(id)) next.add(id);
        return next;
    });
    const hiddenKey = [...hiddenVariants].sort().join(',');
    const hasData = packageVariants.length > 0;
    const graph = useMemo(() => {
        if (!hasData) return { nodes: [] as Node[], edges: [] as Edge[] };
        const dependencyIds = new Set(dependencies);
        const positions = new Map([
            [packageId, { x: 0, y: 0 }],
            ...sidePositions(dependencies.filter(id => id !== packageId), -1),
            ...sidePositions(dependents.filter(id => id !== packageId && !dependencyIds.has(id)), 1),
        ]);
        const ids = [...positions.keys()];
        const edges: Edge[] = [];
        ids.forEach(id => {
            if (id !== packageId && dependencyIds.has(id)) edges.push({ id: `${id}:${packageId}`, source: id, target: packageId,
                type: 'straight', markerEnd: { type: MarkerType.ArrowClosed } });
            if (id !== packageId && dependents.includes(id)) edges.push({ id: `${packageId}:${id}`, source: packageId, target: id,
                type: 'straight', markerEnd: { type: MarkerType.ArrowClosed } });
        });
        const nodes: Node[] = ids.map(id => {
            const pkg = packages.get(id)!;
            const position = positions.get(id)!;
            const linked = variants.filter(variant => !hiddenVariants.has(variant.id)
                && (dependencyVariants.get(id)?.has(variant.id) || dependentVariants.get(id)?.has(variant.id)));
            const label = `${pkg.name}@${pkg.version}`;
            return { id,
                data: { label: id === packageId ? label
                    : <span title={`Variants: ${linked.map(variant => variant.name).join(', ')}`}>{label}</span> },
                position: { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 },
                sourcePosition: Position.Right, targetPosition: Position.Left,
                style: { width: NODE_WIDTH, minHeight: NODE_HEIGHT, overflowWrap: 'anywhere', color: '#111827',
                    borderColor: id === packageId ? '#0e7490' : '#9ca3af',
                    ...(id !== packageId && linked.length
                        ? { background: variantBackground(linked.map(variant => variant.color)) } : {}) } };
        });
        return { nodes, edges };
    }, [hasData, packages, packageId, dependencies, dependents, variants, hiddenVariants, dependencyVariants, dependentVariants]);

    useEffect(() => {
        if (!diagramRef.current) return;
        const observer = new ResizeObserver(entries => setDiagramWidth(Math.round(entries[0].contentRect.width)));
        observer.observe(diagramRef.current);
        return () => observer.disconnect();
    }, [loading, error, hasData]);

    if (loading) return <p role="status">Loading dependency graph...</p>;
    if (error) return <div role="alert">{error} <button type="button" onClick={onRetry}
        aria-label="Retry loading dependencies"><FontAwesomeIcon icon={faRotateRight} /></button></div>;
    if (!hasData) return <p>No dependency data for this package.</p>;

    return <section className="flex min-h-0 flex-1 flex-col" aria-label="Package dependencies">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3 text-sm">
            <span>In {dependencies.length} / Out {dependents.length}</span>
            {sources.length > 1 && <label className="flex items-center gap-2">SBOM source
                <select aria-label="SBOM source" value={documentId} onChange={event => setDocumentId(event.target.value)}
                    className="max-w-56 rounded border border-neutral-600 bg-neutral-800 px-2 py-1">
                    <option value="all">All SBOM sources</option>
                    {sources.map(doc => <option key={doc.id} value={doc.id}>{doc.source_name}</option>)}
                </select>
            </label>}
        </div>
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(18rem,1fr)]">
            <div className="flex min-h-0 min-w-0 flex-col" aria-label="Dependency graph">
                <div ref={diagramRef} className="h-[48vh] min-h-[280px] w-full border border-neutral-700 lg:h-full" aria-label="Dependency diagram">
                    <ReactFlow key={`${packageId}:${hiddenKey}:${documentId}:${diagramWidth}`} nodes={graph.nodes} edges={graph.edges}
                        style={{ '--xy-controls-button-background-color': '#262626',
                            '--xy-controls-button-background-color-hover': '#404040',
                            '--xy-controls-button-color': '#f5f5f5',
                            '--xy-controls-button-color-hover': '#ffffff',
                            '--xy-controls-button-border-color': '#525252' } as CSSProperties}
                        fitView nodesDraggable={false} onlyRenderVisibleElements minZoom={0.1} maxZoom={1.5}
                        onNodeClick={(_, node) => onSelectPackage(node.id)}>
                        <Background /><Controls showInteractive={false} />
                    </ReactFlow>
                </div>
            </div>
            <aside className="min-h-0 overflow-y-auto border-t border-neutral-700 pt-3 lg:border-l lg:border-t-0 lg:pl-4 lg:pt-0"
                aria-label="Dependency tree">
                <h3 className="mb-2 text-sm font-semibold">Variants</h3>
                <ul aria-label="Variants" className="mb-5 space-y-1 text-sm">
                    {legend.map(variant => <li key={variant.id}>
                        <label className="flex cursor-pointer items-center gap-2">
                            <input type="checkbox" aria-label={variant.name} checked={!hiddenVariants.has(variant.id)}
                                onChange={() => toggleVariant(variant.id)} className="h-4 w-4 shrink-0 accent-cyan-600" />
                            <span aria-hidden="true" className="h-3 w-3 shrink-0 rounded-sm border border-neutral-500"
                                style={{ backgroundColor: variant.color }} />
                            <span className="min-w-0 flex-1 break-all">{variant.name}</span>
                            <span className="tabular-nums text-neutral-400">
                                {variant.recorded ? `In ${variant.in} / Out ${variant.out}` : 'Not recorded'}
                            </span>
                        </label>
                    </li>)}
                </ul>
                <h3 className="mb-2 text-sm font-semibold">Depends on ({dependencies.length})</h3>
                <ul role="tree" aria-label="Depends on">
                    <DependencyTree key={`out:${packageId}:${hiddenKey}:${documentId}`} packageId={packageId} packages={packages}
                        links={outgoing} onSelectPackage={onSelectPackage} root />
                </ul>
                <h3 className="mb-2 mt-5 text-sm font-semibold">Required by ({dependents.length})</h3>
                <ul role="tree" aria-label="Required by">
                    <DependencyTree key={`in:${packageId}:${hiddenKey}:${documentId}`} packageId={packageId} packages={packages}
                        links={incoming} onSelectPackage={onSelectPackage} root />
                </ul>
            </aside>
        </div>
    </section>;
}

export default DependencyModal;
