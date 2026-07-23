import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faLayerGroup, faChevronDown, faSort } from '@fortawesome/free-solid-svg-icons';
import Projects from '../handlers/project';
import type { Project } from '../handlers/project';
import Variants from '../handlers/variant';
import type { Variant } from '../handlers/variant';
import type { FrontendScope } from '../handlers/config';

const greenTheme = true;
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Mode = 'select' | 'compare';

// Snapshot of the currently-applied (loaded) scope, used to restore the panel
// controls to the active configuration each time it is reopened.
type AppliedScope = {
    projectId: string;
    mode: Mode;
    variantIds: string[];
    compareBaseId: string;
    compareOp: 'difference' | 'intersection';
    compareId: string;
};

type Props = {
    defaultProject?: { id: string; name: string } | null;
    defaultVariant?: { id: string; name: string } | null;
    defaultScope?: FrontendScope | null;
    onApply: (projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => void;
};

function ProjectVariantSelector({ defaultProject, defaultScope, onApply }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const buttonRef = useRef<HTMLButtonElement>(null);
    const panelRef = useRef<HTMLDivElement>(null);

    const [projects, setProjects] = useState<Project[]>([]);
    const [variants, setVariants] = useState<Variant[]>([]);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');

    // Two mutually-exclusive modes:
    //  - 'select': pick one or more variants; data relevant to *any* of them (union)
    //  - 'compare': diff/intersection between a base variant and a compare variant
    const [mode, setMode] = useState<Mode>('select');

    // Select-variants mode state (all variants selected by default)
    const [selectedVariantIds, setSelectedVariantIds] = useState<string[]>([]);

    // Compare-variants mode state
    const [compareBaseVariantId, setCompareBaseVariantId] = useState<string>('');
    const [compareOperation, setCompareOperation] = useState<'difference' | 'intersection'>('difference');
    const [selectedCompareVariantId, setSelectedCompareVariantId] = useState<string>('');

    // Applied (display) state — initialised from props when they arrive
    const [appliedProject, setAppliedProject] = useState<string>('');
    const [appliedLabel, setAppliedLabel] = useState<string>('');

    // Snapshot of the scope that is actually applied/loaded. Reopening the
    // panel restores its controls from this so the user always sees the
    // current settings checked rather than stale, un-applied edits.
    const [appliedScope, setAppliedScope] = useState<AppliedScope | null>(null);
    const appliedScopeRef = useRef<AppliedScope | null>(null);
    // Selection to apply once variants finish (re)loading for a project. Used
    // both for the initial config scope and when reopening restores a project.
    const pendingRestoreRef = useRef<string[] | null>(null);
    // Mirror project/variants in refs so the open-restore effect can read the
    // latest values without re-running on every change.
    const variantsRef = useRef<Variant[]>([]);
    const selectedProjectIdRef = useRef<string>('');

    const applyScope = (scope: AppliedScope) => {
        appliedScopeRef.current = scope;
        setAppliedScope(scope);
    };

    useEffect(() => { variantsRef.current = variants; }, [variants]);
    useEffect(() => { selectedProjectIdRef.current = selectedProjectId; }, [selectedProjectId]);

    // A persisted browser scope supersedes the server's default project.
    useEffect(() => {
        const initialProjectId = defaultScope?.project_id ?? defaultProject?.id;
        if (initialProjectId) {
            if (defaultScope?.mode === 'select') {
                pendingRestoreRef.current = defaultScope.variant_ids;
            }
            const initialProject = projects.find(project => project.id === initialProjectId)
                ?? (defaultProject?.id === initialProjectId ? defaultProject : null);
            setSelectedProjectId(initialProjectId);
            setAppliedProject(initialProject?.name ?? '');
        }
    }, [defaultProject, defaultScope, projects]);

    // Default the compare base / compare variant once variants are available
    useEffect(() => {
        if (variants.length === 0) return;
        if (!compareBaseVariantId || !variants.some(v => v.id === compareBaseVariantId)) {
            setCompareBaseVariantId(variants[0].id);
        }
    }, [variants, compareBaseVariantId]);

    useEffect(() => {
        if (selectedCompareVariantId === compareBaseVariantId) {
            const first = variants.find(v => v.id !== compareBaseVariantId);
            setSelectedCompareVariantId(first?.id ?? '');
        }
    }, [compareBaseVariantId, variants, selectedCompareVariantId]);

    // Load projects on mount
    useEffect(() => {
        Projects.list()
            .then(setProjects)
            .catch(() => setProjects([]));
    }, []);

    // Load variants when selected project changes
    useEffect(() => {
        let cancelled = false;
        setVariants([]);
        if (!selectedProjectId) return;
        Variants.list(selectedProjectId)
            .then(vs => {
                if (cancelled) return;
                setVariants(vs);
                const restore = pendingRestoreRef.current;
                pendingRestoreRef.current = null;
                if (restore) {
                    // Restore a previously-applied (or configured) selection,
                    // keeping only the ids that still exist for this project.
                    const valid = restore.filter(id => vs.some(v => v.id === id));
                    setSelectedVariantIds(valid.length ? valid : vs.map(v => v.id));
                } else {
                    // Select Variants mode defaults to all variants selected
                    setSelectedVariantIds(vs.map(v => v.id));
                }
            })
            .catch(() => {
                if (!cancelled) setVariants([]);
            });
        return () => { cancelled = true; };
    }, [selectedProjectId]);

    // Establish the initial applied scope from config once variants are known,
    // so the first reopen reflects the configured project/variant.
    useEffect(() => {
        const initialProjectId = defaultScope?.project_id ?? defaultProject?.id;
        if (appliedScope || variants.length === 0 || !selectedProjectId) return;
        if (initialProjectId !== selectedProjectId) return;
        const validVariantIds = (defaultScope?.mode === 'select' && defaultScope.variant_ids.length > 0)
            ? defaultScope.variant_ids.filter(id => variants.some(v => v.id === id))
            : variants.map(v => v.id);
        const initialScope: AppliedScope = defaultScope ? {
            projectId: selectedProjectId,
            mode: defaultScope.mode,
            variantIds: validVariantIds,
            compareBaseId: defaultScope.compare_base_id,
            compareOp: defaultScope.compare_operation,
            compareId: defaultScope.compare_variant_id,
        } : {
            projectId: selectedProjectId,
            mode: 'select',
            variantIds: validVariantIds,
            compareBaseId: variants[0]?.id ?? '',
            compareOp: 'difference',
            compareId: '',
        };
        applyScope(initialScope);
        setMode(initialScope.mode);
        setSelectedVariantIds(initialScope.variantIds);
        setCompareBaseVariantId(initialScope.compareBaseId);
        setCompareOperation(initialScope.compareOp);
        setSelectedCompareVariantId(initialScope.compareId);
        if (initialScope.mode === 'compare') {
            const base = variants.find(v => v.id === initialScope.compareBaseId);
            const compare = variants.find(v => v.id === initialScope.compareId);
            const symbol = initialScope.compareOp === 'difference' ? '∖' : '∩';
            setAppliedLabel(`${base?.name ?? 'All'} ${symbol} ${compare?.name ?? ''}`);
        } else if (initialScope.variantIds.length === variants.length) {
            setAppliedLabel('All variants');
        } else if (initialScope.variantIds.length === 1) {
            setAppliedLabel(variants.find(v => v.id === initialScope.variantIds[0])?.name ?? '');
        } else {
            setAppliedLabel(`${initialScope.variantIds.length} variants (∪)`);
        }
    }, [variants, selectedProjectId, appliedScope, defaultProject?.id, defaultScope]);

    // Restore the panel controls from the applied scope each time it opens.
    useEffect(() => {
        if (!isOpen) return;
        const scope = appliedScopeRef.current;
        if (!scope) return;
        setMode(scope.mode);
        setCompareBaseVariantId(scope.compareBaseId);
        setCompareOperation(scope.compareOp);
        setSelectedCompareVariantId(scope.compareId);
        if (scope.projectId !== selectedProjectIdRef.current) {
            // Switching back to the applied project reloads its variants; defer
            // the selection restore until they arrive.
            pendingRestoreRef.current = scope.variantIds;
            setSelectedProjectId(scope.projectId);
        } else if (scope.mode === 'select') {
            const valid = scope.variantIds.filter(id => variantsRef.current.some(v => v.id === id));
            setSelectedVariantIds(valid.length ? valid : variantsRef.current.map(v => v.id));
        }
    }, [isOpen]);

    // Close panel when clicking outside
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (
                panelRef.current && !panelRef.current.contains(event.target as Node) &&
                buttonRef.current && !buttonRef.current.contains(event.target as Node)
            ) {
                setIsOpen(false);
            }
        }
        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
            return () => document.removeEventListener('mousedown', handleClickOutside);
        }
    }, [isOpen]);

    // Close on Escape
    useEffect(() => {
        function handleEscape(event: KeyboardEvent) {
            if (event.key === 'Escape') setIsOpen(false);
        }
        if (isOpen) {
            document.addEventListener('keydown', handleEscape);
            return () => document.removeEventListener('keydown', handleEscape);
        }
    }, [isOpen]);

    const getPanelPosition = () => {
        if (!buttonRef.current) return { top: 0, right: 0 };
        const rect = buttonRef.current.getBoundingClientRect();
        return { top: rect.bottom + 4, right: window.innerWidth - rect.right };
    };

    const allSelected = variants.length > 0 && selectedVariantIds.length === variants.length;

    const handleApply = () => {
        const project = projects.find(p => p.id === selectedProjectId);

        if (mode === 'compare' && compareBaseVariantId && selectedCompareVariantId) {
            const base = variants.find(v => v.id === compareBaseVariantId);
            const compareVariant = variants.find(v => v.id === selectedCompareVariantId);
            const opSymbol = { difference: '∖', intersection: '∩' }[compareOperation];
            setAppliedProject(project?.name ?? '');
            setAppliedLabel(`${base?.name ?? 'All'} ${opSymbol} ${compareVariant?.name ?? ''}`);
            applyScope({
                projectId: selectedProjectId,
                mode: 'compare',
                variantIds: [],
                compareBaseId: compareBaseVariantId,
                compareOp: compareOperation,
                compareId: selectedCompareVariantId,
            });
            onApply(selectedProjectId, compareBaseVariantId, selectedCompareVariantId, compareOperation, [], '');
            setIsOpen(false);
            return;
        }

        // Select Variants mode — union of the selected variants
        setAppliedProject(project?.name ?? '');
        const selectScope: AppliedScope = {
            projectId: selectedProjectId,
            mode: 'select',
            variantIds: (allSelected || selectedVariantIds.length === 0)
                ? variants.map(v => v.id)
                : [...selectedVariantIds],
            compareBaseId: compareBaseVariantId,
            compareOp: compareOperation,
            compareId: selectedCompareVariantId,
        };
        applyScope(selectScope);
        if (allSelected || selectedVariantIds.length === 0) {
            // Whole project scope
            setAppliedLabel('All variants');
            onApply(selectedProjectId, '', '', '', [], '');
        } else if (selectedVariantIds.length === 1) {
            const variant = variants.find(v => v.id === selectedVariantIds[0]);
            setAppliedLabel(variant?.name ?? '');
            onApply(selectedProjectId, selectedVariantIds[0], '', '', [], '');
        } else {
            setAppliedLabel(`${selectedVariantIds.length} variants (∪)`);
            onApply(selectedProjectId, '', '', '', selectedVariantIds, 'union');
        }
        setIsOpen(false);
    };

    const applyDisabled = !selectedProjectId
        || (mode === 'select' && selectedVariantIds.length === 0)
        || (mode === 'compare' && (!compareBaseVariantId || !selectedCompareVariantId));

    const panelPosition = isOpen ? getPanelPosition() : { top: 0, right: 0 };

    return (
        <>
            <button
                ref={buttonRef}
                onClick={() => setIsOpen(!isOpen)}
                className={[
                    'flex items-center h-full px-4 py-2',
                    bgHoverColor,
                    isOpen ? bgActiveColor : ''
                ].join(' ')}
                type="button"
            >
                <FontAwesomeIcon icon={faLayerGroup} className="mr-2" />
                <div className="flex flex-col items-start leading-tight mr-2">
                    <span className="font-bold text-sm max-w-[160px] truncate">
                        {appliedProject || 'Select Project'}
                    </span>
                    <span className="text-xs font-normal opacity-75 max-w-[160px] truncate">
                        {appliedLabel || (appliedProject ? 'All variants' : 'No variant')}
                    </span>
                </div>
                <FontAwesomeIcon icon={faChevronDown} className="text-xs" />
            </button>

            {isOpen && createPortal(
                <div
                    ref={panelRef}
                    className="fixed z-[9999] bg-cyan-900 text-neutral-50 border border-cyan-700 rounded-lg shadow-xl p-4 w-72"
                    style={{ top: panelPosition.top, right: panelPosition.right }}
                >
                    <p className="text-xs font-semibold uppercase tracking-wide text-cyan-300 mb-3">
                        Project &amp; Variant
                    </p>

                    {/* Project select */}
                    <label className="block text-sm mb-1">Project</label>
                    <select
                        value={selectedProjectId}
                        onChange={e => setSelectedProjectId(e.target.value)}
                        className="w-full rounded px-2 py-1 text-sm bg-cyan-800 border border-cyan-600 focus:outline-none focus:border-cyan-400 mb-3"
                    >
                        <option value="">— select a project —</option>
                        {projects.map(p => (
                            <option key={p.id} value={p.id}>{p.name}</option>
                        ))}
                    </select>

                    {/* Mode selector — exclusive choice */}
                    <div className="flex flex-col gap-1.5 mb-3">
                        <label className="flex items-center gap-2 text-sm cursor-pointer">
                            <input
                                type="radio"
                                name="variant-mode"
                                value="select"
                                checked={mode === 'select'}
                                onChange={() => setMode('select')}
                                className="accent-cyan-400 shrink-0"
                            />
                            <span className="font-semibold">Select Variants</span>
                        </label>
                        <label className="flex items-center gap-2 text-sm cursor-pointer">
                            <input
                                type="radio"
                                name="variant-mode"
                                value="compare"
                                checked={mode === 'compare'}
                                onChange={() => setMode('compare')}
                                className="accent-cyan-400 shrink-0"
                            />
                            <span className="font-semibold">Compare variants</span>
                        </label>
                    </div>

                    {/* Select Variants mode */}
                    {mode === 'select' && (
                        <div className="border-t border-cyan-700 pt-3 mb-4">
                            <div className="flex items-center justify-between mb-1">
                                <label className="block text-sm">Variants</label>
                                <button
                                    type="button"
                                    onClick={() => setSelectedVariantIds(
                                        allSelected ? [] : variants.map(v => v.id)
                                    )}
                                    disabled={!selectedProjectId || variants.length === 0}
                                    className="text-xs text-cyan-300 hover:text-cyan-100 disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    {allSelected ? 'Clear all' : 'Select all'}
                                </button>
                            </div>
                            <div className="max-h-44 overflow-y-auto rounded border border-cyan-600 bg-cyan-800 p-2 flex flex-col gap-1">
                                {!selectedProjectId && (
                                    <span className="text-xs text-cyan-300">Select a project first</span>
                                )}
                                {selectedProjectId && variants.length === 0 && (
                                    <span className="text-xs text-cyan-300">No variants available</span>
                                )}
                                {variants.map(v => (
                                    <label key={v.id} className="flex items-center gap-2 text-sm cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={selectedVariantIds.includes(v.id)}
                                            onChange={e => {
                                                setSelectedVariantIds(prev =>
                                                    e.target.checked
                                                        ? [...prev, v.id]
                                                        : prev.filter(id => id !== v.id)
                                                );
                                            }}
                                            className="accent-cyan-400 shrink-0"
                                        />
                                        <span className="truncate">{v.name}</span>
                                    </label>
                                ))}
                            </div>
                            {selectedProjectId && variants.length > 0 && selectedVariantIds.length === 0 && (
                                <p className="text-xs text-amber-300 mt-1">Select at least one variant.</p>
                            )}
                        </div>
                    )}

                    {/* Compare variants mode */}
                    {mode === 'compare' && (
                        <div className="border-t border-cyan-700 pt-3 mb-4">
                            <div className="flex flex-col gap-1.5 mb-3">
                                {([
                                    { value: 'difference', symbol: 'Exclusion', desc: 'Only present in compared variant' },
                                    { value: 'intersection', symbol: 'Intersection', desc: 'common to both variants' },
                                ] as { value: 'difference' | 'intersection'; symbol: string; desc: string }[]).map(op => (
                                    <label key={op.value} className="flex items-center gap-2 text-sm cursor-pointer">
                                        <input
                                            type="radio"
                                            name="compare-operation"
                                            value={op.value}
                                            checked={compareOperation === op.value}
                                            onChange={() => setCompareOperation(op.value)}
                                            className="accent-cyan-400 shrink-0"
                                        />
                                        <span className="font-mono text-xs">{op.symbol}</span>
                                        <span className="text-xs text-cyan-300">— {op.desc}</span>
                                    </label>
                                ))}
                            </div>
                            <label className="block text-sm mb-1">Base variant</label>
                            <select
                                value={compareBaseVariantId}
                                onChange={e => setCompareBaseVariantId(e.target.value)}
                                disabled={!selectedProjectId}
                                className="w-full rounded px-2 py-1 text-sm bg-cyan-800 border border-cyan-600 focus:outline-none focus:border-cyan-400 mb-3 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {variants.map(v => (
                                    <option key={v.id} value={v.id}>{v.name}</option>
                                ))}
                            </select>
                            <label className="block text-sm mb-1">Compare variant</label>
                            <select
                                value={selectedCompareVariantId}
                                onChange={e => setSelectedCompareVariantId(e.target.value)}
                                disabled={!compareBaseVariantId}
                                className="w-full rounded px-2 py-1 text-sm bg-cyan-800 border border-cyan-600 focus:outline-none focus:border-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {variants.filter(v => v.id !== compareBaseVariantId).map(v => (
                                    <option key={v.id} value={v.id}>{v.name}</option>
                                ))}
                            </select>
                            <button
                                type="button"
                                onClick={() => {
                                    const tmp = compareBaseVariantId;
                                    setCompareBaseVariantId(selectedCompareVariantId);
                                    setSelectedCompareVariantId(tmp);
                                }}
                                disabled={!compareBaseVariantId || !selectedCompareVariantId}
                                title="Swap variants"
                                className="mt-2 w-full flex items-center justify-center gap-2 py-1 rounded border border-cyan-600 text-xs text-cyan-300 hover:bg-cyan-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                            >
                                <FontAwesomeIcon icon={faSort} />
                                Swap variants
                            </button>
                        </div>
                    )}

                    {/* Apply button */}
                    <button
                        onClick={handleApply}
                        disabled={applyDisabled}
                        className="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-sm font-semibold transition-colors duration-150"
                        type="button"
                    >
                        Apply
                    </button>
                </div>,
                document.body
            )}
        </>
    );
}

export default ProjectVariantSelector;
