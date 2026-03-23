import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faLayerGroup, faChevronDown } from '@fortawesome/free-solid-svg-icons';
import Projects from '../handlers/project';
import type { Project } from '../handlers/project';
import Variants from '../handlers/variant';
import type { Variant } from '../handlers/variant';

const greenTheme = true;
const bgHoverColor = greenTheme ? 'hover:bg-cyan-700' : 'dark:hover:bg-neutral-700';
const bgActiveColor = greenTheme ? 'bg-cyan-900' : 'dark:bg-neutral-800';

type Props = {
    defaultProject?: { id: string; name: string } | null;
    defaultVariant?: { id: string; name: string } | null;
    onApply: (projectId: string, variantId: string) => void;
};

function ProjectVariantSelector({ defaultProject, defaultVariant, onApply }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const buttonRef = useRef<HTMLButtonElement>(null);
    const panelRef = useRef<HTMLDivElement>(null);

    const [projects, setProjects] = useState<Project[]>([]);
    const [variants, setVariants] = useState<Variant[]>([]);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');
    const [selectedVariantId, setSelectedVariantId] = useState<string>('');

    // Applied (display) state — initialised from props when they arrive
    const [appliedProject, setAppliedProject] = useState<string>('');
    const [appliedVariant, setAppliedVariant] = useState<string>('');

    // Sync display state when default config arrives from the server
    useEffect(() => {
        if (defaultProject?.id) {
            setSelectedProjectId(defaultProject.id);
            setAppliedProject(defaultProject.name);
        }
    }, [defaultProject?.id, defaultProject?.name]);

    useEffect(() => {
        if (defaultVariant?.id) {
            setSelectedVariantId(defaultVariant.id);
            setAppliedVariant(defaultVariant.name);
        } else if (defaultProject?.id) {
            setSelectedVariantId('');
            setAppliedVariant('All variants');
        }
    }, [defaultVariant?.id, defaultVariant?.name, defaultProject?.id]);

    // Track previous project id to avoid clearing variant on initial default load
    const prevProjectIdRef = useRef("");

    // Load projects on mount
    useEffect(() => {
        Projects.list()
            .then(setProjects)
            .catch(() => setProjects([]));
    }, []);

    // Load variants when selected project changes; only clear variant on user-driven changes
    useEffect(() => {
        setVariants([]);
        if (!selectedProjectId) return;
        const prev = prevProjectIdRef.current;
        prevProjectIdRef.current = selectedProjectId;
        if (prev !== '' && prev !== selectedProjectId) {
            setSelectedVariantId('');
        }
        Variants.list(selectedProjectId)
            .then(setVariants)
            .catch(() => setVariants([]));
    }, [selectedProjectId]);

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

    const handleApply = () => {
        const project = projects.find(p => p.id === selectedProjectId);
        const variant = variants.find(v => v.id === selectedVariantId);
        setAppliedProject(project?.name ?? '');
        setAppliedVariant(selectedVariantId ? (variant?.name ?? '') : (selectedProjectId ? 'All variants' : ''));
        onApply(selectedProjectId, selectedVariantId);
        setIsOpen(false);
    };

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
                        {appliedVariant || (appliedProject ? 'All variants' : 'No variant')}
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

                    {/* Variant select */}
                    <label className="block text-sm mb-1">Variant</label>
                    <select
                        value={selectedVariantId}
                        onChange={e => setSelectedVariantId(e.target.value)}
                        disabled={!selectedProjectId}
                        className="w-full rounded px-2 py-1 text-sm bg-cyan-800 border border-cyan-600 focus:outline-none focus:border-cyan-400 mb-4 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <option value="">— All variants —</option>
                        {variants.map(v => (
                            <option key={v.id} value={v.id}>{v.name}</option>
                        ))}
                    </select>

                    {/* Apply button */}
                    <button
                        onClick={handleApply}
                        disabled={!selectedProjectId}
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
