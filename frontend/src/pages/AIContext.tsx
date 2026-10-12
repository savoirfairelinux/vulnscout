import { useState, useEffect, useRef, useCallback, useId } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faRobot, faBook, faFileExport, faFileImport, faChevronDown } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import Variants from "../handlers/variant";
import Context from "../handlers/context";
import Assessments from "../handlers/assessments";
import type { VariantContextData, ContextExport, ImportResult, ContextFile } from "../handlers/context";
import CodebaseReferences from "../components/CodebaseReferences";
import MessageBanner from "../components/MessageBanner";
import ConfirmationModal from "../components/ConfirmationModal";
import { useDocUrl } from "../helpers/useDocUrl";
import HelpPopover from "../components/HelpPopover";
import StrideContextEditor from "../components/StrideContextEditor";
import useDismissablePopover from "../hooks/useDismissablePopover";
import { AGENT_WRITE_EVENT, type AgentViewContext } from "../types/agent";

// Throwing fetch helpers for selector loads (existing handlers swallow HTTP errors)
async function fetchProjectList(): Promise<Project[]> {
    const res = await fetch(import.meta.env.VITE_API_URL + "/api/projects", { mode: "cors" });
    if (!res.ok) throw new Error(`Failed to load projects (${res.status})`);
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    return data.filter((p: any) => typeof p?.id === "string" && typeof p?.name === "string") as Project[];
}

async function fetchVariantList(projectId: string): Promise<Variant[]> {
    const res = await fetch(
        import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/variants`,
        { mode: "cors" }
    );
    if (!res.ok) throw new Error(`Failed to load variants (${res.status})`);
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    return data.filter(
        (v: any) => typeof v?.id === "string" && typeof v?.name === "string" && typeof v?.project_id === "string"
    ) as Variant[];
}

type SaveSnapshot = {
    loadId: number;
    projectId: string;
    variantId: string;
    description: string | null;
    fields: VariantContextData;
};

const CONTEXT_TABS = [
    { id: "context", label: "Context" },
    { id: "threat_model", label: "Threat model" },
    { id: "risks", label: "Risks" },
] as const;
type ContextTab = (typeof CONTEXT_TABS)[number]["id"];

function AIContext({ onAgentContextChange }: Readonly<{ onAgentContextChange?: (context: AgentViewContext) => void }>) {
    const unmountedRef = useRef(false);
    useEffect(() => {
        unmountedRef.current = false;
        return () => { unmountedRef.current = true; };
    }, []);

    const docUrl = useDocUrl("ai-assessments.html");

    // Selectors
    const [projects, setProjects] = useState<Project[]>([]);
    const [variants, setVariants] = useState<Variant[]>([]);
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');
    const [selectedVariantId, setSelectedVariantId] = useState<string>('');
    const [activeTab, setActiveTab] = useState<ContextTab>("context");
    const [editorModeContainer, setEditorModeContainer] = useState<HTMLDivElement | null>(null);
    const tabIdPrefix = useId();
    const tabRefs = useRef<Partial<Record<ContextTab, HTMLButtonElement | null>>>({});
    const activateTab = (tab: ContextTab) => {
        setActiveTab(tab);
        tabRefs.current[tab]?.focus();
    };
    useEffect(() => {
        onAgentContextChange?.({
            section: activeTab,
            selectedProjectId,
            selectedProjectName: projects.find(project => project.id === selectedProjectId)?.name,
            selectedVariantId,
            selectedVariantName: variants.find(variant => variant.id === selectedVariantId)?.name,
        });
    }, [activeTab, selectedProjectId, selectedVariantId, projects, variants, onAgentContextChange]);

    // Form fields
    const [description, setDescription] = useState<string>('');
    const [variantDescription, setVariantDescription] = useState<string>('');
    const [codebasePaths, setCodebasePaths] = useState<string[]>(['']);
    const [contextFiles, setContextFiles] = useState<{ variantId: string; files: ContextFile[] }>({ variantId: '', files: [] });
    const [environment, setEnvironment] = useState<string>('');
    const [threatModel, setThreatModel] = useState<string>('');
    const [risks, setRisks] = useState<string>('');
    const [otherInfo, setOtherInfo] = useState<string>('');
    // Reset structured drafts on external context loads, not on local edits or saves.
    const [contextEditorVersion, setContextEditorVersion] = useState(0);

    // UI state
    const [busy, setBusy] = useState(false);
    const [variantContextLoading, setVariantContextLoading] = useState(false);
    // Without a successful load there is no baseline to diff against, and the
    // fields were cleared, so saving would both skip the outdating check and
    // overwrite the stored context with blanks.
    const [variantContextLoadFailed, setVariantContextLoadFailed] = useState(false);
    // Same reasoning as variantContextLoadFailed, for the project description.
    const [projectContextLoadFailed, setProjectContextLoadFailed] = useState(false);
    const [confirmOutdate, setConfirmOutdate] = useState(false);
    // Variant fields as last loaded or saved, to detect whether a save changes anything.
    const savedVariantFieldsRef = useRef<VariantContextData | null>(null);
    // Project description as last loaded or saved, to detect whether a save changes anything.
    const savedDescriptionRef = useRef<string | null>(null);
    const variantLoadIdRef = useRef(0);
    // The selection a pending confirmation belongs to, so confirming cannot save
    // whatever happens to be selected by then.
    const pendingSaveRef = useRef<SaveSnapshot | null>(null);
    const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
    const [bannerMsg, setBannerMsg] = useState<ReactNode>('');
    const [bannerType, setBannerType] = useState<'success' | 'error'>('success');
    const [bannerVisible, setBannerVisible] = useState(false);

    // Import/Export state
    const [exportMenuOpen, setExportMenuOpen] = useState(false);
    const [exportSelection, setExportSelection] = useState<Set<string>>(new Set());
    const [ioBusy, setIoBusy] = useState(false);
    const [importDetails, setImportDetails] = useState<ImportResult | null>(null);
    const exportMenuRef = useRef<HTMLDivElement | null>(null);
    const importInputRef = useRef<HTMLInputElement | null>(null);

    const showBanner = (msg: ReactNode, type: 'success' | 'error') => {
        setBannerMsg(msg);
        setBannerType(type);
        setBannerVisible(true);
    };

    // Load projects on mount
    useEffect(() => {
        fetchProjectList().then(ps => {
            if (!unmountedRef.current) setProjects(ps);
        }).catch((e: any) => {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to load projects.", "error");
        });
     
    }, []);

    // Load all variants for the export selector (lazily, when the menu first opens)
    const [allVariantsLoaded, setAllVariantsLoaded] = useState(false);
    const loadAllVariants = useCallback(() => {
        if (allVariantsLoaded) return;
        Variants.listAll().then(vs => {
            if (unmountedRef.current) return;
            setAllVariants(vs);
            setAllVariantsLoaded(true);
        }).catch((e: any) => {
            // Leave allVariantsLoaded false so reopening the menu retries.
            if (!unmountedRef.current)
                showBanner(e?.message || "Failed to load variants for export.", "error");
        });
    }, [allVariantsLoaded]);

    const clearVariantFields = () => {
        setVariantDescription('');
        setCodebasePaths(['']);
        setContextFiles({ variantId: '', files: [] });
        setEnvironment('');
        setThreatModel('');
        setRisks('');
        setOtherInfo('');
        setContextEditorVersion(version => version + 1);
    };

    // Load variants when project changes
    useEffect(() => {
        setVariants([]);
        setSelectedVariantId('');
        clearVariantFields();
        if (!selectedProjectId) return;
        fetchVariantList(selectedProjectId).then(vs => {
            if (!unmountedRef.current) setVariants(vs);
        }).catch((e: any) => {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to load variants.", "error");
        });
     
    }, [selectedProjectId]);

    // The project description is project-bound, so it is loaded only when the project
    // changes. Reloading it on every variant change would discard unsaved edits.
    const loadProjectContext = useCallback(() => {
        setProjectContextLoadFailed(false);
        if (!selectedProjectId) return;
        Context.getProject(selectedProjectId)
            .then(ctx => {
                if (unmountedRef.current) return;
                savedDescriptionRef.current = ctx.description ?? null;
                setDescription(ctx.description ?? '');
            }).catch((e: any) => {
                if (!unmountedRef.current) {
                    setProjectContextLoadFailed(true);
                    showBanner(e?.message || "Failed to load project context.", "error");
                }
            });
    }, [selectedProjectId]);

    useEffect(() => {
        loadProjectContext();
    }, [loadProjectContext]);

    // Variant-bound fields only. The merged endpoint also returns the project
    // description; it is deliberately ignored here.
    const loadVariantContext = useCallback(() => {
        const loadId = ++variantLoadIdRef.current;
        savedVariantFieldsRef.current = null;
        clearVariantFields();
        setVariantContextLoadFailed(false);
        if (!selectedProjectId || !selectedVariantId) {
            setVariantContextLoading(false);
            return;
        }
        setVariantContextLoading(true);
        Context.get(selectedProjectId, selectedVariantId)
            .then(ctx => {
                if (unmountedRef.current || loadId !== variantLoadIdRef.current) return;
                savedVariantFieldsRef.current = {
                    variant_description: ctx.variant_description ?? null,
                    codebase_path: ctx.codebase_path ?? null,
                    environment: ctx.environment ?? null,
                    threat_model: ctx.threat_model ?? null,
                    risks: ctx.risks ?? null,
                    other_info: ctx.other_info ?? null,
                };
                setVariantDescription(ctx.variant_description ?? '');
                setCodebasePaths(ctx.codebase_path?.split(';') ?? ['']);
                setContextFiles({ variantId: selectedVariantId, files: ctx.files ?? [] });
                setEnvironment(ctx.environment ?? '');
                setThreatModel(ctx.threat_model ?? '');
                setRisks(ctx.risks ?? '');
                setOtherInfo(ctx.other_info ?? '');
                setContextEditorVersion(version => version + 1);
            }).catch((e: any) => {
                if (!unmountedRef.current && loadId === variantLoadIdRef.current) {
                    setVariantContextLoadFailed(true);
                    showBanner(e?.message || "Failed to load context.", "error");
                }
            }).finally(() => {
                if (!unmountedRef.current && loadId === variantLoadIdRef.current)
                    setVariantContextLoading(false);
            });
    }, [selectedProjectId, selectedVariantId]);

    useEffect(() => {
        loadVariantContext();
    }, [loadVariantContext]);

    const validate = (): boolean => {
        const errors: Record<string, string> = {};
        if (!description.trim()) {
            errors.description = "Project Description is required.";
        }
        if (selectedVariantId && !threatModel.trim()) {
            errors.threatModel = "Threat Model is required.";
        }
        setValidationErrors(errors);
        if (errors.description) activateTab("context");
        else if (errors.threatModel) activateTab("threat_model");
        return Object.keys(errors).length === 0;
    };

    const currentVariantFields = (): VariantContextData => ({
        variant_description: variantDescription.trim() || null,
        codebase_path: codebasePaths.filter(path => path.trim()).join(';').trim() || null,
        environment: environment.trim() || null,
        threat_model: threatModel.trim() || null,
        risks: risks.trim() || null,
        other_info: otherInfo.trim() || null,
    });

    // Agent updates reload only clean forms, so unsaved edits are never replaced.
    const agentRefreshRef = useRef<(tool?: string) => void>(() => undefined);
    useEffect(() => {
        agentRefreshRef.current = (tool?: string) => {
            if (tool === 'update_project_context') {
                if ((description.trim() || null) === savedDescriptionRef.current) loadProjectContext();
                else showBanner("The agent updated the project description. Your unsaved edits were kept; saving replaces the agent's change.", "error");
            }
            if (tool === 'update_variant_context') {
                const saved = savedVariantFieldsRef.current;
                const fields = currentVariantFields();
                if (saved === null || (Object.keys(fields) as (keyof VariantContextData)[]).every(k => fields[k] === saved[k]))
                    loadVariantContext();
                else showBanner("The agent updated the variant context. Your unsaved edits were kept; saving replaces the agent's change.", "error");
            }
        };
    });
    useEffect(() => {
        const refresh = (event: Event) => agentRefreshRef.current((event as CustomEvent<{ tool?: string }>).detail?.tool);
        window.addEventListener(AGENT_WRITE_EVENT, refresh);
        return () => window.removeEventListener(AGENT_WRITE_EVENT, refresh);
    }, []);

    // Editing the variant context marks every pending AI assessment of that variant
    // as outdated, and editing the project description does the same for every
    // variant in the project, so ask first when the save would actually change
    // either one.
    const handleSave = async () => {
        if (!selectedProjectId || busy || variantContextLoading) return;
        if (selectedVariantId && variantContextLoadFailed) return;
        if (projectContextLoadFailed) return;
        if (!validate()) return;
        const saved = savedVariantFieldsRef.current;
        const fields = currentVariantFields();
        const snapshot: SaveSnapshot = {
            loadId: variantLoadIdRef.current,
            projectId: selectedProjectId,
            variantId: selectedVariantId,
            description: description.trim() || null,
            fields,
        };
        const variantChanged = !!selectedVariantId && saved !== null
            && (Object.keys(fields) as (keyof VariantContextData)[]).some(k => fields[k] !== saved[k]);
        const descriptionChanged = savedDescriptionRef.current !== null
            && snapshot.description !== savedDescriptionRef.current;
        if (descriptionChanged || variantChanged) {
            let hasPendingAi = true;
            try {
                // A project-description change outdates every variant in the
                // project, not just the one selected, so check project-wide.
                hasPendingAi = descriptionChanged
                    ? (await Assessments.listForReview(undefined, snapshot.projectId, 'ai')).length > 0
                    : (await Assessments.listForReview(selectedVariantId, undefined, 'ai')).length > 0;
            } catch {
                // Could not check: warn anyway rather than silently outdating assessments.
            }
            // The selection may have moved on while the check was in flight; its
            // answer says nothing about whatever is selected now.
            if (unmountedRef.current || snapshot.loadId !== variantLoadIdRef.current) return;
            if (hasPendingAi) {
                pendingSaveRef.current = snapshot;
                setConfirmOutdate(true);
                return;
            }
        }
        await performSave(snapshot);
    };

    const performSave = async (snapshot: SaveSnapshot) => {
        setBusy(true);
        try {
            await Context.saveProject(snapshot.projectId, snapshot.description);
            if (snapshot.loadId === variantLoadIdRef.current) savedDescriptionRef.current = snapshot.description;
        } catch (e: any) {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to save project context.", "error");
            setBusy(false);
            return;
        }
        if (snapshot.variantId) {
            const fields = snapshot.fields;
            try {
                await Context.saveVariant(snapshot.variantId, fields);
                if (snapshot.loadId === variantLoadIdRef.current) savedVariantFieldsRef.current = fields;
            } catch (e: any) {
                if (!unmountedRef.current)
                    showBanner(
                        `Project context saved, but variant context failed: ${e?.message ?? "unknown error"}`,
                        "error"
                    );
                setBusy(false);
                return;
            }
        }
        if (!unmountedRef.current) {
            showBanner(
                <>
                    Context saved successfully.
                </>,
                "success"
            );
            setBusy(false);
        }
    };

    const handleFileDownload = (document_: ContextExport, filename: string) => {
        const blob = new Blob([JSON.stringify(document_, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const handleExportSelected = async () => {
        if (ioBusy || exportSelection.size === 0) return;
        setIoBusy(true);
        try {
            const doc = await Context.exportSelected([...exportSelection]);
            handleFileDownload(doc, "vulnscout-context.json");
            if (!unmountedRef.current) setExportMenuOpen(false);
        } catch (e: any) {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to export context.", "error");
        } finally {
            if (!unmountedRef.current) setIoBusy(false);
        }
    };

    const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        e.target.value = '';
        if (!file || ioBusy) return;
        setIoBusy(true);
        setImportDetails(null);
        try {
            const text = await file.text();
            let parsed: unknown;
            try {
                parsed = JSON.parse(text);
            } catch {
                throw new Error("The selected file is not valid JSON.");
            }
            const result = await Context.importContext(parsed);
            if (unmountedRef.current) return;
            setImportDetails(result);
            const total = result.imported.length + result.ignored.length + result.failed.length;
            const msg =
                `Import complete: ${result.imported.length} of ${total} imported, ` +
                `${result.ignored.length} ignored, ${result.failed.length} failed.`;
            showBanner(msg, result.failed.length > 0 ? "error" : "success");
            // Import overwrites stored context, so both scopes are reloaded.
            loadProjectContext();
            loadVariantContext();
        } catch (err: any) {
            if (!unmountedRef.current) showBanner(err?.message || "Import failed.", "error");
        } finally {
            if (!unmountedRef.current) setIoBusy(false);
        }
    };

    const toggleExportVariant = (variantId: string) => {
        setExportSelection(prev => {
            const next = new Set(prev);
            if (next.has(variantId)) next.delete(variantId);
            else next.add(variantId);
            return next;
        });
    };

    const selectAllExport = () => setExportSelection(new Set(allVariants.map(v => v.id)));
    const clearAllExport = () => setExportSelection(new Set());

    // Close the export menu on outside click
    useDismissablePopover(exportMenuOpen, exportMenuRef, useCallback(() => setExportMenuOpen(false), []), { closeOnEscape: false });

    const variantSelected = Boolean(selectedVariantId) && !variantContextLoading;
    const projectSelected = Boolean(selectedProjectId);
    const labelClass = "block text-sm text-zinc-300 mb-1";
    const inputClass =
        "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
    const textareaClass = inputClass + " resize-y min-h-[80px]";
    const selectClass =
        "rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
    const btnPrimary =
        "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
    const btnSecondary =
        "rounded px-3 py-1.5 text-sm border border-slate-500 text-cyan-300 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
    const btnTransfer =
        "bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
    const cardHeader =
        "bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60";
    const cardBody =
        "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 shadow-lg shadow-black/20 space-y-4";

    return (
        <div className="w-full space-y-6">
            {bannerVisible && (
                <div className="sticky top-0 z-10">
                    <MessageBanner
                        type={bannerType}
                        message={bannerMsg}
                        isVisible={bannerVisible}
                        onClose={() => setBannerVisible(false)}
                    />
                </div>
            )}

            <div className="flex items-center gap-4">
                <h1 className="text-3xl font-bold text-white mb-2">AI Assessment Context</h1>
                <a
                    href={docUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="documentation"
                    title="Open documentation"
                    className="text-white hover:text-blue-300 transition-colors"
                    >
                    <FontAwesomeIcon icon={faBook} size='lg' />
                </a>

                {/* Import / Export controls */}
                <div className="ml-auto flex items-center gap-2">
                    <button
                        type="button"
                        aria-label="Import context"
                        onClick={() => importInputRef.current?.click()}
                        disabled={ioBusy}
                        className={btnTransfer}
                    >
                        <FontAwesomeIcon icon={faFileImport} />
                        Import
                    </button>
                    <input
                        ref={importInputRef}
                        type="file"
                        accept="application/json,.json"
                        aria-label="Import context file"
                        className="hidden"
                        onChange={handleImportFile}
                    />
                    <div className="relative" ref={exportMenuRef}>
                        <button
                            type="button"
                            aria-label="Export context"
                            aria-haspopup="true"
                            aria-expanded={exportMenuOpen}
                            onClick={() => setExportMenuOpen(o => { const next = !o; if (next) loadAllVariants(); return next; })}
                            disabled={ioBusy}
                            className={btnTransfer}
                        >
                            <FontAwesomeIcon icon={faFileExport} />
                            Export
                            <FontAwesomeIcon icon={faChevronDown} size="xs" />
                        </button>
                        {exportMenuOpen && (
                            <div
                                role="menu"
                                className="absolute right-0 z-20 mt-2 w-72 max-h-96 overflow-auto rounded-lg bg-slate-800 border border-slate-600 shadow-xl shadow-black/40 p-3"
                            >
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-semibold text-white">Select variants</span>
                                    <div className="flex gap-2 text-xs">
                                        <button type="button" onClick={selectAllExport} className="text-cyan-400 hover:text-cyan-300">All</button>
                                        <button type="button" onClick={clearAllExport} className="text-cyan-400 hover:text-cyan-300">None</button>
                                    </div>
                                </div>
                                {projects.length === 0 && (
                                    <p className="text-xs text-zinc-400">No projects available.</p>
                                )}
                                {projects.map(p => {
                                    const pv = allVariants.filter(v => v.project_id === p.id);
                                    return (
                                        <div key={p.id} className="mb-2">
                                            <p className="text-xs font-semibold text-zinc-300 mb-1">{p.name}</p>
                                            {pv.length === 0 ? (
                                                <p className="text-xs text-zinc-500 pl-2">No variants</p>
                                            ) : pv.map(v => (
                                                <label key={v.id} className="flex items-center gap-2 pl-2 py-0.5 text-sm text-zinc-200 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        aria-label={`Export ${p.name} / ${v.name}`}
                                                        checked={exportSelection.has(v.id)}
                                                        onChange={() => toggleExportVariant(v.id)}
                                                    />
                                                    {v.name}
                                                </label>
                                            ))}
                                        </div>
                                    );
                                })}
                                <button
                                    type="button"
                                    onClick={handleExportSelected}
                                    disabled={ioBusy || exportSelection.size === 0}
                                    className={btnPrimary + " w-full mt-2 flex items-center justify-center gap-2"}
                                >
                                    {ioBusy && <FontAwesomeIcon icon={faSpinner} spin />}
                                    Export selected ({exportSelection.size})
                                </button>
                            </div>
                        )}
                    </div>
                    <HelpPopover ariaLabel="Import help" role="tooltip" buttonClassName="text-sky-300 hover:text-sky-100" surfaceClassName="w-[320px] p-3">
                        Importing overwrites the existing context for each matching
                        project/variant. Variants whose project or variant does not exist
                        are ignored; variants missing mandatory fields (description, threat
                        model) fail. Accepts an exported file, whose projects each nest
                        their variants. Uploaded codebase references are not included
                        in context JSON transfers.
                    </HelpPopover>
                </div>
            </div>

            {importDetails && (importDetails.ignored.length > 0 || importDetails.failed.length > 0) && (
                <div className="rounded-lg bg-slate-800/60 border border-slate-600 p-3 text-sm">
                    {importDetails.failed.length > 0 && (
                        <div className="mb-2">
                            <p className="font-semibold text-red-400">Failed ({importDetails.failed.length})</p>
                            <ul className="list-disc list-inside text-zinc-300">
                                {importDetails.failed.map((it, i) => (
                                    <li key={`f-${i}`}>{it.project_name ?? '—'} / {it.variant_name ?? '—'}: {it.reason}</li>
                                ))}
                            </ul>
                        </div>
                    )}
                    {importDetails.ignored.length > 0 && (
                        <div>
                            <p className="font-semibold text-yellow-400">Ignored ({importDetails.ignored.length})</p>
                            <ul className="list-disc list-inside text-zinc-300">
                                {importDetails.ignored.map((it, i) => (
                                    <li key={`i-${i}`}>{it.project_name ?? '—'} / {it.variant_name ?? '—'}: {it.reason}</li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
            )}
            <div>
                <div className={cardHeader}>
                    <FontAwesomeIcon icon={faRobot} className="text-cyan-400" />
                    <h2 className="text-xl font-bold text-white">Assessment context</h2>
                </div>
                <div className={cardBody}>

                    <div className="grid gap-4 sm:grid-cols-2">
                        {/* Project selector */}
                        <div>
                            <label className={labelClass} htmlFor="ai-project-select">Project</label>
                            <select
                                id="ai-project-select"
                                aria-label="Project"
                                className={selectClass + " w-full"}
                                value={selectedProjectId}
                                onChange={e => setSelectedProjectId(e.target.value)}
                            >
                                <option value="">— Select project —</option>
                                {projects.map(p => (
                                    <option key={p.id} value={p.id}>{p.name}</option>
                                ))}
                            </select>
                            {projectSelected && projectContextLoadFailed && (
                                <p className="text-red-500 text-xs mt-1 flex items-center gap-2">
                                    Could not load this project&apos;s context. Saving is disabled until it loads.
                                    <button
                                        type="button"
                                        onClick={loadProjectContext}
                                        className="underline hover:text-red-400"
                                    >
                                        Retry
                                    </button>
                                </p>
                            )}
                        </div>

                        {/* Variant selector */}
                        <div>
                            <label className={labelClass} htmlFor="ai-variant-select">Variant</label>
                            <select
                                id="ai-variant-select"
                                aria-label="Variant"
                                className={selectClass + " w-full"}
                                value={selectedVariantId}
                                onChange={e => setSelectedVariantId(e.target.value)}
                                disabled={!projectSelected || variants.length === 0}
                            >
                                <option value="">— Select variant —</option>
                                {variants.map(v => (
                                    <option key={v.id} value={v.id}>{v.name}</option>
                                ))}
                            </select>
                            {variantSelected && variantContextLoadFailed && (
                                <p className="text-red-500 text-xs mt-1 flex items-center gap-2">
                                    Could not load this variant&apos;s context. Saving is disabled until it loads.
                                    <button
                                        type="button"
                                        onClick={loadVariantContext}
                                        className="underline hover:text-red-400"
                                    >
                                        Retry
                                    </button>
                                </p>
                            )}
                        </div>
                    </div>

                    <div role="tablist" aria-label="AI context sections" className="flex flex-wrap gap-1 border-b border-slate-600 p-1 pb-2">
                        {CONTEXT_TABS.map((tab, index) => (
                            <button
                                key={tab.id}
                                ref={element => { tabRefs.current[tab.id] = element; }}
                                type="button"
                                role="tab"
                                id={`${tabIdPrefix}-${tab.id}-tab`}
                                aria-controls={`${tabIdPrefix}-${tab.id}-panel`}
                                aria-selected={activeTab === tab.id}
                                tabIndex={activeTab === tab.id ? 0 : -1}
                                className={`rounded-md px-4 py-2 text-sm font-semibold whitespace-nowrap transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
                                    activeTab === tab.id ? "bg-sky-900 text-white" : "text-slate-300 hover:bg-slate-700 hover:text-white"
                                }`}
                                onClick={() => activateTab(tab.id)}
                                onKeyDown={event => {
                                    let next: number;
                                    if (event.key === "ArrowRight") next = (index + 1) % CONTEXT_TABS.length;
                                    else if (event.key === "ArrowLeft") next = (index + CONTEXT_TABS.length - 1) % CONTEXT_TABS.length;
                                    else if (event.key === "Home") next = 0;
                                    else if (event.key === "End") next = CONTEXT_TABS.length - 1;
                                    else return;
                                    event.preventDefault();
                                    activateTab(CONTEXT_TABS[next].id);
                                }}
                            >{tab.label}</button>
                        ))}
                    </div>

                    <div
                        role="tabpanel"
                        id={`${tabIdPrefix}-context-panel`}
                        aria-labelledby={`${tabIdPrefix}-context-tab`}
                        hidden={activeTab !== "context"}
                        tabIndex={0}
                        className="space-y-4"
                    >
                        {/* Project Description */}
                        <div>
                            <label className={labelClass} htmlFor="ai-project-description">
                                Project Description <span className="text-red-500">*</span>
                            </label>
                            <textarea
                                id="ai-project-description"
                                aria-label="Project Description"
                                className={textareaClass}
                                value={description}
                                onChange={e => setDescription(e.target.value)}
                                disabled={!projectSelected}
                                placeholder={projectSelected ? "Describe your project..." : "Select a project first"}
                                aria-invalid={Boolean(validationErrors.description)}
                                aria-describedby={validationErrors.description ? `${tabIdPrefix}-description-error` : undefined}
                            />
                            {validationErrors.description && (
                                <p id={`${tabIdPrefix}-description-error`} role="alert" className="text-red-500 text-xs mt-1">
                                    {validationErrors.description}
                                </p>
                            )}
                        </div>

                        {/* Variant Description */}
                        <div>
                            <label className={labelClass} htmlFor="ai-variant-description">Variant Description</label>
                            <textarea
                                id="ai-variant-description"
                                aria-label="Variant Description"
                                className={textareaClass}
                                value={variantDescription}
                                onChange={e => setVariantDescription(e.target.value)}
                                disabled={!variantSelected}
                                placeholder={variantSelected ? "Describe this variant..." : "Select a variant to enable"}
                            />
                        </div>

                        <fieldset disabled={!variantSelected}
                            aria-describedby={`${tabIdPrefix}-codebase-help`}>
                            <legend className={labelClass}>Codebase Paths</legend>
                            <p id={`${tabIdPrefix}-codebase-help`} className="text-xs text-zinc-400 mb-1">
                                Source code locations visible to external assessment tools. Paths do not mount host
                                directories into the container; use Codebase References for the embedded Agent.
                            </p>
                            <div className="space-y-3">
                                {codebasePaths.map((path, index) => (
                                    <div key={index} className="flex flex-col gap-2 sm:flex-row sm:items-end">
                                        <div className="min-w-0 flex-1">
                                            <label className={labelClass} htmlFor={`${tabIdPrefix}-codebase-${index}`}>
                                                Codebase Path {index + 1}
                                            </label>
                                            <input
                                                id={`${tabIdPrefix}-codebase-${index}`}
                                                type="text" className={inputClass} value={path}
                                                onChange={event => {
                                                    const value = event.target.value;
                                                    setCodebasePaths(paths =>
                                                        paths.map((path, row) => row === index ? value : path));
                                                }}
                                                placeholder={variantSelected ? "e.g. /home/user/src/myproject" : "Select a variant to enable"}
                                            />
                                        </div>
                                        <button type="button" className={btnSecondary + " shrink-0 self-start sm:self-auto"}
                                            aria-label={`Remove Codebase Path ${index + 1}`}
                                            onClick={() => setCodebasePaths(paths => paths.filter((_, row) => row !== index))}
                                        >Remove Codebase Path</button>
                                    </div>
                                ))}
                                <button type="button" className={btnSecondary}
                                    onClick={() => setCodebasePaths(paths => [...paths, ''])}
                                >Add Codebase Path</button>
                            </div>
                        </fieldset>

                        <CodebaseReferences
                            key={`${selectedProjectId}/${selectedVariantId}`}
                            variantId={selectedVariantId}
                            initialFiles={contextFiles.variantId === selectedVariantId ? contextFiles.files : []}
                            disabled={!variantSelected || contextFiles.variantId !== selectedVariantId || variantContextLoadFailed || busy || ioBusy}
                            notify={showBanner}
                        />

                        {/* Environment */}
                        <div>
                            <label className={labelClass} htmlFor="ai-environment">Environment</label>
                            <p id={`${tabIdPrefix}-environment-help`} className="text-xs text-zinc-400 mb-1">
                                Describe the target platform, operating system and deployment conditions.
                            </p>
                            <textarea
                                id="ai-environment"
                                aria-label="Environment"
                                aria-describedby={`${tabIdPrefix}-environment-help`}
                                className={textareaClass}
                                value={environment}
                                onChange={e => setEnvironment(e.target.value)}
                                disabled={!variantSelected}
                                placeholder={variantSelected ? "e.g. runtime environment details" : "Select a variant to enable"}
                            />
                        </div>

                        <div ref={setEditorModeContainer} />

                        {/* Other Information */}
                        <div>
                            <label className={labelClass} htmlFor="ai-other-info">Other Information</label>
                            <textarea
                                id="ai-other-info"
                                aria-label="Other Information"
                                className={textareaClass}
                                value={otherInfo}
                                onChange={e => setOtherInfo(e.target.value)}
                                disabled={!variantSelected}
                                placeholder={variantSelected ? "Any additional context..." : "Select a variant to enable"}
                            />
                        </div>
                    </div>

                    <div hidden={activeTab === "context"}>
                        <StrideContextEditor
                            key={`${selectedVariantId}:${contextEditorVersion}`}
                            activeSection={activeTab === "risks" ? "risks" : "threat_model"}
                            tabIdPrefix={tabIdPrefix}
                            modeContainer={editorModeContainer}
                            threatModel={threatModel}
                            risks={risks}
                            disabled={!variantSelected}
                            error={validationErrors.threatModel}
                            onChange={text => { setThreatModel(text.threatModel); setRisks(text.risks); }}
                        />
                    </div>

                    <ConfirmationModal
                        isOpen={confirmOutdate}
                        title="Mark AI assessments as outdated?"
                        message="Saving this context will mark all pending AI assessments as outdated, because they were generated before the context changed. They remain outdated until they are regenerated."
                        confirmText="Save and mark outdated"
                        cancelText="Cancel"
                        showTitleIcon={true}
                        onConfirm={() => {
                            setConfirmOutdate(false);
                            const snapshot = pendingSaveRef.current;
                            pendingSaveRef.current = null;
                            if (snapshot) void performSave(snapshot);
                        }}
                        onCancel={() => { pendingSaveRef.current = null; setConfirmOutdate(false); }}
                    />

                    {/* Save */}
                    <div className="flex items-center gap-3 border-t border-slate-700 pt-4">
                        <button
                            type="button"
                            onClick={handleSave}
                            disabled={!projectSelected || busy || variantContextLoading
                                || (variantSelected && variantContextLoadFailed) || projectContextLoadFailed}
                            className={btnPrimary + " flex items-center gap-2"}
                        >
                            {busy && <FontAwesomeIcon icon={faSpinner} spin />}
                            Save
                        </button>
                        <p className="text-xs text-zinc-400">Saves all sections.</p>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default AIContext;
