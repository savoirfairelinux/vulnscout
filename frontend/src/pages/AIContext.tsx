import { useState, useEffect, useRef, useCallback, useId } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faRobot, faBook, faFileExport, faFileImport, faChevronDown } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import Variants from "../handlers/variant";
import Context from "../handlers/context";
import Assessments from "../handlers/assessments";
import type { ContextExport, ImportResult, ContextFile } from "../handlers/context";
import CodebaseReferences from "../components/CodebaseReferences";
import MessageBanner from "../components/MessageBanner";
import ConfirmationModal from "../components/ConfirmationModal";
import HelpPopover from "../components/HelpPopover";
import ScopedTextEditor from "../components/ScopedTextEditor";
import VariantScopeSelector from "../components/VariantScopeSelector";
import StrideContextEditor from "../components/StrideContextEditor";
import { useDocUrl } from "../helpers/useDocUrl";
import { THREAT_MODEL_FIELDS } from "../helpers/strideContext";
import type { StrideEditorMode } from "../helpers/strideContext";
import {
    COLLECTIONS, CONTEXT_FIELDS, SYSTEM_FIELDS, emptySharedContext,
    mergeSavedSection, nextSharedId, sharedDraft, updateSharedDraft,
} from "../helpers/sharedContext";
import type {
    ScopedText, SharedContext, SharedContextResponse, SharedSection, TextCollection, TextField,
} from "../helpers/sharedContext";
import useDismissablePopover from "../hooks/useDismissablePopover";
import { AGENT_WRITE_EVENT, type AgentViewContext } from "../types/agent";

const TABS = [
    { id: "context", label: "Context" }, { id: "system", label: "System" },
    { id: "threat_model", label: "Threat model" }, { id: "risks", label: "Risks" }, { id: "summary", label: "Summary" },
] as const;
type Tab = (typeof TABS)[number]["id"];
type SaveSnapshot = {
    section: SharedSection; loadId: number; projectId: string; context: SharedContext;
    description: string | null; revision: number;
};
const labelClass = "block text-sm text-zinc-300 mb-1";
const inputClass = "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40";
const primaryClass = "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed";
const secondaryClass = "rounded px-3 py-1.5 text-sm border border-slate-500 text-cyan-300 hover:bg-slate-700 disabled:opacity-40";
const transferClass = "bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5 disabled:opacity-40";
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "The context operation failed.";
const isTextField = (key: TextField | TextCollection): key is TextField =>
    CONTEXT_FIELDS.some(field => field === key) || SYSTEM_FIELDS.some(field => field === key);

export default function AIContext({ onAgentContextChange }: Readonly<{
    onAgentContextChange?: (context: AgentViewContext) => void;
}>) {
    const docUrl = useDocUrl("ai-assessments.html");
    const id = useId();
    const mounted = useRef(true);
    const loadId = useRef(0);
    const [projects, setProjects] = useState<Project[]>([]);
    const [projectId, setProjectId] = useState("");
    const [referenceVariantId, setReferenceVariantId] = useState("");
    const [referenceFiles, setReferenceFiles] = useState<ContextFile[] | null>(null);
    const [referenceError, setReferenceError] = useState("");
    const [referenceReload, setReferenceReload] = useState(0);
    const [activeTab, setActiveTab] = useState<Tab>("context");
    const tabRefs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});
    const [saved, setSaved] = useState<SharedContextResponse | null>(null);
    const [draft, setDraft] = useState<SharedContext | null>(null);
    const [description, setDescription] = useState("");
    const [loading, setLoading] = useState(false);
    const [busy, setBusy] = useState(false);
    const [loadFailed, setLoadFailed] = useState(false);
    const [banner, setBanner] = useState<{ message: ReactNode; type: "success" | "error" } | null>(null);
    const [confirmOutdate, setConfirmOutdate] = useState(false);
    const [confirmReload, setConfirmReload] = useState(false);
    const pendingSave = useRef<SaveSnapshot | null>(null);
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [exportLoaded, setExportLoaded] = useState(false);
    const [exportMenuOpen, setExportMenuOpen] = useState(false);
    const [exportSelection, setExportSelection] = useState<Set<string>>(new Set());
    const [ioBusy, setIoBusy] = useState(false);
    const [importDetails, setImportDetails] = useState<ImportResult | null>(null);
    const exportMenuRef = useRef<HTMLDivElement | null>(null);
    const importInputRef = useRef<HTMLInputElement | null>(null);
    const dirty = !!saved && (JSON.stringify(draft) !== JSON.stringify(saved.context)
        || (description || null) !== saved.description);
    const locked = !saved || !draft || loading || busy || ioBusy || confirmOutdate || loadFailed;
    const modeUnsaved = draft?.editor_mode !== saved?.context.editor_mode;
    const editorLocked = locked || modeUnsaved;
    const variants = saved?.variants ?? [];
    const activateTab = (tab: Tab) => { setActiveTab(tab); tabRefs.current[tab]?.focus(); };
    const showError = (error: unknown) => setBanner({ message: errorMessage(error), type: "error" });

    useEffect(() => {
        mounted.current = true;
        fetch(`${import.meta.env.VITE_API_URL}/api/projects`, { mode: "cors" }).then(async response => {
            if (!response.ok) throw new Error(`Failed to load projects (${response.status})`);
            const data: Project[] = await response.json();
            if (!Array.isArray(data)) throw new Error("Invalid project list.");
            if (mounted.current) setProjects(data);
        }).catch(error => { if (mounted.current) showError(error); });
        return () => { mounted.current = false; };
    }, []);

    const loadContext = useCallback(() => {
        const token = ++loadId.current;
        setSaved(null); setDraft(null); setDescription(""); setLoadFailed(false);
        setBusy(false); setConfirmOutdate(false); pendingSave.current = null;
        setLoading(Boolean(projectId));
        if (!projectId) return;
        Context.getShared(projectId).then(response => {
            if (!mounted.current || token !== loadId.current) return;
            setSaved(response); setDraft(response.context); setDescription(response.description ?? "");
        }).catch(error => {
            if (mounted.current && token === loadId.current) { setLoadFailed(true); showError(error); }
        }).finally(() => {
            if (mounted.current && token === loadId.current) setLoading(false);
        });
    }, [projectId]);
    useEffect(() => { loadContext(); }, [loadContext]);
    useEffect(() => {
        let cancelled = false;
        setReferenceFiles(null);
        setReferenceError("");
        if (projectId && referenceVariantId) {
            Context.get(projectId, referenceVariantId).then(response => {
                if (!cancelled) setReferenceFiles(response.files ?? []);
            }).catch(error => {
                if (!cancelled) setReferenceError(errorMessage(error));
            });
        }
        return () => { cancelled = true; };
    }, [projectId, referenceVariantId, referenceReload]);
    useEffect(() => {
        onAgentContextChange?.({
            section: activeTab, selectedProjectId: projectId,
            selectedProjectName: projects.find(project => project.id === projectId)?.name,
        });
    }, [activeTab, projectId, projects, onAgentContextChange]);

    const agentRefresh = useRef<() => void>(() => undefined);
    useEffect(() => {
        agentRefresh.current = () => {
            if (dirty || busy || ioBusy || confirmOutdate) {
                setBanner({ message: "The agent updated saved context. Your drafts were kept; section saves check for conflicts. Reload saved context after preserving your drafts.", type: "error" });
            } else loadContext();
        };
    });
    useEffect(() => {
        const listener = (event: Event) => {
            const tool = (event as CustomEvent<{ tool?: string }>).detail?.tool;
            if (tool === "update_project_context" || tool === "update_variant_context") agentRefresh.current();
        };
        window.addEventListener(AGENT_WRITE_EVENT, listener);
        return () => window.removeEventListener(AGENT_WRITE_EVENT, listener);
    }, []);

    const performSave = async (snapshot: SaveSnapshot) => {
        if (!mounted.current || snapshot.loadId !== loadId.current) return;
        setBusy(true);
        try {
            const response = await Context.saveShared(snapshot.projectId, snapshot.section, snapshot.context,
                snapshot.revision, snapshot.description);
            if (!mounted.current || snapshot.loadId !== loadId.current) return;
            setSaved(response);
            setDraft(current => current && (current.editor_mode !== response.context.editor_mode
                || snapshot.context.editor_mode !== saved?.context.editor_mode
                ? response.context : mergeSavedSection(current, response.context, snapshot.section)));
            if (snapshot.section === "context") setDescription(response.description ?? "");
            setBanner({ message: `${TABS.find(tab => tab.id === snapshot.section)?.label} saved successfully.`, type: "success" });
        } catch (error) {
            if (mounted.current && snapshot.loadId === loadId.current) showError(error);
        } finally {
            if (mounted.current && snapshot.loadId === loadId.current) setBusy(false);
        }
    };

    const handleSave = async () => {
        if (locked || !saved || !draft || activeTab === "summary") return;
        if (modeUnsaved && activeTab !== "context") return;
        const snapshot: SaveSnapshot = {
            section: activeTab, loadId: loadId.current, projectId, context: draft,
            description: description || null, revision: saved.revision,
        };
        setBusy(true);
        try {
            const preview = await Context.saveShared(projectId, activeTab, draft, saved.revision, snapshot.description, true);
            let shouldConfirm = false;
            if (preview.description_changed || preview.changed_variant_ids.length) {
                try {
                    const assessments = await Assessments.listForReview(undefined, projectId, "ai");
                    shouldConfirm = assessments.some(assessment => {
                        const targets = assessment.variant_ids ?? assessment.targets?.flatMap(target =>
                            target.variant_id ? [target.variant_id] : []) ?? (assessment.variant_id ? [assessment.variant_id] : []);
                        return preview.description_changed || !targets.length
                            || targets.some(target => preview.changed_variant_ids.includes(target));
                    });
                } catch (error) {
                    shouldConfirm = true;
                    setBanner({ message: `${errorMessage(error)} Could not check pending AI assessments; confirm before saving.`, type: "error" });
                }
            }
            if (!mounted.current || snapshot.loadId !== loadId.current) return;
            if (shouldConfirm) { pendingSave.current = snapshot; setConfirmOutdate(true); }
            else await performSave(snapshot);
        } catch (error) {
            if (mounted.current && snapshot.loadId === loadId.current) showError(error);
        } finally {
            if (mounted.current && snapshot.loadId === loadId.current) setBusy(false);
        }
    };

    const changeMode = async (mode: StrideEditorMode) => {
        if (!draft || !saved || locked || mode === draft.editor_mode) return;
        if (modeUnsaved && mode === saved.context.editor_mode) {
            setDraft(mergeSavedSection(saved.context, draft, "context"));
            return;
        }
        const othersDirty = COLLECTIONS.some(key => JSON.stringify(draft[key]) !== JSON.stringify(saved.context[key]))
            || SYSTEM_FIELDS.some(key => JSON.stringify(draft.fields[key]) !== JSON.stringify(saved.context.fields[key]));
        if (othersDirty) {
            setBanner({ message: "Save or discard System, Threat model and Risks drafts before changing Editor mode.", type: "error" });
            return;
        }
        const token = loadId.current;
        setBusy(true);
        try {
            const converted = await Context.convertShared(projectId, draft, mode);
            if (mounted.current && token === loadId.current) setDraft(converted);
        } catch (error) {
            if (mounted.current && token === loadId.current) showError(error);
        } finally {
            if (mounted.current && token === loadId.current) setBusy(false);
        }
    };

    const textEditor = (key: TextField | TextCollection, label: string, help?: string) => {
        const rows = draft ? (isTextField(key) ? draft.fields[key] : draft[key]) : [];
        const contextField = CONTEXT_FIELDS.some(field => field === key);
        return <ScopedTextEditor label={label} help={help} rows={rows} variants={variants} path={key === "codebase_path"}
            disabled={contextField ? locked : editorLocked}
            allocateId={reserved => draft && saved ? nextSharedId("X", [draft, saved.context], reserved) : "X1"}
            onChange={(entries: ScopedText[]) => setDraft(current => current && (isTextField(key)
                ? { ...current, fields: { ...current.fields, [key]: entries } } : { ...current, [key]: entries }))} />;
    };
    const nodeScope = (kind: "components" | "interactions" | "threats" | "risks", identifier: string, index: number) => {
        if (!draft) return null;
        const row = draft[kind][index];
        if (!row) return null;
        const references = "targetIds" in row ? row.targetIds : "threatId" in row ? [row.threatId]
            : "sourceId" in row ? [row.sourceId, row.destinationId] : [];
        const nodes = [...draft.components, ...draft.interactions, ...draft.threats];
        const invalid = references.filter(target => {
            const found = nodes.find(node => node.id === target);
            return found && row.variant_ids.some(variant => !found.variant_ids.includes(variant));
        });
        const label = `${kind === "components" ? "Component" : kind === "interactions" ? "Interaction"
            : kind === "threats" ? "Threat" : "Risk"} ${index + 1}`;
        return <div className="space-y-2">
            <VariantScopeSelector label={label} variants={variants} selected={row.variant_ids} disabled={editorLocked}
                onChange={targets => setDraft(current => current && ({
                    ...current, [kind]: current[kind].map((entry, position) =>
                        position === index ? { ...entry, variant_ids: targets } : entry),
                }))} />
            {invalid.length > 0 && <p role="status" className="text-xs text-amber-300">
                {identifier || row.id} references {invalid.join(", ")} outside their variant scope.
                Narrow this entry&apos;s variants or expand the referenced entry and save it first.
            </p>}
        </div>;
    };

    const loadExportVariants = async () => {
        if (exportLoaded) return;
        try {
            const result = await Variants.listAll();
            if (mounted.current) { setAllVariants(result); setExportLoaded(true); }
        } catch (error) { if (mounted.current) showError(error); }
    };
    useDismissablePopover(exportMenuOpen, exportMenuRef, useCallback(() => setExportMenuOpen(false), []));
    const download = (document: ContextExport) => {
        const url = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2)], { type: "application/json" }));
        const link = window.document.createElement("a");
        link.href = url; link.download = "vulnscout-context.json"; link.click(); URL.revokeObjectURL(url);
    };
    const exportSelected = async () => {
        if (ioBusy || !exportSelection.size) return;
        setIoBusy(true);
        try {
            download(await Context.exportSelected([...exportSelection]));
            if (mounted.current) setExportMenuOpen(false);
        } catch (error) { if (mounted.current) showError(error); }
        finally { if (mounted.current) setIoBusy(false); }
    };
    const importFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        event.target.value = "";
        if (!file || ioBusy) return;
        const token = loadId.current;
        setIoBusy(true); setImportDetails(null);
        try {
            let parsed: unknown;
            const text = await file.text();
            try { parsed = JSON.parse(text); }
            catch { throw new Error("The selected file is not valid JSON."); }
            const result = await Context.importContext(parsed);
            if (!mounted.current) return;
            setImportDetails(result);
            setBanner({
                message: `Import complete: ${result.imported.length} imported, ${result.ignored.length} ignored, ${result.failed.length} failed.${dirty ? " Your unsaved drafts were kept; reload saved context after preserving them." : ""}`,
                type: result.failed.length || dirty ? "error" : "success",
            });
            if (token === loadId.current && !dirty) loadContext();
        } catch (error) { if (mounted.current) showError(error); }
        finally { if (mounted.current) setIoBusy(false); }
    };

    const saveAction = activeTab !== "summary" && <div className="flex flex-wrap items-center gap-3 border-t border-slate-700 mt-4 pt-4">
        <button type="button" onClick={handleSave} disabled={locked || (modeUnsaved && activeTab !== "context")}
            className={primaryClass + " flex items-center gap-2"}>
            {busy && <FontAwesomeIcon icon={faSpinner} spin />}Save {TABS.find(tab => tab.id === activeTab)?.label}
        </button>
        <p className="text-xs text-zinc-400">Saves only this section. Other drafts remain unsaved.</p>
    </div>;

    return <div className="w-full space-y-6">
        {banner && <div className="sticky top-0 z-10"><MessageBanner type={banner.type} message={banner.message}
            isVisible onClose={() => setBanner(null)} /></div>}
        <div className="flex flex-wrap items-center gap-4">
            <h1 className="text-3xl font-bold text-white mb-2">AI Assessment Context</h1>
            <a href={docUrl} target="_blank" rel="noopener noreferrer" aria-label="documentation" className="text-white hover:text-blue-300">
                <FontAwesomeIcon icon={faBook} size="lg" />
            </a>
            <div className="ml-auto flex items-center gap-2">
                <button type="button" aria-label="Import context" disabled={ioBusy || busy || confirmOutdate}
                    className={transferClass} onClick={() => importInputRef.current?.click()}><FontAwesomeIcon icon={faFileImport} />Import</button>
                <input ref={importInputRef} type="file" accept="application/json,.json" aria-label="Import context file"
                    className="hidden" onChange={importFile} />
                <div className="relative" ref={exportMenuRef}>
                    <button type="button" aria-label="Export context" aria-haspopup="true" aria-expanded={exportMenuOpen}
                        disabled={ioBusy} className={transferClass} onClick={() => {
                            setExportMenuOpen(!exportMenuOpen); if (!exportMenuOpen) void loadExportVariants();
                        }}><FontAwesomeIcon icon={faFileExport} />Export<FontAwesomeIcon icon={faChevronDown} size="xs" /></button>
                    {exportMenuOpen && <div role="menu" className="absolute right-0 z-20 mt-2 w-72 max-h-96 overflow-auto rounded-lg bg-slate-800 border border-slate-600 p-3">
                        <div className="flex items-center justify-between mb-2 text-sm text-white">
                            Select variants
                            <div className="flex gap-2">
                                <button type="button" onClick={() => setExportSelection(new Set(allVariants.map(variant => variant.id)))}>All</button>
                                <button type="button" onClick={() => setExportSelection(new Set())}>None</button>
                            </div>
                        </div>
                        {projects.map(project => <div key={project.id} className="mb-2">
                            <p className="text-xs font-semibold text-zinc-300 mb-1">{project.name}</p>
                            {allVariants.filter(variant => variant.project_id === project.id).map(variant =>
                                <label key={variant.id} className="flex items-center gap-2 pl-2 py-0.5 text-sm text-zinc-200">
                                    <input type="checkbox" aria-label={`Export ${project.name} / ${variant.name}`}
                                        checked={exportSelection.has(variant.id)} onChange={() => setExportSelection(current => {
                                            const next = new Set(current);
                                            if (next.has(variant.id)) next.delete(variant.id); else next.add(variant.id);
                                            return next;
                                        })} />{variant.name}
                                </label>)}
                        </div>)}
                        <button type="button" disabled={ioBusy || !exportSelection.size} className={primaryClass + " w-full"}
                            onClick={exportSelected}>Export selected ({exportSelection.size})</button>
                    </div>}
                </div>
                <HelpPopover ariaLabel="Import help" role="tooltip" buttonClassName="text-sky-300" surfaceClassName="w-[320px] p-3">
                    Shared format 3.0 preserves entries and their variant scopes. Format 2.0 and legacy files remain importable;
                    legacy text uses Advanced free mode. Imports replace matching recipients only. Exports contain saved context, not drafts.
                    Uploaded codebase references are not included in context JSON transfers.
                </HelpPopover>
            </div>
        </div>
        {importDetails && (importDetails.failed.length > 0 || importDetails.ignored.length > 0) &&
            <div className="rounded-lg bg-slate-800/60 border border-slate-600 p-3 text-sm text-zinc-300">
                {(["failed", "ignored"] as const).map(kind => importDetails[kind].length > 0 && <div key={kind}>
                    <p className={kind === "failed" ? "font-semibold text-red-400" : "font-semibold text-yellow-400"}>
                        {kind === "failed" ? "Failed" : "Ignored"} ({importDetails[kind].length})
                    </p>
                    <ul>{importDetails[kind].map((entry, index) => <li key={index}>
                        {entry.project_name ?? "-"} / {entry.variant_name ?? "-"}: {entry.reason}
                    </li>)}</ul>
                </div>)}
            </div>}
        <div>
            <div className="bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60">
                <FontAwesomeIcon icon={faRobot} className="text-cyan-400" /><h2 className="text-xl font-bold text-white">Assessment context</h2>
            </div>
            <div className="bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 space-y-4">
                <div className="flex flex-wrap items-end gap-3">
                    <div className="flex-1">
                        <label className={labelClass} htmlFor={`${id}-project`}>Project</label>
                        <select id={`${id}-project`} className={inputClass} value={projectId} onChange={event => {
                            loadId.current++; setConfirmReload(false); setReferenceVariantId("");
                            setReferenceFiles(null); setProjectId(event.target.value);
                        }}>
                            <option value="">Select project</option>
                            {projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}
                        </select>
                    </div>
                    <button type="button" className={secondaryClass} disabled={!projectId || busy || loading || ioBusy || confirmOutdate}
                        onClick={() => dirty ? setConfirmReload(true) : loadContext()}>Reload saved context</button>
                </div>
                <p className="text-xs text-zinc-400">
                    Entries are shared by the selected variants. Editing an entry updates every selected recipient;
                    add another entry for different information. New entries select all current variants, not future variants.
                </p>
                {loading && <p role="status" className="text-sm text-zinc-300">Loading project context...</p>}
                {loadFailed && <p role="alert" className="text-sm text-red-400">
                    Could not load this project&apos;s context. Saving is disabled.
                    <button type="button" className="underline ml-2" onClick={loadContext}>Retry</button>
                </p>}
                {saved && !variants.length && <p role="status" className="text-sm text-amber-300">This project has no variants to receive shared entries.</p>}
                <div role="tablist" aria-label="AI context sections" className="flex flex-wrap gap-1 border-b border-slate-600 p-1 pb-2">
                    {TABS.map((tab, index) => <button key={tab.id} type="button" role="tab" ref={element => { tabRefs.current[tab.id] = element; }}
                        id={`${id}-${tab.id}-tab`} aria-controls={`${id}-${tab.id}-panel`} aria-selected={activeTab === tab.id}
                        tabIndex={activeTab === tab.id ? 0 : -1} onClick={() => activateTab(tab.id)}
                        className={`rounded-md px-4 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-cyan-400 ${activeTab === tab.id ? "bg-sky-900 text-white" : "text-slate-300 hover:bg-slate-700"}`}
                        onKeyDown={event => {
                            const next = event.key === "ArrowRight" ? (index + 1) % TABS.length
                                : event.key === "ArrowLeft" ? (index + TABS.length - 1) % TABS.length
                                : event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : null;
                            if (next !== null) { event.preventDefault(); activateTab(TABS[next].id); }
                        }}>{tab.label}</button>)}
                </div>
                <div role="tabpanel" id={`${id}-context-panel`} aria-labelledby={`${id}-context-tab`}
                    hidden={activeTab !== "context"} tabIndex={0} className="space-y-4">
                    <div>
                        <label className={labelClass} htmlFor={`${id}-description`}>Project Description</label>
                        <textarea id={`${id}-description`} className={inputClass + " resize-y min-h-[80px]"}
                            disabled={locked} value={description} onChange={event => setDescription(event.target.value)} />
                    </div>
                    {textEditor("variant_description", "Variant Description")}
                    {textEditor("codebase_path", "Codebase Path",
                        "Source locations visible to external assessment tools. Paths do not mount host directories into the container; use Codebase References for the embedded Agent.")}
                    <section className="space-y-2" aria-label="Variant codebase references">
                        <label className={labelClass} htmlFor={`${id}-reference-variant`}>Codebase reference variant</label>
                        <select id={`${id}-reference-variant`} className={inputClass} value={referenceVariantId}
                            disabled={locked} onChange={event => {
                                setReferenceFiles(null); setReferenceVariantId(event.target.value);
                            }}>
                            <option value="">Select a variant for uploaded references</option>
                            {variants.map(variant => <option key={variant.id} value={variant.id}>{variant.name}</option>)}
                        </select>
                        <p className="text-xs text-zinc-400">
                            Uploaded files belong only to this variant, independently of shared text entry scopes.
                        </p>
                        {referenceError && <p role="alert" className="text-sm text-red-400">
                            {referenceError}
                            <button type="button" className="underline ml-2"
                                onClick={() => setReferenceReload(value => value + 1)}>Retry references</button>
                        </p>}
                        {referenceVariantId && referenceFiles === null && !referenceError &&
                            <p role="status" className="text-sm text-zinc-300">Loading codebase references...</p>}
                        {referenceVariantId && referenceFiles !== null && <CodebaseReferences
                            key={`${projectId}/${referenceVariantId}/${referenceReload}`}
                            variantId={referenceVariantId} initialFiles={referenceFiles} disabled={locked}
                            notify={(message, type) => setBanner({ message, type })}
                        />}
                    </section>
                    {textEditor("environment", "Environment", "Describe the target platform, operating system and deployment conditions.")}
                    <div>
                        <label className={labelClass} htmlFor={`${id}-mode`}>Editor mode</label>
                        <p id={`${id}-mode-help`} className="text-xs text-zinc-400 mb-1">Applies to System, Threat model and Risks.</p>
                        <select id={`${id}-mode`} aria-describedby={`${id}-mode-help`} className={inputClass}
                            disabled={locked} value={draft?.editor_mode ?? "stride"} onChange={event => {
                                if (event.target.value === "stride" || event.target.value === "free") void changeMode(event.target.value);
                            }}>
                            <option value="stride">STRIDE template (recommended)</option>
                            <option value="free">Advanced free mode</option>
                        </select>
                    </div>
                    {textEditor("other_info", "Other Information")}
                    {activeTab === "context" && saveAction}
                </div>
                {modeUnsaved && activeTab !== "context" && <p role="status" className="text-sm text-amber-300">
                    Save Editor mode in Context before editing another section.
                </p>}
                <div hidden={activeTab === "context"}>
                    <StrideContextEditor activeSection={activeTab === "context" ? "system" : activeTab} tabIdPrefix={id}
                        modeContainer={null} threatModel={draft?.free_threat_model.map(row => row.value).join("\n\n") ?? ""}
                        risks={draft?.free_risks.map(row => row.value).join("\n\n") ?? ""} onChange={() => undefined}
                        controlledDraft={sharedDraft(draft ?? emptySharedContext())}
                        onControlledDraftChange={value => setDraft(current => current && saved
                            ? updateSharedDraft(current, value, variants, saved.context) : current)}
                        disabled={editorLocked} saveAction={saveAction} scopeEditor={nodeScope}
                        summaryAvailable={!!saved && !!draft && !loading && !loadFailed}
                        fieldEditor={key => {
                            const field = THREAT_MODEL_FIELDS.find(item => item.key === key)!;
                            return textEditor(key, field.label, field.help);
                        }}
                        notesEditor={section => section === "threat_model"
                            ? textEditor("threat_notes", "Additional notes", "Record assumptions, exclusions or notes that do not fit the threat entries.")
                            : textEditor("risk_notes", "Additional risk notes")}
                        freeEditor={section => textEditor(section === "threat_model" ? "free_threat_model" : "free_risks",
                            section === "threat_model" ? "Threat Model" : "Risks")}
                        allocateId={prefix => draft && saved ? nextSharedId(prefix, [draft, saved.context]) : `${prefix}1`}
                        canReference={(identifier, targetId) => {
                            if (!draft) return false;
                            const nodes = [...draft.components, ...draft.interactions, ...draft.threats];
                            const row = nodes.find(node => node.id === identifier);
                            const target = nodes.find(node => node.id === targetId);
                            return !!row && !!target && row.variant_ids.every(variant => target.variant_ids.includes(variant));
                        }}
                        summaryScope={(kind, index) => variants.filter(variant => draft?.[kind][index]?.variant_ids.includes(variant.id))
                            .map(variant => variant.name).join(", ") || "No variants selected"}
                    />
                    {activeTab === "summary" && draft && <section className="mt-4">
                        <h3 className="font-semibold text-white mb-2">Entry variant scopes</h3>
                        <div role="region" aria-label="Entry variant scopes" tabIndex={0} className="overflow-x-auto rounded border border-slate-600">
                            <table className="w-full text-sm text-zinc-300">
                                <thead><tr>{["Entry", "Information", "Variants"].map(label =>
                                    <th key={label} className="text-left p-2" scope="col">{label}</th>)}</tr></thead>
                                <tbody>{[
                                    ...Object.entries(draft.fields).flatMap(([key, rows]) => rows.map(row => ({
                                        ...row, label: key.replace(/_/g, " "), text: row.value,
                                    }))),
                                    ...COLLECTIONS.flatMap(key => draft[key].map(row => ({
                                        ...row, label: key.replace(/_/g, " "), text: "name" in row ? row.name
                                            : "value" in row ? row.value : "description" in row ? row.description : row.threatId,
                                    }))),
                                ].map(row => <tr key={row.id}>
                                    <th scope="row" className="border-t border-slate-700 p-2 text-left font-normal">{row.label} ({row.id})</th>
                                    <td className="border-t border-slate-700 p-2 whitespace-pre-wrap">{row.text || "Not recorded"}</td>
                                    <td className="border-t border-slate-700 p-2">{variants.filter(variant => row.variant_ids.includes(variant.id))
                                        .map(variant => variant.name).join(", ") || "No variants selected"}</td>
                                </tr>)}</tbody>
                            </table>
                        </div>
                    </section>}
                </div>
            </div>
        </div>
        <ConfirmationModal isOpen={confirmOutdate} title="Mark AI assessments as outdated?"
            message="Saving this section marks pending AI assessments for changed variants as outdated. A project-description change affects all project variants."
            confirmText="Save and mark outdated" cancelText="Cancel" showTitleIcon
            onConfirm={() => {
                const snapshot = pendingSave.current;
                pendingSave.current = null; setConfirmOutdate(false);
                if (snapshot) void performSave(snapshot);
            }} onCancel={() => { pendingSave.current = null; setConfirmOutdate(false); }} />
        <ConfirmationModal isOpen={confirmReload} title="Discard unsaved drafts?"
            message="Reloading replaces all current drafts with saved project context." confirmText="Discard and reload" cancelText="Cancel"
            onConfirm={() => { setConfirmReload(false); loadContext(); }} onCancel={() => setConfirmReload(false)} />
    </div>;
}
