import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBook } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import Context, { ContextSaveError } from "../handlers/context";
import Assessments from "../handlers/assessments";
import type { ContextFile, ImportResult, VariantDraft } from "../handlers/context";
import MessageBanner from "../components/MessageBanner";
import ConfirmationModal from "../components/ConfirmationModal";
import { useDocUrl } from "../helpers/useDocUrl";
import { useUnsavedGuard } from "../hooks/useUnsavedGuard";
import { useLoadedDraft } from "../hooks/useLoadedDraft";
import { draftFromContext, draftsEqual, emptyDraft, hasThreatModel, requiredFieldErrors } from "../helpers/strideModel";
import ContextSidebar from "../components/aiContext/ContextSidebar";
import type { SidebarSelection } from "../components/aiContext/ContextSidebar";
import ProjectDescriptionPanel from "../components/aiContext/ProjectDescriptionPanel";
import ContextTransferControls, { ImportDetails } from "../components/aiContext/ContextTransferControls";
import VariantEditor, { type VariantTab } from "../components/aiContext/VariantEditor";
import CopyFromDialog, { type CopySourceProject } from "../components/aiContext/CopyFromDialog";
import { ERROR } from "../components/aiContext/styles";
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

/** Every project with its variants; projects whose variants fail to load are left out. */
async function fetchCopySources(): Promise<CopySourceProject[]> {
    const projects = await fetchProjectList();
    const lists = await Promise.all(projects.map(p => fetchVariantList(p.id).catch(() => null)));
    return projects.flatMap((p, i) => {
        const list = lists[i];
        return list ? [{ id: p.id, name: p.name, variants: list.map(v => ({ id: v.id, name: v.name })) }] : [];
    });
}

/**
 * Top-bar scope; `variantIds` undefined means the whole project. `revision`
 * changes on every applied scope, even an identical one, so the page drops
 * edits the user chose to discard.
 */
export type AiContextScope = { projectId?: string; variantIds?: string[]; revision?: number };

type SaveTarget =
    | { kind: 'project'; projectId: string; description: string; sent: string }
    | { kind: 'variant'; projectId: string; variantId: string; draft: VariantDraft };

const DIRTY_PROJECT_AGENT_TEXT = "The agent updated the project description. Your unsaved edits were kept; saving replaces the agent's change.";
const DIRTY_VARIANT_AGENT_TEXT = "The agent updated the variant context. Your unsaved edits were kept; saving replaces the agent's change.";
const FIX_FIELDS_TEXT = "Fix the highlighted fields before saving.";
const EMPTY_VARIANT_DRAFT = emptyDraft();
const NO_FILES: ContextFile[] = [];
const sameText = (a: string, b: string) => a === b;
type BannerType = 'success' | 'error' | 'info';

/** The variant tab that owns a server field path (e.g. "components[0].name", "system.actors"). */
function tabForField(path: string): VariantTab {
    if (/^(system\.|components(\.|\[|$)|interactions(\.|\[|$))/.test(path)) return 'system';
    if (/^(threats|threat_model)(\.|\[|$)/.test(path)) return 'threat_model';
    if (/^risks(\.|\[|$)/.test(path)) return 'risks';
    return 'context';
}

async function hasPendingAi(target: SaveTarget): Promise<boolean> {
    try {
        // A project-description change outdates every variant in the project.
        const rows = target.kind === 'variant'
            ? await Assessments.listForReview(target.variantId, undefined, 'ai')
            : await Assessments.listForReview(undefined, target.projectId, 'ai');
        return rows.length > 0;
    } catch {
        // Could not check: warn anyway rather than silently outdating assessments.
        return true;
    }
}

function AIContext({ scope, onAgentContextChange }: Readonly<{
    scope: AiContextScope;
    onAgentContextChange?: (context: AgentViewContext) => void;
}>) {
    const unmountedRef = useRef(false);
    useEffect(() => {
        unmountedRef.current = false;
        return () => { unmountedRef.current = true; };
    }, []);

    const docUrl = useDocUrl("ai-assessments.html");
    const { registerGuard, confirmLeave } = useUnsavedGuard();
    const projectId = scope.projectId;

    const [projects, setProjects] = useState<Project[]>([]);
    // Tagged with their project: right after a project switch they still hold
    // the previous project's values, which must not be used.
    const [variantList, setVariantList] = useState<{ projectId: string; list: Variant[] } | null>(null);
    const [selection, setSelection] = useState<{ projectId: string; item: SidebarSelection } | null>(null);
    const variants = variantList && variantList.projectId === projectId ? variantList.list : null;
    const selected = selection && selection.projectId === projectId ? selection.item : null;

    // UI state
    const [busy, setBusy] = useState(false);
    const [fieldError, setFieldError] = useState('');
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
    const [variantTab, setVariantTab] = useState<VariantTab>('context');
    // Uploaded references are saved on their own, outside the draft; tagged with the draft key they belong to.
    const [variantFiles, setVariantFiles] = useState<{ key: string | null; files: ContextFile[] }>({ key: null, files: [] });
    const [announcement, setAnnouncement] = useState('');
    const [confirmOutdate, setConfirmOutdate] = useState(false);
    // The save a pending confirmation belongs to, and who waits for its outcome.
    const pendingSaveRef = useRef<{ target: SaveTarget; resolve: (saved: boolean) => void } | null>(null);
    const [banner, setBanner] = useState<{ msg: ReactNode; type: BannerType } | null>(null);
    const [importDetails, setImportDetails] = useState<ImportResult | null>(null);
    // Copy dialog sources; null while the dialog is closed.
    const [copySources, setCopySources] = useState<CopySourceProject[] | null>(null);

    const showBanner = useCallback((msg: ReactNode, type: BannerType) => {
        if (unmountedRef.current) return;
        setBanner({ msg, type });
    }, []);
    // Info banners (e.g. after Copy) stay; only an error that no longer applies is hidden.
    const hideErrorBanner = useCallback(() => setBanner(prev => (prev?.type === 'error' ? null : prev)), []);
    const showLoadError = useCallback((message: string) => showBanner(message, 'error'), [showBanner]);

    useEffect(() => {
        fetchProjectList().then(ps => {
            if (!unmountedRef.current) setProjects(ps);
        }).catch((e: any) => showBanner(e?.message || "Failed to load projects.", "error"));
    }, [showBanner]);

    // Every variant of the scope's project is listed; out-of-scope ones are locked.
    useEffect(() => {
        setVariantList(null);
        setSelection(null);
        if (!projectId) return;
        let current = true;
        fetchVariantList(projectId).then(vs => {
            if (current) setVariantList({ projectId, list: vs });
        }).catch((e: any) => {
            if (!current) return;
            showBanner(e?.message || "Failed to load variants.", "error");
            setVariantList({ projectId, list: [] });
        });
        return () => { current = false; };
    }, [projectId, showBanner]);

    const scopeKey = scope.variantIds?.join(',');
    const inScopeIds = useMemo(() => {
        const ids = (variants ?? []).map(v => v.id);
        return scopeKey === undefined ? ids : ids.filter(id => scopeKey.split(',').includes(id));
    }, [variants, scopeKey]);
    const inScopeKey = inScopeIds.join(',');

    // Drafts: only the open item has a key, so only it is loaded.
    const projectKey = projectId && selected?.kind === 'project' ? projectId : null;
    const variantKey = projectId && selected?.kind === 'variant' ? `${projectId}/${selected.id}` : null;
    const projectDraft = useLoadedDraft<string>(
        projectKey,
        () => Context.getProject(projectId ?? '').then(ctx => ctx.description ?? ''),
        '', sameText, showLoadError,
    );
    const variantDraft = useLoadedDraft<VariantDraft>(
        variantKey,
        () => Context.get(projectId ?? '', selected?.kind === 'variant' ? selected.id : '').then(ctx => {
            setVariantFiles({ key: variantKey, files: ctx.editor?.files ?? ctx.files ?? [] });
            return draftFromContext(ctx);
        }),
        EMPTY_VARIANT_DRAFT, draftsEqual, showLoadError,
    );
    const openKey = projectKey ?? variantKey;
    const openKeyRef = useRef(openKey);
    openKeyRef.current = openKey;
    // Field errors and the active tab belong to the open item, however it changed.
    useEffect(() => {
        setFieldError('');
        setFieldErrors({});
        setVariantTab('context');
    }, [openKey, projectDraft.epoch, variantDraft.epoch]);
    useEffect(() => { setCopySources(null); }, [openKey]);
    // Errors about the item or project just left no longer apply. Opening the
    // first item keeps them: they may explain why the variant list is empty.
    const lastOpenRef = useRef({ projectId, openKey });
    useEffect(() => {
        const last = lastOpenRef.current;
        lastOpenRef.current = { projectId, openKey };
        if (last.projectId !== projectId || (last.openKey !== null && last.openKey !== openKey)) hideErrorBanner();
    }, [projectId, openKey, hideErrorBanner]);
    const { reset: resetProject, reload: reloadProject } = projectDraft;
    const { reset: resetVariant, reload: reloadVariant } = variantDraft;

    // Keep the selection inside the scope; otherwise open the project
    // description. A scope change only happens after the unsaved prompt was
    // answered, so the open item's edits are dropped.
    useEffect(() => {
        if (!projectId || variants === null) return;
        const ids = inScopeKey ? inScopeKey.split(',') : [];
        setSelection(prev => {
            const item = prev?.projectId === projectId ? prev.item : null;
            if (item?.kind === 'project' || (item?.kind === 'variant' && ids.includes(item.id))) return prev;
            return { projectId, item: { kind: 'project' } };
        });
        resetProject();
        resetVariant();
    }, [projectId, variants, inScopeKey, scope.revision, resetProject, resetVariant]);

    const projectName = projects.find(p => p.id === projectId)?.name ?? '';
    const openVariant = selected?.kind === 'variant' ? variants?.find(v => v.id === selected.id) : undefined;
    const openLabel = selected?.kind === 'variant' ? (openVariant?.name ?? 'this variant') : (projectName || 'the project description');
    const dirty = selected?.kind === 'variant' ? variantDraft.dirty : projectDraft.dirty;

    useEffect(() => {
        onAgentContextChange?.({
            selectedProjectId: projectId,
            selectedProjectName: projectName || undefined,
            selectedVariantId: openVariant?.id,
            selectedVariantName: openVariant?.name,
        });
    }, [projectId, projectName, openVariant, onAgentContextChange]);

    const buildSaveTarget = (): SaveTarget | null => {
        if (!projectId || !selected) return null;
        if (selected.kind === 'project') {
            if (projectDraft.baseline === null) return null;
            if (!projectDraft.draft.trim()) {
                setFieldError("Project description is required.");
                return null;
            }
            return { kind: 'project', projectId, description: projectDraft.draft.trim(), sent: projectDraft.draft };
        }
        if (variantDraft.baseline === null) return null;
        if (!hasThreatModel(variantDraft.draft)) {
            setFieldError("A threat model is required.");
            setVariantTab('threat_model');
            return null;
        }
        const missing = requiredFieldErrors(variantDraft.draft.stride);
        const first = Object.keys(missing)[0];
        if (first !== undefined) {
            setFieldErrors(missing);
            setVariantTab(tabForField(first));
            showBanner(FIX_FIELDS_TEXT, "error");
            return null;
        }
        return { kind: 'variant', projectId, variantId: selected.id, draft: variantDraft.draft };
    };

    const performSave = async (target: SaveTarget, key: string | null): Promise<boolean> => {
        setBusy(true);
        hideErrorBanner();
        try {
            if (target.kind === 'project') {
                const saved = await Context.saveProject(target.projectId, target.description);
                if (openKeyRef.current === key) projectDraft.commit(saved.description ?? target.description, target.sent);
            } else {
                const saved = await Context.saveVariantEditor(target.variantId, target.draft);
                const value = saved?.editor
                    ? draftFromContext({ ...saved, project_id: target.projectId, description: null })
                    : target.draft;
                if (openKeyRef.current === key) variantDraft.commit(value, target.draft);
            }
            if (!unmountedRef.current) setAnnouncement("Saved.");
            return true;
        } catch (e: any) {
            const fields = e instanceof ContextSaveError ? e.fields : {};
            const first = Object.keys(fields)[0];
            if (e instanceof ContextSaveError && !unmountedRef.current && openKeyRef.current === key) {
                setFieldErrors(fields);
                if (first !== undefined) setVariantTab(tabForField(first));
            }
            // Field problems are shown inline; the raw server text joins their paths.
            showBanner(first === undefined ? (e?.message || "Failed to save context.") : FIX_FIELDS_TEXT, "error");
            return false;
        } finally {
            if (!unmountedRef.current) setBusy(false);
        }
    };

    // Saving marks pending AI assessments outdated (the variant's, or every
    // variant's for the project description), so ask first when there are any.
    // Resolves false when validation, the confirmation or the save fails.
    const requestSave = async (): Promise<boolean> => {
        if (busy) return false;
        setFieldError('');
        setFieldErrors({});
        setAnnouncement('');
        const target = buildSaveTarget();
        if (!target) return false;
        const key = openKeyRef.current;
        const pending = await hasPendingAi(target);
        // The selection may have moved on while the check was in flight.
        if (unmountedRef.current || key !== openKeyRef.current) return false;
        if (!pending) return performSave(target, key);
        return new Promise<boolean>(resolve => {
            pendingSaveRef.current = { target, resolve };
            setConfirmOutdate(true);
        });
    };

    const saveRef = useRef(requestSave);
    useEffect(() => { saveRef.current = requestSave; });
    useEffect(() => {
        registerGuard(dirty ? { label: openLabel, save: () => saveRef.current() } : null);
    }, [dirty, openLabel, registerGuard]);
    useEffect(() => () => registerGuard(null), [registerGuard]);

    // Agent updates reload only a clean open item, so unsaved edits are never replaced.
    const agentRefreshRef = useRef<(tool?: string) => void>(() => undefined);
    useEffect(() => {
        agentRefreshRef.current = (tool?: string) => {
            if (tool === 'update_project_context' && selected?.kind === 'project') {
                if (projectDraft.dirty) showBanner(DIRTY_PROJECT_AGENT_TEXT, "error");
                else reloadProject();
            }
            if (tool === 'update_variant_context' && selected?.kind === 'variant') {
                if (variantDraft.dirty) showBanner(DIRTY_VARIANT_AGENT_TEXT, "error");
                else reloadVariant();
            }
        };
    });
    useEffect(() => {
        const refresh = (event: Event) => agentRefreshRef.current((event as CustomEvent<{ tool?: string }>).detail?.tool);
        window.addEventListener(AGENT_WRITE_EVENT, refresh);
        return () => window.removeEventListener(AGENT_WRITE_EVENT, refresh);
    }, []);

    const handleSelect = async (next: SidebarSelection) => {
        const same = next.kind === selected?.kind && (next.kind === 'project' || (selected?.kind === 'variant' && next.id === selected.id));
        if (!projectId || same || !(await confirmLeave())) return;
        setSelection({ projectId, item: next });
    };

    const resolvePendingSave = (confirmed: boolean) => {
        const pending = pendingSaveRef.current;
        pendingSaveRef.current = null;
        setConfirmOutdate(false);
        if (!pending) return;
        if (!confirmed) pending.resolve(false);
        else void performSave(pending.target, openKeyRef.current).then(pending.resolve);
    };

    // Import overwrites stored context, so unsaved edits are confirmed first.
    const beforeImport = async () => {
        if (!(await confirmLeave())) return false;
        resetProject();
        resetVariant();
        setImportDetails(null);
        return true;
    };

    const openCopyFrom = () => {
        const key = openKeyRef.current;
        fetchCopySources().then(sources => {
            if (!unmountedRef.current && openKeyRef.current === key) setCopySources(sources);
        }).catch((e: any) => showBanner(e?.message || "Failed to load projects.", "error"));
    };

    // Copy replaces only the draft: the baseline stays, so the variant turns dirty.
    const handleCopy = async (sourceProjectId: string, sourceVariantId: string) => {
        const key = openKeyRef.current;
        const project = copySources?.find(p => p.id === sourceProjectId);
        const variant = project?.variants.find(v => v.id === sourceVariantId);
        try {
            const source = await Context.get(sourceProjectId, sourceVariantId);
            if (unmountedRef.current || openKeyRef.current !== key) return;
            variantDraft.setDraft(draftFromContext(source));
            setFieldError('');
            setFieldErrors({});
            showBanner(`Copied the context of ${project?.name ?? ''} / ${variant?.name ?? ''}. Review it, then Save changes.`, "info");
        } catch (e: any) {
            showBanner(e?.message || "Failed to load context.", "error");
        }
    };

    const handleImported = (result: ImportResult) => {
        setImportDetails(result);
        reloadProject();
        reloadVariant();
    };

    return (
        <div className="w-full space-y-6">
            {banner && (
                <div className="sticky top-0 z-10">
                    <MessageBanner
                        type={banner.type}
                        message={banner.msg}
                        isVisible={true}
                        onClose={() => setBanner(null)}
                    />
                </div>
            )}

            <div className="flex flex-wrap items-center gap-4">
                <h1 className="text-3xl font-bold text-white">AI Assessment Context</h1>
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
                <span
                    role="status"
                    className={dirty ? "rounded-full border border-amber-400/60 px-3 py-0.5 text-xs font-semibold text-amber-300" : ""}
                >
                    {dirty ? `Unsaved changes in ${openLabel}` : ''}
                </span>

                <ContextTransferControls
                    projects={projects}
                    beforeImport={beforeImport}
                    onImported={handleImported}
                    notify={showBanner}
                />
            </div>

            <ImportDetails result={importDetails} />

            {!projectId ? (
                <p className="text-sm text-zinc-400">Select a project with the project/variant selector in the top bar.</p>
            ) : (
                <div className="flex items-start gap-4">
                    <ContextSidebar
                        projectName={projectName}
                        variants={variants ?? []}
                        inScopeIds={inScopeIds}
                        selected={selected}
                        onSelect={next => { void handleSelect(next); }}
                    />
                    <div className="min-w-0 flex-1">
                        {selected?.kind === 'project' && (
                            <ProjectDescriptionPanel
                                projectName={projectName}
                                value={projectDraft.draft}
                                onChange={projectDraft.setDraft}
                                onSave={() => { void requestSave(); }}
                                saving={busy}
                                dirty={projectDraft.dirty}
                                error={fieldError}
                            />
                        )}
                        {selected?.kind === 'variant' && (
                            <>
                                {fieldError && <p role="alert" className={`${ERROR} mb-2`}>{fieldError}</p>}
                                {variantDraft.baseline === null ? (
                                    <p className="text-sm text-zinc-400">{variantDraft.loading ? 'Loading variant context…' : ''}</p>
                                ) : (
                                    <VariantEditor
                                        variantId={selected.id}
                                        variantName={openVariant?.name ?? ''}
                                        draft={variantDraft.draft}
                                        onDraftChange={variantDraft.setDraft}
                                        files={variantFiles.key === variantKey ? variantFiles.files : NO_FILES}
                                        onSave={() => { void requestSave(); }}
                                        saving={busy}
                                        dirty={variantDraft.dirty}
                                        onCopyFrom={openCopyFrom}
                                        fieldErrors={fieldErrors}
                                        notify={showBanner}
                                        draftGeneration={variantDraft.generation}
                                        tab={variantTab}
                                        onTabChange={setVariantTab}
                                    />
                                )}
                            </>
                        )}
                    </div>
                </div>
            )}

            {selected?.kind === 'variant' && (
                <CopyFromDialog
                    isOpen={copySources !== null}
                    currentVariantId={selected.id}
                    projects={copySources ?? []}
                    onCopy={handleCopy}
                    onClose={() => setCopySources(null)}
                />
            )}
            <ConfirmationModal
                isOpen={confirmOutdate}
                title="Mark AI assessments as outdated?"
                message="Saving this context will mark all pending AI assessments as outdated, because they were generated before the context changed. They remain outdated until they are regenerated."
                confirmText="Save and mark outdated"
                cancelText="Cancel"
                showTitleIcon={true}
                onConfirm={() => resolvePendingSave(true)}
                onCancel={() => resolvePendingSave(false)}
            />
            <div role="status" className="sr-only">{announcement}</div>
        </div>
    );
}

export default AIContext;
