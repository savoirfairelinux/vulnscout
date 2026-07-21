import { useState, useEffect, useRef, useCallback } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faRobot, faBook, faFileExport, faFileImport, faChevronDown } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import Variants from "../handlers/variant";
import Context from "../handlers/context";
import type { VariantContextData, ContextEntry, ImportResult } from "../handlers/context";
import MessageBanner from "../components/MessageBanner";
import { useDocUrl } from "../helpers/useDocUrl";

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

function AIContext() {
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

    // Form fields
    const [description, setDescription] = useState<string>('');
    const [variantDescription, setVariantDescription] = useState<string>('');
    const [codebasePath, setCodebasePath] = useState<string>('');
    const [environment, setEnvironment] = useState<string>('');
    const [threatModel, setThreatModel] = useState<string>('');
    const [risks, setRisks] = useState<string>('');
    const [otherInfo, setOtherInfo] = useState<string>('');

    // UI state
    const [busy, setBusy] = useState(false);
    const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
    const [bannerMsg, setBannerMsg] = useState<string>('');
    const [bannerType, setBannerType] = useState<'success' | 'error'>('success');
    const [bannerVisible, setBannerVisible] = useState(false);

    // Import/Export state
    const [exportMenuOpen, setExportMenuOpen] = useState(false);
    const [exportSelection, setExportSelection] = useState<Set<string>>(new Set());
    const [ioBusy, setIoBusy] = useState(false);
    const [importDetails, setImportDetails] = useState<ImportResult | null>(null);
    const exportMenuRef = useRef<HTMLDivElement | null>(null);
    const importInputRef = useRef<HTMLInputElement | null>(null);

    const showBanner = (msg: string, type: 'success' | 'error') => {
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
        setCodebasePath('');
        setEnvironment('');
        setThreatModel('');
        setRisks('');
        setOtherInfo('');
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

    // Load context when selections change
    const loadContext = useCallback(() => {
        if (!selectedProjectId) return;
        if (selectedVariantId) {
            Context.get(selectedProjectId, selectedVariantId)
                .then(ctx => {
                    if (unmountedRef.current) return;
                    setDescription(ctx.description ?? '');
                    setVariantDescription(ctx.variant_description ?? '');
                    setCodebasePath(ctx.codebase_path ?? '');
                    setEnvironment(ctx.environment ?? '');
                    setThreatModel(ctx.threat_model ?? '');
                    setRisks(ctx.risks ?? '');
                    setOtherInfo(ctx.other_info ?? '');
                }).catch((e: any) => {
                    if (!unmountedRef.current)
                        showBanner(e?.message || "Failed to load context.", "error");
                });
        } else {
            // Variant cleared or not yet selected — clear variant-bound fields
            clearVariantFields();
            Context.getProject(selectedProjectId)
                .then(ctx => {
                    if (unmountedRef.current) return;
                    setDescription(ctx.description ?? '');
                }).catch((e: any) => {
                    if (!unmountedRef.current)
                        showBanner(e?.message || "Failed to load project context.", "error");
                });
        }
    }, [selectedProjectId, selectedVariantId]);

    useEffect(() => {
        loadContext();
    }, [loadContext]);

    const validate = (): boolean => {
        const errors: Record<string, string> = {};
        if (!description.trim()) {
            errors.description = "Project Description is required.";
        }
        if (selectedVariantId && !threatModel.trim()) {
            errors.threatModel = "Threat Model is required.";
        }
        setValidationErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSave = async () => {
        if (!selectedProjectId || busy) return;
        if (!validate()) return;
        setBusy(true);
        try {
            await Context.saveProject(selectedProjectId, description.trim() || null);
        } catch (e: any) {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to save project context.", "error");
            setBusy(false);
            return;
        }
        if (selectedVariantId) {
            const fields: VariantContextData = {
                variant_description: variantDescription.trim() || null,
                codebase_path: codebasePath.trim() || null,
                environment: environment.trim() || null,
                threat_model: threatModel.trim() || null,
                risks: risks.trim() || null,
                other_info: otherInfo.trim() || null,
            };
            try {
                await Context.saveVariant(selectedVariantId, fields);
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
            showBanner("Context saved successfully.", "success");
            setBusy(false);
        }
    };

    const handleFileDownload = (entries: ContextEntry[], filename: string) => {
        const blob = new Blob([JSON.stringify(entries, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const projectNameById = useCallback(
        (projectId: string) => projects.find(p => p.id === projectId)?.name ?? '',
        [projects]
    );

    const handleExportSelected = async () => {
        if (ioBusy || exportSelection.size === 0) return;
        setIoBusy(true);
        try {
            const all = await Context.exportAll();
            // Keep only entries whose variant is checked in the selector.
            const keys = new Set(
                allVariants
                    .filter(v => exportSelection.has(v.id))
                    .map(v => `${projectNameById(v.project_id)}\u0000${v.name}`)
            );
            const chosen = all.filter(e => keys.has(`${e.project_name}\u0000${e.variant_name}`));
            handleFileDownload(chosen, "vulnscout-context.json");
            if (!unmountedRef.current) setExportMenuOpen(false);
        } catch (e: any) {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to export context.", "error");
        } finally {
            if (!unmountedRef.current) setIoBusy(false);
        }
    };

    const handleExportVariant = async () => {
        if (ioBusy || !selectedProjectId || !selectedVariantId) return;
        setIoBusy(true);
        try {
            const entries = await Context.exportVariant(selectedProjectId, selectedVariantId);
            const variantName = variants.find(v => v.id === selectedVariantId)?.name ?? "variant";
            handleFileDownload(entries, `vulnscout-context-${variantName}.json`);
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
            if (!Array.isArray(parsed)) {
                throw new Error("The file must contain a JSON array of context entries.");
            }
            const result = await Context.importContext(parsed);
            if (unmountedRef.current) return;
            setImportDetails(result);
            const total = result.imported.length + result.ignored.length + result.failed.length;
            const msg =
                `Import complete: ${result.imported.length} of ${total} imported, ` +
                `${result.ignored.length} ignored, ${result.failed.length} failed.`;
            showBanner(msg, result.failed.length > 0 ? "error" : "success");
            loadContext();
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
    useEffect(() => {
        if (!exportMenuOpen) return;
        const onClick = (ev: MouseEvent) => {
            if (exportMenuRef.current && !exportMenuRef.current.contains(ev.target as Node)) {
                setExportMenuOpen(false);
            }
        };
        document.addEventListener("mousedown", onClick);
        return () => document.removeEventListener("mousedown", onClick);
    }, [exportMenuOpen]);

    const variantSelected = Boolean(selectedVariantId);
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
        "px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 focus:ring-4 focus:outline-none focus:ring-slate-500 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
    const cardHeader =
        "bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60";
    const cardBody =
        "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 shadow-lg shadow-black/20 space-y-4";

    return (
        <div className="w-full space-y-6">
            <MessageBanner
                type={bannerType}
                message={bannerMsg}
                isVisible={bannerVisible}
                onClose={() => setBannerVisible(false)}
            />

            <div className="flex items-center justify-start gap-4">
                <h1 className="text-3xl font-bold text-white mb-2">AI Assessment Context</h1>
                <a
                    href={docUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="documentation"
                    title="Open documentation"
                    className="hover:text-blue-400 transition-colors"
                    >
                    <FontAwesomeIcon icon={faBook} size='lg' />
                </a>

                {/* Import / Export controls */}
                <div className="ml-auto flex items-center gap-2">
                    <div className="relative" ref={exportMenuRef}>
                        <button
                            type="button"
                            aria-label="Export context"
                            aria-haspopup="true"
                            aria-expanded={exportMenuOpen}
                            onClick={() => setExportMenuOpen(o => { const next = !o; if (next) loadAllVariants(); return next; })}
                            disabled={ioBusy}
                            className={btnSecondary + " flex items-center gap-2"}
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
                    <button
                        type="button"
                        aria-label="Import context"
                        onClick={() => importInputRef.current?.click()}
                        disabled={ioBusy}
                        className={btnSecondary + " flex items-center gap-2"}
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
                    <h2 className="text-xl font-bold text-white">Context</h2>
                </div>
                <div className={cardBody}>

            {/* Project selector */}
            <div>
                <label className={labelClass} htmlFor="ai-project-select">Project</label>
                <select
                    id="ai-project-select"
                    aria-label="Project"
                    className={selectClass}
                    value={selectedProjectId}
                    onChange={e => setSelectedProjectId(e.target.value)}
                >
                    <option value="">— Select project —</option>
                    {projects.map(p => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                </select>
            </div>

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
                />
                {validationErrors.description && (
                    <p className="text-red-500 text-xs mt-1">{validationErrors.description}</p>
                )}
            </div>

            {/* Variant selector */}
            <div>
                <label className={labelClass} htmlFor="ai-variant-select">Variant</label>
                <select
                    id="ai-variant-select"
                    aria-label="Variant"
                    className={selectClass}
                    value={selectedVariantId}
                    onChange={e => setSelectedVariantId(e.target.value)}
                    disabled={!projectSelected || variants.length === 0}
                >
                    <option value="">— Select variant —</option>
                    {variants.map(v => (
                        <option key={v.id} value={v.id}>{v.name}</option>
                    ))}
                </select>
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

            {/* Codebase Path */}
            <div>
                <label className={labelClass} htmlFor="ai-codebase-path">
                    Codebase Path <span className="text-neutral-400 font-normal">(source code location(s) on the local machine; separate multiple paths with a semicolon)</span>
                </label>
                <input
                    id="ai-codebase-path"
                    aria-label="Codebase Path"
                    type="text"
                    className={inputClass}
                    value={codebasePath}
                    onChange={e => setCodebasePath(e.target.value)}
                    disabled={!variantSelected}
                    placeholder={variantSelected ? "e.g. /home/user/src/myproject;/home/user/src/otherproject" : "Select a variant to enable"}
                />
            </div>

            {/* Environment */}
            <div>
                <label className={labelClass} htmlFor="ai-environment">Environment</label>
                <textarea
                    id="ai-environment"
                    aria-label="Environment"
                    className={textareaClass}
                    value={environment}
                    onChange={e => setEnvironment(e.target.value)}
                    disabled={!variantSelected}
                    placeholder={variantSelected ? "e.g. runtime environment details" : "Select a variant to enable"}
                />
            </div>

            {/* Threat Model */}
            <div>
                <label className={labelClass} htmlFor="ai-threat-model">
                    Threat Model <span className="text-red-500">*</span>
                </label>
                <textarea
                    id="ai-threat-model"
                    aria-label="Threat Model"
                    className={textareaClass}
                    value={threatModel}
                    onChange={e => setThreatModel(e.target.value)}
                    disabled={!variantSelected}
                    placeholder={variantSelected ? "Describe the threat criteria for CVEs..." : "Select a variant to enable"}
                />
                {validationErrors.threatModel && (
                    <p className="text-red-500 text-xs mt-1">{validationErrors.threatModel}</p>
                )}
            </div>

            {/* Risks */}
            <div>
                <label className={labelClass} htmlFor="ai-risks">Risks</label>
                <textarea
                    id="ai-risks"
                    aria-label="Risks"
                    className={textareaClass}
                    value={risks}
                    onChange={e => setRisks(e.target.value)}
                    disabled={!variantSelected}
                    placeholder={variantSelected ? "Describe known risks..." : "Select a variant to enable"}
                />
            </div>

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

                {/* Export this variant */}
                <div>
                    <button
                        type="button"
                        aria-label="Export this variant"
                        onClick={handleExportVariant}
                        disabled={!variantSelected || ioBusy}
                        className={btnSecondary + " flex items-center gap-2"}
                    >
                        <FontAwesomeIcon icon={faFileExport} />
                        Export this variant
                    </button>
                </div>

                {/* Save */}
                <div>
                    <button
                        type="button"
                        onClick={handleSave}
                        disabled={!projectSelected || busy}
                        className={btnPrimary + " flex items-center gap-2"}
                    >
                        {busy && <FontAwesomeIcon icon={faSpinner} spin />}
                        Save
                    </button>
                </div>
                </div>
            </div>
        </div>
    );
}

export default AIContext;
