import { useState, useEffect, useRef, useCallback } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark, faSpinner, faRobot } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import Context from "../handlers/context";
import type { ContextFile, VariantContextData } from "../handlers/context";
import MessageBanner from "../components/MessageBanner";

const MAX_FILE_BYTES = 10 * 1024 * 1024;

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

    // Selectors
    const [projects, setProjects] = useState<Project[]>([]);
    const [variants, setVariants] = useState<Variant[]>([]);
    const [selectedProjectId, setSelectedProjectId] = useState<string>('');
    const [selectedVariantId, setSelectedVariantId] = useState<string>('');

    // Form fields
    const [description, setDescription] = useState<string>('');
    const [variantDescription, setVariantDescription] = useState<string>('');
    const [environment, setEnvironment] = useState<string>('');
    const [threatModel, setThreatModel] = useState<string>('');
    const [risks, setRisks] = useState<string>('');
    const [otherInfo, setOtherInfo] = useState<string>('');
    const [files, setFiles] = useState<ContextFile[]>([]);
    const [fileDescription, setFileDescription] = useState<string>('');

    // UI state
    const [busy, setBusy] = useState(false);
    const [fileError, setFileError] = useState<string | null>(null);
    const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
    const [bannerMsg, setBannerMsg] = useState<string>('');
    const [bannerType, setBannerType] = useState<'success' | 'error'>('success');
    const [bannerVisible, setBannerVisible] = useState(false);

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

    const clearVariantFields = () => {
        setVariantDescription('');
        setEnvironment('');
        setThreatModel('');
        setRisks('');
        setOtherInfo('');
        setFiles([]);
        setFileDescription('');
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
                    setEnvironment(ctx.environment ?? '');
                    setThreatModel(ctx.threat_model ?? '');
                    setRisks(ctx.risks ?? '');
                    setOtherInfo(ctx.other_info ?? '');
                    setFiles(ctx.files);
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

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        e.target.value = '';
        if (!file || !selectedVariantId) return;
        setFileError(null);
        if (file.size > MAX_FILE_BYTES) {
            setFileError("File exceeds the 10 MB maximum size.");
            return;
        }
        const desc = fileDescription.trim() || null;
        try {
            const uploaded = await Context.uploadFile(selectedVariantId, file, desc);
            if (!unmountedRef.current) {
                setFiles(prev => [...prev, uploaded]);
                setFileDescription('');
            }
        } catch (e: any) {
            if (!unmountedRef.current) setFileError(e?.message || "Upload failed.");
        }
    };

    const handleDeleteFile = async (fileId: string) => {
        if (!selectedVariantId) return;
        try {
            await Context.deleteFile(selectedVariantId, fileId);
            if (!unmountedRef.current) setFiles(prev => prev.filter(f => f.id !== fileId));
        } catch (e: any) {
            if (!unmountedRef.current) showBanner(e?.message || "Failed to delete file.", "error");
        }
    };

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

            <h1 className="text-3xl font-bold text-white mb-2">AI Assessment Context</h1>

            <div>
                <div className={cardHeader}>
                    <FontAwesomeIcon icon={faRobot} className="text-cyan-400" />
                    <h2 className="text-xl font-bold text-white">Context</h2>
                </div>
                <div className={cardBody}>

            {/* Selectors */}
            <div className="flex gap-4 flex-wrap">
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

            {/* Supplemental Files */}
            <div>
                <label className={labelClass} htmlFor="ai-files">
                    Supplemental Files <span className="text-neutral-400 font-normal">(10 MB each)</span>
                </label>
                <input
                    id="ai-file-description"
                    aria-label="File Description"
                    type="text"
                    className={inputClass + " mb-2"}
                    value={fileDescription}
                    onChange={e => setFileDescription(e.target.value)}
                    disabled={!variantSelected}
                    placeholder={variantSelected ? "Optional description for the next uploaded file" : "Select a variant to enable"}
                />
                <input
                    id="ai-files"
                    aria-label="Supplemental Files"
                    type="file"
                    className="text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    disabled={!variantSelected}
                    onChange={handleFileChange}
                />
                {fileError && <p className="text-red-500 text-xs mt-1">{fileError}</p>}
                {files.length > 0 && (
                    <ul className="mt-2 flex flex-col gap-2">
                        {files.map(f => (
                            <li key={f.id} className="flex items-start gap-1 bg-slate-900/60 border border-slate-600 rounded px-2 py-1.5 text-sm text-white">
                                <div className="flex flex-col">
                                    <span>{f.original_name}</span>
                                    {f.description && (
                                        <span className="text-xs text-zinc-400">{f.description}</span>
                                    )}
                                </div>
                                <button
                                    type="button"
                                    aria-label={`Delete ${f.original_name}`}
                                    onClick={() => handleDeleteFile(f.id)}
                                    className="ml-auto text-zinc-400 hover:text-red-400"
                                >
                                    <FontAwesomeIcon icon={faXmark} />
                                </button>
                            </li>
                        ))}
                    </ul>
                )}
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
