import { useEffect, useRef, useState } from "react";
import Context, { type ContextFile } from "../handlers/context";
import Assessments from "../handlers/assessments";
import ConfirmationModal from "./ConfirmationModal";
import FileInputButton from "./FileInputButton";
import HelpPopover from "./HelpPopover";

type Action = { kind: "upload"; files: File[]; description: string } | { kind: "delete"; file: ContextFile };

function CodebaseReferences({ variantId, initialFiles, disabled, notify }: Readonly<{
    variantId: string;
    initialFiles: ContextFile[];
    disabled: boolean;
    notify: (message: string, type: "success" | "error") => void;
}>) {
    const [files, setFiles] = useState(initialFiles);
    const [description, setDescription] = useState("");
    const [busy, setBusy] = useState(false);
    const [dragging, setDragging] = useState(false);
    const [pending, setPending] = useState<Action | null>(null);
    const mounted = useRef(true);
    const busyRef = useRef(false);
    useEffect(() => {
        mounted.current = true;
        return () => { mounted.current = false; };
    }, []);
    useEffect(() => { setFiles(initialFiles); }, [initialFiles]);

    const execute = async (action: Action) => {
        try {
            if (action.kind === "delete") {
                await Context.deleteFile(variantId, action.file.id);
                if (!mounted.current) return;
                setFiles(current => current.filter(file => file.id !== action.file.id));
                notify("Codebase reference deleted. Pending AI assessments are marked outdated.", "success");
            } else {
                const failures: string[] = [];
                let uploaded = 0;
                for (const file of action.files) {
                    if (!mounted.current) break;
                    try {
                        const reference = await Context.uploadFile(variantId, file, action.description);
                        uploaded++;
                        if (mounted.current) setFiles(current => [...current, reference]);
                    } catch (error) {
                        failures.push(`${file.name}: ${error instanceof Error ? error.message : "Upload failed."}`);
                    }
                }
                if (!mounted.current) return;
                notify(
                    `${uploaded} reference(s) uploaded.${uploaded ? " Pending AI assessments are marked outdated." : ""}${failures.length ? ` ${failures.join(" ")}` : ""}`,
                    failures.length ? "error" : "success"
                );
            }
        } catch (error) {
            if (mounted.current) notify(error instanceof Error ? error.message : "Reference change failed.", "error");
        } finally {
            busyRef.current = false;
            if (mounted.current) setBusy(false);
        }
    };

    const requestAction = async (action: Action) => {
        if (!variantId || disabled || busyRef.current || pending) return;
        busyRef.current = true;
        setBusy(true);
        if (action.kind === "delete") {
            setPending(action);
            return;
        }
        let warn = true;
        try {
            warn = (await Assessments.listForReview(variantId, undefined, "ai")).length > 0;
        } catch (error) {
            if (mounted.current) notify(
                `${error instanceof Error ? error.message : "Could not check pending AI assessments."} Confirm before changing references.`,
                "error"
            );
        }
        if (!mounted.current) return;
        if (warn) setPending(action);
        else await execute(action);
    };

    const unavailable = disabled || busy || !variantId;
    return (
        <section aria-label="Codebase references" className="space-y-2">
            <div className="flex items-center gap-2">
                <h3 className="text-sm text-zinc-300">Codebase References</h3>
                <HelpPopover ariaLabel="Codebase references help" role="tooltip" buttonClassName="text-sky-300 hover:text-sky-100" surfaceClassName="w-[360px] p-3">
                    Upload source files or ZIP, TAR, TAR.GZ/TGZ archives for the embedded Agent and external MCP clients.
                    References are saved immediately for this variant, separately from the context form.
                    Archives are limited to 5,000 entries. Binary files cannot be read as source.
                    Upload only code you are permitted to share with your selected AI provider; exclude secrets.
                </HelpPopover>
            </div>
            <div
                role="region"
                aria-label="Drop codebase files"
                aria-disabled={unavailable}
                className={`rounded border-2 border-dashed p-4 ${dragging ? "border-cyan-400 bg-cyan-950/40" : "border-slate-600"} ${unavailable ? "opacity-40" : ""}`}
                onDragOver={event => { event.preventDefault(); if (!unavailable) setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={event => {
                    event.preventDefault();
                    setDragging(false);
                    const dropped = Array.from(event.dataTransfer.files);
                    if (dropped.length) void requestAction({ kind: "upload", files: dropped, description });
                }}
            >
                <label htmlFor="ai-codebase-files" className="block text-sm text-zinc-300 mb-2">
                    {busy ? "Updating references..." : "Drag and drop files here, or choose files"}
                </label>
                <FileInputButton
                    id="ai-codebase-files"
                    buttonLabel="Choose files"
                    multiple
                    aria-label="Upload codebase references"
                    disabled={unavailable}
                    onChange={event => {
                        const selected = Array.from(event.target.files ?? []);
                        event.target.value = "";
                        if (selected.length) void requestAction({ kind: "upload", files: selected, description });
                    }}
                />
            </div>
            <div className="block text-sm text-zinc-300">
                <div className="flex items-center gap-2">
                    <label htmlFor="ai-codebase-description">Reference description</label>
                    <HelpPopover ariaLabel="Reference description help" role="tooltip" buttonClassName="text-sky-300 hover:text-sky-100" surfaceClassName="w-[320px] p-3">
                        Optional. Applied to the next upload.
                    </HelpPopover>
                </div>
                <input
                    id="ai-codebase-description"
                    aria-label="Codebase reference description"
                    value={description}
                    onChange={event => setDescription(event.target.value)}
                    disabled={unavailable}
                    className="block w-full rounded px-2 py-1.5 mt-1 text-sm bg-slate-900/60 border border-slate-600 text-white disabled:opacity-40"
                    placeholder="e.g. Complete source for this variant, or selected component only"
                />
            </div>
            {files.length === 0 ? <p className="text-xs text-zinc-400">No codebase references uploaded.</p> : (
                <ul className="space-y-2">
                    {files.map(file => (
                        <li key={file.id} className="flex items-center justify-between gap-2 rounded bg-slate-900/60 p-2 text-sm text-zinc-300">
                            <span className="break-all">
                                {file.original_name}
                                {file.description && <span className="block text-xs text-zinc-400">{file.description}</span>}
                            </span>
                            <button
                                type="button"
                                aria-label={`Delete reference ${file.original_name}`}
                                disabled={unavailable}
                                className="text-red-400 hover:text-red-300 disabled:opacity-40"
                                onClick={() => void requestAction({ kind: "delete", file })}
                            >Delete</button>
                        </li>
                    ))}
                </ul>
            )}
            <ConfirmationModal
                isOpen={pending !== null}
                title={pending?.kind === "delete" ? "Delete codebase reference?" : "Mark AI assessments as outdated?"}
                message={pending?.kind === "delete"
                    ? `Delete ${pending.file.original_name}? This removes the stored reference and marks any pending AI assessments for this variant as outdated.`
                    : "Changing codebase references marks pending AI assessments for this variant as outdated. Your unsaved context fields are preserved."}
                confirmText={pending?.kind === "delete" ? "Delete reference" : "Upload and mark outdated"}
                cancelText="Cancel"
                onConfirm={() => {
                    const action = pending;
                    setPending(null);
                    if (action) void execute(action);
                }}
                onCancel={() => { setPending(null); busyRef.current = false; setBusy(false); }}
            />
        </section>
    );
}

export default CodebaseReferences;
