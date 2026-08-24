import { useCallback, useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCloudArrowUp, faFileLines, faImage, faSpinner, faXmark } from "@fortawesome/free-solid-svg-icons";
import type { ExportDocument } from "./ExportWizard";

const assetExtensions = new Set(["png", "jpg", "jpeg", "gif", "webp"]);
const templateAccept = ".adoc,.asciidoc,.html,.htm,.md,.markdown,.csv,.txt,.json,.xml,.tex,.j2,.jinja,.jinja2";
const assetAccept = ".png,.jpg,.jpeg,.gif,.webp";

const asExportDocument = (data: any): ExportDocument | [] => {
    if (typeof data !== "object" || typeof data?.id !== "string") return [];
    return {
        id: data.id,
        category: Array.isArray(data.category)
            ? data.category.filter((entry: any) => typeof entry === "string")
            : [],
        extension: typeof data.extension === "string"
            ? data.extension
            : data.id.split(".").at(-1) ?? "unk",
    };
};

export default function CustomExportContentManager() {
    const [documents, setDocuments] = useState<ExportDocument[]>([]);
    const [dragActive, setDragActive] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [uploadError, setUploadError] = useState<string | null>(null);
    const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const loadDocuments = useCallback(() => {
        fetch(import.meta.env.VITE_API_URL + "/api/documents", { mode: "cors" })
            .then(response => response.json())
            .then(data => setDocuments(Array.isArray(data) ? data.flatMap(asExportDocument) : []))
            .catch(() => setDocuments([]));
    }, []);

    useEffect(() => loadDocuments(), [loadDocuments]);

    const upload = useCallback((file: File) => {
        const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
        const isAsset = assetExtensions.has(extension);
        const body = new FormData();
        body.append("file", file);
        setUploadError(null);
        setUploadSuccess(null);
        setUploading(true);
        fetch(import.meta.env.VITE_API_URL + `/api/documents/${isAsset ? "assets" : "templates"}`, {
            mode: "cors",
            method: "POST",
            body,
        })
            .then(async response => {
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(data?.error || `${isAsset ? "Upload" : "Import"} failed (${response.status})`);
                }
                setUploadSuccess(isAsset
                    ? `Uploaded "${data?.name ?? file.name}".`
                    : `Imported "${data?.id ?? file.name}".`);
                loadDocuments();
            })
            .catch(reason => setUploadError(reason instanceof Error ? reason.message : String(reason)))
            .finally(() => setUploading(false));
    }, [loadDocuments]);

    const onFilesSelected = useCallback((files: FileList | null) => {
        if (files?.[0]) upload(files[0]);
    }, [upload]);

    const customReports = documents.filter(document => document.category.includes("custom"));
    const assets = documents.filter(document => document.category.includes("assets"));

    return <div className="space-y-5">
        <div>
            <h2 className="text-xl font-bold text-white">Custom reports and assets</h2>
            <p className="mt-1 text-sm text-zinc-400">Upload report templates and the image assets used by those templates.</p>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4" aria-labelledby="custom-reports-heading">
                <h3 id="custom-reports-heading" className="flex items-center gap-2 text-sm font-semibold text-white"><FontAwesomeIcon icon={faFileLines} className="text-cyan-400" />Custom reports ({customReports.length})</h3>
                <ul className="mt-3 max-h-44 space-y-2 overflow-y-auto text-sm text-zinc-300">
                    {customReports.map(report => <li key={report.id} className="rounded border border-slate-700 bg-neutral-800 px-3 py-2">{report.id}</li>)}
                    {customReports.length === 0 && <li className="italic text-zinc-500">No custom reports installed.</li>}
                </ul>
            </section>
            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4" aria-labelledby="custom-assets-heading">
                <h3 id="custom-assets-heading" className="flex items-center gap-2 text-sm font-semibold text-white"><FontAwesomeIcon icon={faImage} className="text-cyan-400" />Custom assets ({assets.length})</h3>
                <ul className="mt-3 max-h-44 space-y-2 overflow-y-auto text-sm text-zinc-300">
                    {assets.map(asset => <li key={asset.id} className="rounded border border-slate-700 bg-neutral-800 px-3 py-2">{asset.id}</li>)}
                    {assets.length === 0 && <li className="italic text-zinc-500">No custom assets installed.</li>}
                </ul>
            </section>
        </div>

        <input ref={fileInputRef} type="file" className="hidden" accept={`${templateAccept},${assetAccept}`} onChange={event => { onFilesSelected(event.target.files); event.target.value = ""; }} />
        <button
            type="button"
            onClick={() => !uploading && fileInputRef.current?.click()}
            onDragOver={event => { event.preventDefault(); setDragActive(true); }}
            onDragEnter={event => { event.preventDefault(); setDragActive(true); }}
            onDragLeave={event => { event.preventDefault(); setDragActive(false); }}
            onDrop={event => { event.preventDefault(); setDragActive(false); onFilesSelected(event.dataTransfer.files); }}
            aria-label="Upload a custom report or asset"
            className={`flex w-full cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-6 py-7 text-center transition-colors ${dragActive ? "border-sky-400 bg-sky-900/40 text-white" : "border-white/20 bg-gray-700/40 text-white/70 hover:border-white/35 hover:text-white"} ${uploading ? "cursor-wait opacity-70" : ""}`}
            disabled={uploading}
        >
            <FontAwesomeIcon icon={uploading ? faSpinner : faCloudArrowUp} className={`text-2xl ${uploading ? "animate-spin" : ""}`} aria-hidden="true" />
            <span className="text-base font-medium">{uploading ? "Uploading file..." : "Drag and drop a custom report or asset here, or click to browse"}</span>
            <span className="text-xs text-white/60">Reports: .adoc, .html, .md, .csv, .txt, .json, .xml, .tex, .j2 | Assets: .png, .jpg, .webp, .gif</span>
        </button>

        {uploadError && <div role="alert" className="rounded-lg border border-red-700 bg-red-900/40 px-4 py-2 text-sm text-red-300">{uploadError}</div>}
        {uploadSuccess && <div role="status" className="flex items-start justify-between gap-2 rounded-lg border border-green-700 bg-green-900/40 px-4 py-2 text-sm text-green-300">
            <span>{uploadSuccess}</span>
            <button type="button" onClick={() => setUploadSuccess(null)} aria-label="Dismiss message" className="text-green-300/80 hover:text-white"><FontAwesomeIcon icon={faXmark} /></button>
        </div>}
    </div>;
}