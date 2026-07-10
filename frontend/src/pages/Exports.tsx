import { useEffect, useState, useCallback, useRef } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faThumbTack, faFolderOpen, faFileShield, faBoxes, faCloudArrowUp, faSpinner, faXmark,
} from "@fortawesome/free-solid-svg-icons";
import FileTag from "../components/FileTag";
import PopupExportOptions from "../components/PopupExportOptions";
import type { Options as PopupOptions } from "../components/PopupExportOptions";


type ExportDoc = {
    id: string;
    category: string[];
    extension: string;
}

const asExportDoc = (data: any): ExportDoc | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    let item: ExportDoc = {
        id: data.id,
        category: [],
        extension: "unk"
    };
    if (Array.isArray(data?.category))
        item.category = data.category.filter((e: any) => typeof e === "string");
    if (typeof data?.extension === "string")
        item.extension = data.extension;
    else if (typeof data?.id?.split('.')?.at(-1) === "string")
        item.extension = data.id.split('.').at(-1);
    return item
}


function Exports ({ variantId, projectId }: Readonly<{ variantId?: string; projectId?: string }>) {
    const [tab, setTab] = useState<string>("all");
    const [docs, setDocs] = useState<ExportDoc[]>([]);
    const [openDl, setOpenDl] = useState<string | null>(null);
    const [popupOptions, setPopupOptions] = useState<PopupOptions|undefined>(undefined);
    const [dragActive, setDragActive] = useState<boolean>(false);
    const [uploading, setUploading] = useState<boolean>(false);
    const [uploadError, setUploadError] = useState<string | null>(null);
    const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const loadDocs = useCallback(() => {
        fetch(import.meta.env.VITE_API_URL + "/api/documents", {
            mode: 'cors'
        })
        .then(res => res.json())
        .then(data => {
            if (Array.isArray(data)) {
                setDocs(data.flatMap(asExportDoc));
            }
        })
        .catch(error => {
            console.error('Error:', error);
        })
    }, []);

    useEffect(() => {
        loadDocs();
    }, [loadDocs]);

    const uploadTemplate = useCallback((file: File) => {
        setUploadError(null);
        setUploadSuccess(null);
        setUploading(true);
        const body = new FormData();
        body.append("file", file);
        fetch(import.meta.env.VITE_API_URL + "/api/documents/templates", {
            mode: 'cors',
            method: 'POST',
            body,
        })
        .then(async (res) => {
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(data?.error || `Import failed (${res.status})`);
            }
            setUploadSuccess(`Imported "${data?.id ?? file.name}".`);
            setTab("custom");
            loadDocs();
        })
        .catch((error) => {
            setUploadError(error instanceof Error ? error.message : String(error));
        })
        .finally(() => {
            setUploading(false);
        });
    }, [loadDocs]);

    const onFilesSelected = useCallback((files: FileList | null) => {
        if (files && files.length > 0) {
            uploadTemplate(files[0]);
        }
    }, [uploadTemplate]);

    const onDrop = useCallback((e: React.DragEvent<HTMLElement>) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);
        onFilesSelected(e.dataTransfer.files);
    }, [onFilesSelected]);


    return (<>
        <div className="w-full pt-32 flex justify-center" onClick={() => setOpenDl(null)}>
        <div className="w-[70%]">
            <h1 className="text-3xl font-bold mb-4">Export</h1>
            <p className="mb-6">Generate reports and SBOM files from your scan results.</p>

            {/* Tabs */}
            <div className="flex gap-2 bg-sky-800 rounded-2xl p-2 shadow-lg backdrop-blur-md justify-center">
            {[
                { key: "all", icon: faBoxes, label: "All" },

                { key: "built-in", icon: faThumbTack, label: "Built-in reports" },
                { key: "custom", icon: faFolderOpen, label: "Custom reports" },
                { key: "sbom", icon: faFileShield, label: "SBOM files" },
            ].map(({ key, icon, label }) => (
                <button
                key={key}
                onClick={(e) => {
                    e.stopPropagation()
                    setTab(key)
                    setOpenDl(null)
                }}
                className={[
                    "flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200",
                    tab === key
                    ? "bg-white/20 text-white shadow-inner"
                    : "text-white/70 hover:text-white hover:bg-white/10",
                ].join(" ")}
                >
                <FontAwesomeIcon icon={icon} className="w-4 h-4" />
                {label}
                </button>
            ))}
            </div>
    </div>
</div>

<div className="w-full pt-4 flex justify-center">
  <div className="w-[70%] bg-gray-700 from-zinc-800 to-zinc-900 rounded-3xl p-6 grid grid-cols-3 gap-6 justify-center shadow-xl border border-white/10 backdrop-blur-sm">
    {docs.filter((doc) => doc.category.includes(tab) || tab === 'all').map((doc) => (
      <FileTag
        name={doc.id}
        key={encodeURIComponent(doc.id)}
        extension={doc.extension}
        variantId={variantId}
        projectId={projectId}
        opened={openDl === doc.id}
        onOpen={() => openDl === doc.id ? setOpenDl(null) : setOpenDl(doc.id)}
      />
    ))}

    {docs.filter((doc) => doc.category.includes(tab) || tab === 'all').length === 0 && (
      <div className="col-span-2 flex flex-col items-center justify-center text-white/70 w-full py-10">
        <div className="text-lg font-medium">No documents found</div>
        {tab === 'custom' && (
          <div className="mt-2 text-sm">
            You can upload your own templates in
            <code className="p-1 mx-1 bg-white/10 rounded">.vulnscout/templates</code>
          </div>
        )}
      </div>
    )}
  </div>
</div>

{(tab === 'custom' || tab === 'all') && (
<div className="w-full pt-4 flex justify-center">
  <div className="w-[70%]">
    <input
      ref={fileInputRef}
      type="file"
      className="hidden"
      accept=".adoc,.asciidoc,.html,.htm,.md,.markdown,.csv,.txt,.json,.xml,.tex,.j2,.jinja,.jinja2"
      onChange={(e) => { onFilesSelected(e.target.files); e.target.value = ""; }}
    />
    <button
      type="button"
      onClick={() => !uploading && fileInputRef.current?.click()}
      onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setDragActive(true); }}
      onDragEnter={(e) => { e.preventDefault(); e.stopPropagation(); setDragActive(true); }}
      onDragLeave={(e) => { e.preventDefault(); e.stopPropagation(); setDragActive(false); }}
      onDrop={onDrop}
      aria-label="Import a custom report template"
      className={[
        "w-full flex flex-col items-center justify-center gap-2 rounded-2xl border-2 border-dashed",
        "px-6 py-8 text-center transition-colors duration-150 cursor-pointer",
        dragActive
          ? "border-sky-400 bg-sky-900/40 text-white"
          : "border-white/20 bg-gray-700/40 text-white/70 hover:border-white/35 hover:text-white",
        uploading && "cursor-wait opacity-70",
      ].filter(Boolean).join(" ")}
      disabled={uploading}
    >
      <FontAwesomeIcon
        icon={uploading ? faSpinner : faCloudArrowUp}
        className={["text-2xl", uploading && "animate-spin"].filter(Boolean).join(" ")}
        aria-hidden="true"
      />
      <div className="text-base font-medium">
        {uploading ? "Importing template…" : "Drag & drop a custom template here, or click to browse"}
      </div>
      <div className="text-xs text-white/60">
        Accepted: .adoc, .html, .md, .csv, .txt, .json, .xml, .tex, .j2
      </div>
    </button>
    {uploadError && (
      <div role="alert" className="mt-3 text-sm text-red-300 bg-red-900/40 border border-red-700 rounded-lg px-4 py-2">
        {uploadError}
      </div>
    )}
    {uploadSuccess && (
      <div role="status" className="mt-3 flex items-start justify-between gap-2 text-sm text-green-300 bg-green-900/40 border border-green-700 rounded-lg px-4 py-2">
        <span>{uploadSuccess}</span>
        <button
          type="button"
          onClick={() => setUploadSuccess(null)}
          aria-label="Dismiss message"
          className="shrink-0 text-green-300/80 hover:text-white transition-colors"
        >
          <FontAwesomeIcon icon={faXmark} className="w-4 h-4" />
        </button>
      </div>
    )}
  </div>
</div>
)}



        {popupOptions && <PopupExportOptions
            docName={popupOptions.docName}
            extension={popupOptions.extension}
            onClose={() => {setPopupOptions(undefined)}}
        ></PopupExportOptions>}
    </>);
}

export default Exports;
