import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faFileExport, faFileImport, faChevronDown } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../../handlers/project";
import type { Variant } from "../../handlers/variant";
import Variants from "../../handlers/variant";
import Context from "../../handlers/context";
import type { ContextExport, ImportResult } from "../../handlers/context";
import HelpPopover from "../HelpPopover";
import useDismissablePopover from "../../hooks/useDismissablePopover";
import { BUTTON_PRIMARY, BUTTON_TRANSFER } from "./styles";

type Props = {
    projects: Project[];
    /** Runs before the file picker opens; false cancels the import. */
    beforeImport: () => Promise<boolean>;
    onImported: (result: ImportResult) => void;
    notify: (message: ReactNode, type: 'success' | 'error') => void;
};

function downloadJson(document_: ContextExport, filename: string) {
    const blob = new Blob([JSON.stringify(document_, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/** Import and Export buttons, the export variant menu and the import help. */
function ContextTransferControls({ projects, beforeImport, onImported, notify }: Readonly<Props>) {
    const unmountedRef = useRef(false);
    useEffect(() => {
        unmountedRef.current = false;
        return () => { unmountedRef.current = true; };
    }, []);

    const [exportMenuOpen, setExportMenuOpen] = useState(false);
    const [exportSelection, setExportSelection] = useState<Set<string>>(new Set());
    const [ioBusy, setIoBusy] = useState(false);
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [allVariantsLoaded, setAllVariantsLoaded] = useState(false);
    const exportMenuRef = useRef<HTMLDivElement | null>(null);
    const importInputRef = useRef<HTMLInputElement | null>(null);

    // Load all variants for the export selector (lazily, when the menu first opens)
    const loadAllVariants = useCallback(() => {
        if (allVariantsLoaded) return;
        Variants.listAll().then(vs => {
            if (unmountedRef.current) return;
            setAllVariants(vs);
            setAllVariantsLoaded(true);
        }).catch((e: any) => {
            // Leave allVariantsLoaded false so reopening the menu retries.
            if (!unmountedRef.current) notify(e?.message || "Failed to load variants for export.", "error");
        });
    }, [allVariantsLoaded, notify]);

    const handleExportSelected = async () => {
        if (ioBusy || exportSelection.size === 0) return;
        setIoBusy(true);
        try {
            const doc = await Context.exportSelected([...exportSelection]);
            downloadJson(doc, "vulnscout-context.json");
            if (!unmountedRef.current) setExportMenuOpen(false);
        } catch (e: any) {
            if (!unmountedRef.current) notify(e?.message || "Failed to export context.", "error");
        } finally {
            if (!unmountedRef.current) setIoBusy(false);
        }
    };

    const handleImportClick = async () => {
        if (ioBusy || !(await beforeImport())) return;
        importInputRef.current?.click();
    };

    const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        e.target.value = '';
        if (!file || ioBusy) return;
        setIoBusy(true);
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
            const total = result.imported.length + result.ignored.length + result.failed.length;
            const msg =
                `Import complete: ${result.imported.length} of ${total} imported, ` +
                `${result.ignored.length} ignored, ${result.failed.length} failed.`;
            notify(msg, result.failed.length > 0 ? "error" : "success");
            onImported(result);
        } catch (err: any) {
            if (!unmountedRef.current) notify(err?.message || "Import failed.", "error");
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

    return (
        <div className="ml-auto flex items-center gap-2">
            <button
                type="button"
                aria-label="Import context"
                onClick={() => { void handleImportClick(); }}
                disabled={ioBusy}
                className={BUTTON_TRANSFER}
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
                    className={BUTTON_TRANSFER}
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
                            className={BUTTON_PRIMARY + " w-full mt-2 justify-center"}
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
    );
}

/** Lists the ignored and failed entries of the last import, if any. */
export function ImportDetails({ result }: Readonly<{ result: ImportResult | null }>) {
    if (!result || (result.ignored.length === 0 && result.failed.length === 0)) return null;
    return (
        <div className="rounded-lg bg-slate-800/60 border border-slate-600 p-3 text-sm">
            {result.failed.length > 0 && (
                <div className="mb-2">
                    <p className="font-semibold text-red-400">Failed ({result.failed.length})</p>
                    <ul className="list-disc list-inside text-zinc-300">
                        {result.failed.map((it, i) => (
                            <li key={`f-${i}`}>{it.project_name ?? '—'} / {it.variant_name ?? '—'}: {it.reason}</li>
                        ))}
                    </ul>
                </div>
            )}
            {result.ignored.length > 0 && (
                <div>
                    <p className="font-semibold text-yellow-400">Ignored ({result.ignored.length})</p>
                    <ul className="list-disc list-inside text-zinc-300">
                        {result.ignored.map((it, i) => (
                            <li key={`i-${i}`}>{it.project_name ?? '—'} / {it.variant_name ?? '—'}: {it.reason}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

export default ContextTransferControls;
