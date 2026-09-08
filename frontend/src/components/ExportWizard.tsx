import { useEffect, useMemo, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBoxArchive, faDownload, faFileLines, faLayerGroup, faShieldHalved } from "@fortawesome/free-solid-svg-icons";
import type { Project } from "../handlers/project";
import type { Variant } from "../handlers/variant";
import { queueExport } from "../handlers/exportQueue";
import ModalShell, { ModalActions, ModalButton } from "./ModalShell";

export type ExportDocument = {
    id: string;
    category: string[];
    extension: string;
};

type ExportMode = "consolidated" | "per_variant";
type ExportType = "reports" | "sbom";
type WizardStep = "scope" | "type" | "documents";

type Selection = {
    key: string;
    name: string;
    extension: string;
    category: string[];
};

type Props = {
    isOpen: boolean;
    embedded?: boolean;
    project?: Project;
    variants: Variant[];
    documents: ExportDocument[];
    onClose?: () => void;
};

const reportCategories = [
    ["all", "All reports"],
    ["built-in", "Built-in reports"],
    ["custom", "Custom reports"],
] as const;

export default function ExportWizard({ isOpen, embedded = false, project, variants, documents, onClose }: Readonly<Props>) {
    const [step, setStep] = useState<WizardStep>("scope");
    const [exportType, setExportType] = useState<ExportType | null>(null);
    const [mode, setMode] = useState<ExportMode>("consolidated");
    const [category, setCategory] = useState("all");
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [enabledDocuments, setEnabledDocuments] = useState<Set<string>>(new Set());
    const [selectedVariantIds, setSelectedVariantIds] = useState<Set<string>>(new Set());
    const [exporting, setExporting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const dialogRef = useRef<HTMLDivElement>(null);
    const stepHeadingRef = useRef<HTMLHeadingElement>(null);
    const focusStepHeadingOnChange = useRef(false);

    const selections = useMemo<Selection[]>(() => documents
        .filter(document => !document.category.includes("assets") && !document.id.startsWith("assets/"))
        .flatMap(document =>
        document.extension.split("|").map(extension => {
            const normalizedExtension = extension.trim();
            return {
                key: `${document.id}\0${normalizedExtension}`,
                name: document.id,
                extension: normalizedExtension,
                category: document.category,
            };
        })), [documents]);
    const visibleSelections = selections.filter(selection => {
        if (exportType === "sbom") return selection.category.includes("sbom");
        if (exportType === "reports") {
            return !selection.category.includes("sbom")
                && (category === "all" || selection.category.includes(category));
        }
        return false;
    });
    const selectionGroups = Array.from(visibleSelections.reduce((groups, selection) => {
        const group = groups.get(selection.name) ?? [];
        group.push(selection);
        groups.set(selection.name, group);
        return groups;
    }, new Map<string, Selection[]>()));
    const activeSteps: WizardStep[] = ["scope", "type", "documents"];
    const stepLabels: Record<WizardStep, string> = {
        scope: "Scope",
        type: "Export type",
        documents: "Documents",
    };
    const stepIndex = activeSteps.indexOf(step);

    useEffect(() => {
        if (!isOpen) return;
        setStep("scope");
        setExportType(null);
        setMode("consolidated");
        setCategory("all");
        setSelected(new Set());
        setEnabledDocuments(new Set());
        setError(null);
        dialogRef.current?.focus();
    }, [isOpen]);

    useEffect(() => {
        if (isOpen) setSelectedVariantIds(new Set(variants.map(variant => variant.id)));
    }, [isOpen, variants]);

    useEffect(() => {
        if (!focusStepHeadingOnChange.current) return;
        focusStepHeadingOnChange.current = false;
        stepHeadingRef.current?.focus();
    }, [step]);

    if (!isOpen) return null;

    const navigateToStep = (nextStep: WizardStep) => {
        focusStepHeadingOnChange.current = true;
        setStep(nextStep);
    };

    const toggleSelection = (key: string) => {
        setSelected(current => {
            const next = new Set(current);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    };

    const selectVisible = () => {
        setEnabledDocuments(current => new Set([
            ...current,
            ...selectionGroups.map(([name]) => name),
        ]));
        setSelected(current => {
            const next = new Set(current);
            visibleSelections.forEach(selection => next.add(selection.key));
            return next;
        });
    };

    const clearVisible = () => {
        setEnabledDocuments(current => {
            const next = new Set(current);
            selectionGroups.forEach(([name]) => next.delete(name));
            return next;
        });
        setSelected(current => {
            const next = new Set(current);
            visibleSelections.forEach(selection => next.delete(selection.key));
            return next;
        });
    };

    const toggleDocument = (name: string, documentSelections: Selection[]) => {
        const disabling = enabledDocuments.has(name);
        setEnabledDocuments(current => {
            const next = new Set(current);
            if (disabling) next.delete(name);
            else next.add(name);
            return next;
        });
        if (disabling || documentSelections.length === 1) {
            setSelected(current => {
                const next = new Set(current);
                documentSelections.forEach(selection => {
                    if (disabling) next.delete(selection.key);
                    else next.add(selection.key);
                });
                return next;
            });
        }
    };

    const toggleVariant = (variantId: string) => setSelectedVariantIds(current => {
        const next = new Set(current);
        if (next.has(variantId)) next.delete(variantId);
        else next.add(variantId);
        return next;
    });

    const launchExport = async () => {
        if (!project || selectedVariantIds.size === 0 || selected.size === 0) return;
        setExporting(true);
        setError(null);
        try {
            await queueExport({
                project_id: project.id,
                variant_ids: variants
                    .filter(variant => selectedVariantIds.has(variant.id))
                    .map(variant => variant.id),
                mode: exportType === "sbom" ? "per_variant" : mode,
                documents: selections
                    .filter(selection => selected.has(selection.key))
                    .map(({ name, extension }) => ({ name, extension })),
            }, project.name);
            if (embedded) {
                setStep("scope");
                setExportType(null);
                setSelected(new Set());
                setEnabledDocuments(new Set());
                setSelectedVariantIds(new Set(variants.map(variant => variant.id)));
            } else {
                onClose?.();
            }
        } catch (reason) {
            setError(reason instanceof Error ? reason.message : String(reason));
        } finally {
            setExporting(false);
        }
    };

    const footer = (
        <ModalActions align="between">
            <ModalButton onClick={() => navigateToStep(activeSteps[stepIndex - 1])} disabled={stepIndex === 0 || exporting}>Back</ModalButton>
            {step !== "documents" ? <ModalButton variant="primary" onClick={() => navigateToStep(activeSteps[stepIndex + 1])} disabled={(step === "scope" && (!project || selectedVariantIds.size === 0)) || (step === "type" && exportType === null)}>Next</ModalButton> : <ModalButton variant="primary" onClick={launchExport} disabled={selected.size === 0 || exporting}><FontAwesomeIcon icon={faDownload} className="mr-2" aria-hidden="true" />{exporting ? "Preparing export..." : "Download export"}</ModalButton>}
        </ModalActions>
    );

    return (
        <ModalShell
            isOpen={isOpen}
            embedded={embedded}
            title="Create export"
            subtitle={`Step ${stepIndex + 1} of ${activeSteps.length}`}
            titleId="export-wizard-title"
            onClose={() => onClose?.()}
            closeLabel="Close export wizard"
            showCloseButton={!embedded}
            closeDisabled={exporting}
            closeOnEscape={!exporting}
            closeOnBackdrop={!exporting}
            size="large"
            panelRef={dialogRef}
            panelTabIndex={-1}
            contentClassName={embedded ? "min-h-[38rem] px-10 py-9 md:px-10 md:py-9" : "min-h-80 px-6 py-5 md:px-6 md:py-5"}
            footer={footer}
            headerContent={
                <ol className={`${embedded ? "mt-6" : "mt-4"} grid grid-cols-3 gap-3 text-xs`}>
                    {activeSteps.map((currentStep, index) => (
                        <li key={currentStep} className={index <= stepIndex ? "text-cyan-300" : "text-neutral-500"}>
                            <span aria-hidden="true" className="mr-1 font-semibold">{index + 1}.</span>{stepLabels[currentStep]}
                        </li>
                    ))}
                </ol>
            }
        >
            {step === "scope" && <>
                <h3 ref={stepHeadingRef} tabIndex={-1} className="text-base font-semibold text-white">Project scope</h3>
                {project ? <>
                    <p className="mt-1 text-sm text-neutral-400">Choose the variants to export from <span className="font-semibold text-white">{project.name}</span>.</p>
                    <p className="mt-1 text-xs text-neutral-500">Use the project selector in the navigation bar to export another project.</p>
                    <div className={`mt-5 rounded-lg border border-slate-600 bg-slate-900/40 ${embedded ? "p-6" : "p-4"}`}>
                        <div className="flex items-center justify-between gap-3">
                            <h4 className="text-sm font-semibold text-white">Variants ({selectedVariantIds.size} of {variants.length} selected)</h4>
                            {variants.length > 1 && <div className="flex gap-3 text-xs">
                                <button type="button" onClick={() => setSelectedVariantIds(new Set(variants.map(variant => variant.id)))} className="rounded border border-cyan-700 px-2.5 py-1 font-medium text-cyan-300 hover:bg-cyan-950/40 hover:text-white">Select all</button>
                                <button type="button" onClick={() => setSelectedVariantIds(new Set())} className="rounded border border-neutral-600 px-2.5 py-1 font-medium text-neutral-300 hover:bg-neutral-800 hover:text-white">Clear</button>
                            </div>}
                        </div>
                        <div className="mt-3 grid max-h-48 grid-cols-1 gap-2 overflow-y-auto pr-1">
                            {variants.map(variant => <label key={variant.id} className={`flex cursor-pointer items-center gap-4 rounded-lg border transition-colors ${embedded ? "px-5 py-4" : "px-3 py-2"} text-sm ${selectedVariantIds.has(variant.id) ? "border-cyan-500 bg-cyan-950/40 text-white" : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500"}`}>
                                <input type="checkbox" checked={selectedVariantIds.has(variant.id)} onChange={() => toggleVariant(variant.id)} className="accent-cyan-500" />
                                <span className="truncate font-medium">{variant.name}</span>
                            </label>)}
                        </div>
                        {variants.length === 0 && <p className="mt-3 text-sm italic text-neutral-500">This project has no variants.</p>}
                    </div>
                </> : <p className="mt-4 rounded border border-amber-700/60 bg-amber-950/30 p-3 text-sm text-amber-200">Select a project from the navigation bar before creating an export.</p>}
            </>}

            {step === "type" && <>
                <h3 ref={stepHeadingRef} tabIndex={-1} className="text-base font-semibold text-white">What do you want to export?</h3>
                <p className="mt-1 text-sm text-neutral-400">Choose one export family. You will select its individual files in the final step.</p>
                <div className={`mt-6 grid grid-cols-1 ${embedded ? "gap-5 xl:grid-cols-2" : "grid-cols-2 gap-3"}`}>
                    <label className={`flex cursor-pointer items-start rounded-lg border ${embedded ? "gap-5 p-7" : "gap-3 p-4"} ${exportType === "reports" ? "border-cyan-500 bg-cyan-950/40" : "border-slate-600 bg-slate-900/40 hover:border-slate-500"}`}>
                        <input type="radio" name="export-type" checked={exportType === "reports"} onChange={() => { setExportType("reports"); setSelected(new Set()); setEnabledDocuments(new Set()); }} className="mt-1 accent-cyan-500" />
                        <FontAwesomeIcon icon={faFileLines} className="mt-0.5 text-cyan-400" aria-hidden="true" />
                        <span><span className="block font-medium text-white">Reports</span><span className="mt-1 block text-xs text-zinc-400">Built-in and custom reports, consolidated or separated by variant.</span></span>
                    </label>
                    <label className={`flex cursor-pointer items-start rounded-lg border ${embedded ? "gap-5 p-7" : "gap-3 p-4"} ${exportType === "sbom" ? "border-cyan-500 bg-cyan-950/40" : "border-slate-600 bg-slate-900/40 hover:border-slate-500"}`}>
                        <input type="radio" name="export-type" checked={exportType === "sbom"} onChange={() => { setExportType("sbom"); setMode("per_variant"); setSelected(new Set()); setEnabledDocuments(new Set()); }} className="mt-1 accent-cyan-500" />
                        <FontAwesomeIcon icon={faShieldHalved} className="mt-0.5 text-cyan-400" aria-hidden="true" />
                        <span><span className="block font-medium text-white">SBOM files</span><span className="mt-1 block text-xs text-zinc-400">Generated per variant and downloaded together as a ZIP archive.</span></span>
                    </label>
                </div>
                {exportType === "reports" && <section className="mt-6 border-t border-neutral-700 pt-5" aria-labelledby="output-layout-heading">
                    <h4 id="output-layout-heading" className="text-sm font-semibold text-white">Output layout</h4>
                    <p className="mt-1 text-xs text-neutral-400">Choose how project variants are represented in the archive.</p>
                    <div className={`mt-4 grid grid-cols-1 ${embedded ? "gap-5 xl:grid-cols-2" : "grid-cols-2 gap-3"}`}>
                    <label className={`flex cursor-pointer items-start rounded-lg border ${embedded ? "gap-5 p-7" : "gap-3 p-4"} ${mode === "consolidated" ? "border-cyan-500 bg-cyan-950/40" : "border-slate-600 bg-slate-900/40 hover:border-slate-500"}`}>
                        <input type="radio" name="export-mode" checked={mode === "consolidated"} onChange={() => setMode("consolidated")} className="mt-1 accent-cyan-500" />
                        <FontAwesomeIcon icon={faLayerGroup} className="mt-0.5 text-cyan-400" aria-hidden="true" />
                        <span><span className="block font-medium text-white">Consolidated</span><span className="mt-1 block text-xs text-zinc-400">Each selected document combines all project variants.</span></span>
                    </label>
                    <label className={`flex cursor-pointer items-start rounded-lg border ${embedded ? "gap-5 p-7" : "gap-3 p-4"} ${mode === "per_variant" ? "border-cyan-500 bg-cyan-950/40" : "border-slate-600 bg-slate-900/40 hover:border-slate-500"}`}>
                        <input type="radio" name="export-mode" checked={mode === "per_variant"} onChange={() => setMode("per_variant")} className="mt-1 accent-cyan-500" />
                        <FontAwesomeIcon icon={faBoxArchive} className="mt-0.5 text-cyan-400" aria-hidden="true" />
                        <span><span className="block font-medium text-white">One set per variant</span><span className="mt-1 block text-xs text-zinc-400">The ZIP contains a folder and selected files for each variant.</span></span>
                    </label>
                    </div>
                </section>}
            </>}

            {step === "documents" && <>
                <div className="flex items-start justify-between gap-4">
                    <div><h3 ref={stepHeadingRef} tabIndex={-1} className="text-base font-semibold text-white">Select {exportType === "sbom" ? "SBOM files" : "reports"}</h3><p className="mt-1 text-sm text-neutral-400">Choose every file to include in the export.</p></div>
                    <span className="text-sm font-semibold text-cyan-300">{selected.size} selected</span>
                </div>
                <div className="mt-4 flex flex-wrap gap-1 border-b border-neutral-700 pb-3">
                    {exportType === "reports" && reportCategories.map(([key, label]) => <button key={key} type="button" onClick={() => setCategory(key)} className={`rounded px-2.5 py-1 text-xs font-medium ${category === key ? "bg-cyan-800 text-white" : "text-neutral-400 hover:bg-neutral-800 hover:text-white"}`}>{label}</button>)}
                    <div className="ml-auto flex gap-2">
                        <button type="button" onClick={selectVisible} className="rounded border border-cyan-700 px-2.5 py-1 text-xs font-medium text-cyan-300 hover:bg-cyan-950/40 hover:text-white">Select visible</button>
                        <button type="button" onClick={clearVisible} className="rounded border border-neutral-600 px-2.5 py-1 text-xs font-medium text-neutral-300 hover:bg-neutral-800 hover:text-white">Clear visible</button>
                    </div>
                </div>
                <div className={`mt-3 grid grid-cols-1 gap-2 overflow-y-auto pr-1 ${embedded ? "max-h-96" : "max-h-56"}`}>
                    {selectionGroups.map(([name, documentSelections]) => {
                        const documentEnabled = enabledDocuments.has(name);
                        return <fieldset key={name} className={`rounded-lg border text-sm ${embedded ? "px-5 py-4" : "px-3 py-2.5"} ${documentEnabled ? "border-cyan-500 bg-cyan-950/40" : "border-slate-600 bg-slate-900/40"}`}>
                            <legend className="sr-only">{name}</legend>
                            <div className="flex items-center gap-3">
                                <FontAwesomeIcon icon={faFileLines} className="w-4 text-neutral-400" aria-hidden="true" />
                                <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 font-medium text-white">
                                    <input type="checkbox" aria-label="Include" checked={documentEnabled} onChange={() => toggleDocument(name, documentSelections)} className="accent-cyan-500" />
                                    <span aria-hidden="true" className="truncate">{name}</span>
                                </label>
                            </div>
                            <div className={`mt-2 flex flex-wrap items-center gap-4 border-t border-slate-700 pt-2 pl-7 ${documentEnabled ? "" : "opacity-40"}`}>
                                {documentSelections.map(selection => <label key={selection.key} className={`flex items-center gap-1.5 text-xs font-medium uppercase text-neutral-300 ${documentEnabled && documentSelections.length > 1 ? "cursor-pointer" : "cursor-not-allowed"}`}>
                                    <input type="checkbox" checked={selected.has(selection.key)} disabled={!documentEnabled || documentSelections.length === 1} onChange={() => toggleSelection(selection.key)} className="accent-cyan-500" />
                                    {selection.extension}
                                </label>)}
                            </div>
                        </fieldset>;
                    })}
                    {visibleSelections.length === 0 && <p className="py-8 text-center text-sm text-neutral-500">No documents in this category.</p>}
                </div>
                {error && <div role="alert" className="mt-3 rounded border border-red-700 bg-red-950/40 px-3 py-2 text-sm text-red-300">{error}</div>}
            </>}
        </ModalShell>
    );
}