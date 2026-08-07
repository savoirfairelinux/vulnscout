import { useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBug, faCircleQuestion, faCrosshairs, faLeaf, faPlay, faShieldHalved, faXmark } from "@fortawesome/free-solid-svg-icons";
import type { Variant } from "../handlers/variant";
import { refreshSourcesForScans } from "../helpers/refreshSources";

type Props = {
    isOpen: boolean;
    variants: Variant[];
    selectedVariantIds: Set<string>;
    selectedScanTypes: Set<string>;
    selectedRefreshTypes: Set<string>;
    refreshMode: "complete" | "custom";
    excludeKernel: boolean;
    onClose: () => void;
    onToggleVariant: (variantId: string) => void;
    onToggleScanType: (scanType: string) => void;
    onToggleRefreshType: (refreshType: string) => void;
    onRefreshModeChange: (mode: "complete" | "custom") => void;
    onSelectAllVariants: () => void;
    onSelectNoVariants: () => void;
    onExcludeKernelChange: (exclude: boolean) => void;
    onLaunch: () => void;
};

const scanTypes = [
    { key: "grype", label: "Grype", description: "Matches SBOM packages against Grype vulnerability databases.", icon: faBug, iconClass: "text-purple-400" },
    { key: "nvd", label: "NVD CPE", description: "Matches package CPEs against National Vulnerability Database records.", icon: faShieldHalved, iconClass: "text-orange-400" },
    { key: "osv", label: "OSV", description: "Queries the Open Source Vulnerabilities database for affected package versions.", icon: faLeaf, iconClass: "text-green-400" },
    { key: "scc", label: "sbom-cve-check", description: "Checks the SBOM against CVE data using sbom-cve-check.", icon: faCrosshairs, iconClass: "text-sky-400" },
] as const;

const refreshTypes = [
    { key: "nvd", label: "FKIE", description: "Refresh local NVD-FKIE data for newly discovered CVEs." },
    { key: "epss", label: "EPSS", description: "Refresh exploit prediction scores for newly discovered CVEs." },
    { key: "euvd", label: "ENISA EUVD", description: "Refresh EU vulnerability data for newly discovered CVEs." },
] as const;

const stepLabels = ["Scans", "Variants", "Kernel", "Refresh", "Review"] as const;
const reviewStep = stepLabels.length;

export default function RunScansWizard({
    isOpen,
    variants,
    selectedVariantIds,
    selectedScanTypes,
    selectedRefreshTypes,
    refreshMode,
    excludeKernel,
    onClose,
    onToggleVariant,
    onToggleScanType,
    onToggleRefreshType,
    onRefreshModeChange,
    onSelectAllVariants,
    onSelectNoVariants,
    onExcludeKernelChange,
    onLaunch,
}: Readonly<Props>) {
    const [step, setStep] = useState(1);
    const [showKernelHelp, setShowKernelHelp] = useState(false);
    const dialogRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!isOpen) return;
        setStep(1);
        setShowKernelHelp(false);
        dialogRef.current?.focus();
    }, [isOpen]);

    useEffect(() => {
        if (!isOpen) return;
        function handleEscape(event: KeyboardEvent) {
            if (event.key === "Escape") onClose();
        }
        document.addEventListener("keydown", handleEscape);
        return () => document.removeEventListener("keydown", handleEscape);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    const availableRefreshTypes: Set<string> = refreshSourcesForScans(selectedScanTypes);
    const effectiveRefreshTypes = refreshMode === "complete"
        ? availableRefreshTypes
        : new Set([...selectedRefreshTypes].filter(type => availableRefreshTypes.has(type)));
    const nextDisabled = (step === 1 && selectedScanTypes.size === 0)
        || (step === 2 && selectedVariantIds.size === 0);

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) onClose();
            }}
        >
            <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="scan-wizard-title" className="w-full max-w-xl rounded-lg border border-sky-700/60 bg-neutral-900 shadow-xl outline-none">
                <div className="border-b border-neutral-700 px-6 py-4">
                    <div className="flex items-center justify-between gap-4">
                        <div>
                            <h2 id="scan-wizard-title" className="text-lg font-semibold text-white">Run scans</h2>
                            <p className="mt-1 text-sm text-neutral-400">Step {step} of {reviewStep}</p>
                        </div>
                        <button type="button" onClick={onClose} className="text-neutral-400 hover:text-white" aria-label="Close scan wizard">
                            <FontAwesomeIcon icon={faXmark} />
                        </button>
                    </div>
                    <ol className="mt-4 grid grid-cols-5 gap-2 text-xs">
                        {stepLabels.map((label, index) => (
                            <li key={label} className={index + 1 <= step ? "text-cyan-300" : "text-neutral-500"}>
                                <span className="mr-1 font-semibold">{index + 1}.</span>{label}
                            </li>
                        ))}
                    </ol>
                </div>

                <div className="min-h-72 px-6 py-5">
                    {step === 1 && <>
                        <h3 className="text-base font-semibold text-white">Select scans</h3>
                        <p className="mt-1 text-sm text-neutral-400">Choose the vulnerability scanners to run.</p>
                        <div className="mt-4 grid grid-cols-1 gap-2">
                            {scanTypes.map(({ key, label, description, icon, iconClass }) => (
                                <label key={key} className={[
                                    "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-3 text-sm transition-colors",
                                    selectedScanTypes.has(key)
                                        ? "border-cyan-500 bg-cyan-950/40 text-white"
                                        : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                ].join(" ")}>
                                    <input type="checkbox" checked={selectedScanTypes.has(key)} onChange={() => onToggleScanType(key)} className="mt-0.5 accent-cyan-500" />
                                    <FontAwesomeIcon icon={icon} className={`${iconClass} mt-0.5 w-4`} />
                                    <span className="flex flex-col"><span className="font-medium">{label}</span><span className="mt-1 text-xs text-zinc-400">{description}</span></span>
                                </label>
                            ))}
                        </div>
                    </>}

                    {step === 2 && <>
                        <h3 className="text-base font-semibold text-white">Select context variants</h3>
                        <p className="mt-1 text-sm text-neutral-400">Choose the variants whose SBOMs should be scanned.</p>
                        <div className="mt-4 grid max-h-48 grid-cols-1 gap-2 overflow-y-auto pr-1">
                            {variants.length === 0 && <span className="text-sm text-neutral-500 italic">No variants found</span>}
                            {variants.map((variant) => (
                                <label key={variant.id} className={[
                                    "flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm transition-colors",
                                    selectedVariantIds.has(variant.id)
                                        ? "border-cyan-500 bg-cyan-950/40 text-white"
                                        : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                ].join(" ")}>
                                    <input type="checkbox" checked={selectedVariantIds.has(variant.id)} onChange={() => onToggleVariant(variant.id)} className="accent-cyan-500" />
                                    <span className="truncate font-medium">{variant.name}</span>
                                </label>
                            ))}
                        </div>
                        {variants.length > 1 && <div className="mt-3 flex gap-3">
                            <button type="button" onClick={onSelectAllVariants} className="text-xs text-sky-400 hover:text-sky-300">Select all</button>
                            <button type="button" onClick={onSelectNoVariants} className="text-xs text-sky-400 hover:text-sky-300">Select none</button>
                        </div>}
                    </>}

                    {step === 3 && <>
                        <h3 className="text-base font-semibold text-white">Exclude kernel packages?</h3>
                        <p className="mt-1 text-sm text-neutral-400">The main kernel package is always scanned.</p>
                        <div className="mt-5 grid grid-cols-2 gap-3">
                            <label className={[
                                "flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-3 transition-colors",
                                excludeKernel ? "border-cyan-500 bg-cyan-950/40 text-white" : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                            ].join(" ")}>
                                <input type="radio" name="exclude-kernel" checked={excludeKernel} onChange={() => onExcludeKernelChange(true)} className="mt-0.5 accent-cyan-500" />
                                <span className="flex flex-col"><span className="font-medium">Yes</span><span className="mt-1 text-xs text-zinc-400">Avoid duplicate kernel findings.</span></span>
                            </label>
                            <label className={[
                                "flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-3 transition-colors",
                                !excludeKernel ? "border-cyan-500 bg-cyan-950/40 text-white" : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                            ].join(" ")}>
                                <input type="radio" name="exclude-kernel" checked={!excludeKernel} onChange={() => onExcludeKernelChange(false)} className="mt-0.5 accent-cyan-500" />
                                <span className="flex flex-col"><span className="font-medium">No</span><span className="mt-1 text-xs text-zinc-400">Scan every kernel-related package.</span></span>
                            </label>
                        </div>
                        <button type="button" onClick={() => setShowKernelHelp(value => !value)} className="mt-4 text-sm text-sky-300 hover:text-sky-200">
                            <FontAwesomeIcon icon={faCircleQuestion} className="mr-2" />Why exclude kernel packages?
                        </button>
                        {showKernelHelp && <p className="mt-2 rounded border border-sky-700/40 bg-sky-900/30 p-3 text-xs leading-relaxed text-sky-200">Yocto kernel recipes create many companion packages that share the same kernel CPE. Excluding those companions avoids duplicate findings and slower scans while retaining CVE coverage for the real kernel package.</p>}
                    </>}

                    {step === 4 && <>
                        <h3 className="text-base font-semibold text-white">Refresh data</h3>
                        <p className="mt-1 text-sm text-neutral-400">Optionally refresh data for vulnerabilities found by this scan.</p>
                        <div className="mt-4 grid grid-cols-2 gap-3">
                            {([
                                ["complete", "Complete refresh", "Refresh every source applicable to the selected scans."],
                                ["custom", "Custom refresh", "Choose which applicable sources to refresh."],
                            ] as const).map(([mode, label, description]) => (
                                <label key={mode} className={[
                                    "flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-3 transition-colors",
                                    refreshMode === mode ? "border-cyan-500 bg-cyan-950/40 text-white" : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                ].join(" ")}>
                                    <input type="radio" name="refresh-mode" checked={refreshMode === mode} onChange={() => onRefreshModeChange(mode)} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="font-medium">{label}</span><span className="mt-1 text-xs text-zinc-400">{description}</span></span>
                                </label>
                            ))}
                        </div>
                        {availableRefreshTypes.size === 0 && <p className="mt-4 text-sm text-neutral-500">The selected scans do not produce CVEs that can be refreshed.</p>}
                        {refreshMode === "custom" && availableRefreshTypes.size > 0 && <div className="mt-4 grid grid-cols-1 gap-2">
                            {refreshTypes.filter(({ key }) => availableRefreshTypes.has(key)).map(({ key, label, description }) => (
                                <label key={key} className={[
                                    "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-3 text-sm transition-colors",
                                    selectedRefreshTypes.has(key)
                                        ? "border-cyan-500 bg-cyan-950/40 text-white"
                                        : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                ].join(" ")}>
                                    <input type="checkbox" checked={selectedRefreshTypes.has(key)} onChange={() => onToggleRefreshType(key)} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="font-medium">{label}</span><span className="mt-1 text-xs text-zinc-400">{description}</span></span>
                                </label>
                            ))}
                        </div>}
                    </>}

                    {step === reviewStep && <>
                        <h3 className="text-base font-semibold text-white">Review and launch</h3>
                        <p className="mt-1 text-sm text-neutral-400">Check the launch configuration before starting the scan queue.</p>
                        <div className="mt-5 space-y-3 text-sm">
                            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4">
                                <div className="flex items-start justify-between gap-4"><div><h4 className="font-semibold text-white">Scans</h4><p className="mt-1 text-zinc-300">{scanTypes.filter(({ key }) => selectedScanTypes.has(key)).map(({ label }) => label).join(", ")}</p></div><button type="button" onClick={() => setStep(1)} className="text-xs font-semibold text-cyan-300 hover:text-cyan-200" aria-label="Edit scans">Edit</button></div>
                            </section>
                            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4">
                                <div className="flex items-start justify-between gap-4"><div><h4 className="font-semibold text-white">Context variants</h4><p className="mt-1 text-zinc-300">{variants.filter(variant => selectedVariantIds.has(variant.id)).map(variant => variant.name).join(", ")}</p></div><button type="button" onClick={() => setStep(2)} className="text-xs font-semibold text-cyan-300 hover:text-cyan-200" aria-label="Edit context variants">Edit</button></div>
                            </section>
                            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4">
                                <div className="flex items-start justify-between gap-4"><div><h4 className="font-semibold text-white">Kernel packages</h4><p className="mt-1 text-zinc-300">{excludeKernel ? "Excluded" : "Included"}</p></div><button type="button" onClick={() => setStep(3)} className="text-xs font-semibold text-cyan-300 hover:text-cyan-200" aria-label="Edit kernel package selection">Edit</button></div>
                            </section>
                            <section className="rounded-lg border border-slate-600 bg-slate-900/40 p-4">
                                <div className="flex items-start justify-between gap-4"><div><h4 className="font-semibold text-white">Vulnerability data refresh</h4><p className="mt-1 text-zinc-300">{refreshTypes.filter(({ key }) => effectiveRefreshTypes.has(key)).map(({ label }) => label).join(", ") || "No refresh selected"}</p></div><button type="button" onClick={() => setStep(4)} className="text-xs font-semibold text-cyan-300 hover:text-cyan-200" aria-label="Edit vulnerability data refresh">Edit</button></div>
                            </section>
                        </div>
                    </>}
                </div>

                <div className="flex items-center justify-between border-t border-neutral-700 px-6 py-4">
                    <button type="button" onClick={() => setStep(value => value - 1)} disabled={step === 1} className="rounded px-3 py-1.5 text-sm font-semibold text-neutral-300 hover:bg-neutral-800 disabled:cursor-not-allowed disabled:text-neutral-600">Back</button>
                    {step < reviewStep ? (
                        <button type="button" onClick={() => setStep(value => value + 1)} disabled={nextDisabled} className="rounded bg-cyan-700 px-3 py-1.5 text-sm font-semibold text-white hover:bg-cyan-600 disabled:cursor-not-allowed disabled:bg-neutral-700 disabled:text-neutral-500">Next</button>
                    ) : (
                        <button type="button" onClick={onLaunch} className="rounded bg-cyan-700 px-3 py-1.5 text-sm font-semibold text-white hover:bg-cyan-600"><FontAwesomeIcon icon={faPlay} className="mr-2" />Launch scans</button>
                    )}
                </div>
            </div>
        </div>
    );
}