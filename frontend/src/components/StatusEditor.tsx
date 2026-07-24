import { useState, useEffect, useCallback, useMemo } from "react";
import MessageBanner from './MessageBanner';
import type { Variant } from '../handlers/variant';
import { formatPkgId } from '../helpers/pkgId';

type PostAssessment = {
    vuln_id?: string,
    packages?: string[],
    status: string,
    justification?: string,
    impact_statement?: string,
    status_notes?: string,
    workaround?: string,
    variant_ids?: string[]
}

type Props = {
    onAddAssessment: (data: PostAssessment) => void;
    progressBar?: number;
    clearFields?: boolean;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
    defaultStatus?: string;
    variants?: Variant[];
    availablePackages?: string[];
    defaultSelectedPackages?: string[];
    /** variant_id -> packages that exist for this CVE in that variant */
    variantPackageMap?: Record<string, string[]>;
    /** variant_id -> historical findings that may be selected explicitly */
    variantFindingsMap?: Record<string, Array<{ pkg: string; outdated: boolean }>>;
    findingsLoading?: boolean;
}

function StatusEditor ({onAddAssessment, progressBar, clearFields: shouldClearFields, onFieldsChange, triggerBanner, defaultStatus = "under_investigation", variants, availablePackages, defaultSelectedPackages, variantPackageMap, variantFindingsMap, findingsLoading = false}: Readonly<Props>) {
    const outdatedPackages = useMemo(() => {
        const packages = new Set<string>();
        for (const finding of Object.values(variantFindingsMap ?? {}).flat()) {
            if (finding.outdated) packages.add(finding.pkg);
        }
        return packages;
    }, [variantFindingsMap]);
    const packagesWithCurrentFindings = useMemo(() => new Set(
        Object.values(variantFindingsMap ?? {}).flatMap(findings =>
            findings.filter(finding => !finding.outdated).map(finding => finding.pkg)
        )
    ), [variantFindingsMap]);
    const currentPackages = useMemo(
        () => (availablePackages ?? []).filter(pkg =>
            !outdatedPackages.has(pkg) || packagesWithCurrentFindings.has(pkg)
        ),
        [availablePackages, outdatedPackages, packagesWithCurrentFindings]
    );
    // When multiple choices exist, start fully unchecked so the user makes an
    // explicit selection; when exactly one exists auto-select it.
    const initialPackages = useMemo(() => {
        if (currentPackages.length === 1) return currentPackages;
        if (defaultSelectedPackages && defaultSelectedPackages.length === 1) return defaultSelectedPackages;
        return [];
    }, [defaultSelectedPackages, currentPackages]);

    const [status, setStatus] = useState(defaultStatus);
    const [justification, setJustification] = useState("none");
    const [statusNotes, setStatusNotes] = useState("");
    const [workaround, setWorkaround] = useState("");
    const [impact, setImpact] = useState("");
    const [selectedVariantIds, setSelectedVariantIds] = useState<string[]>(
        variants?.length === 1 ? [variants[0].id] : []
    );
    const [selectedPackages, setSelectedPackages] = useState<string[]>(initialPackages);
    const [includeOutdatedPackages, setIncludeOutdatedPackages] = useState(false);

    const packageOptions = useMemo(() => {
        const options = new Set(currentPackages);
        if (includeOutdatedPackages) {
            for (const pkg of outdatedPackages) options.add(pkg);
        }
        return [...options];
    }, [currentPackages, includeOutdatedPackages, outdatedPackages]);
    const effectiveVariantPackageMap = useMemo(() => {
        if (!variantPackageMap) return undefined;
        const result: Record<string, string[]> = {};
        for (const [variantId, packages] of Object.entries(variantPackageMap)) {
            const selectable = new Set(packages);
            if (includeOutdatedPackages) {
                for (const finding of variantFindingsMap?.[variantId] ?? []) {
                    if (finding.outdated) selectable.add(finding.pkg);
                }
            }
            result[variantId] = [...selectable];
        }
        return result;
    }, [variantPackageMap, variantFindingsMap, includeOutdatedPackages]);

    // Derived: which packages are reachable from the currently selected variants,
    // and which variants are reachable from the currently selected packages.
    const allowedPackages = useMemo<Set<string> | null>(() => {
        if (!effectiveVariantPackageMap) return null;

        // Use selected variant IDs if any are checked; otherwise derive from selected packages.
        let effectiveVariantIds: string[];
        if (selectedVariantIds.length > 0) {
            effectiveVariantIds = selectedVariantIds;
        } else if (selectedPackages.length > 0) {
            effectiveVariantIds = Object.entries(effectiveVariantPackageMap)
                .filter(([, pkgs]) => selectedPackages.some(p => pkgs.includes(p)))
                .map(([vid]) => vid);
        } else {
            return null;
        }

        const union = new Set<string>();
        for (const vid of effectiveVariantIds) {
            for (const pkg of effectiveVariantPackageMap[vid] ?? []) union.add(pkg);
        }
        return union.size > 0 ? union : null;
    }, [effectiveVariantPackageMap, selectedVariantIds, selectedPackages]);

    const allowedVariants = useMemo<Set<string> | null>(() => {
        if (!effectiveVariantPackageMap) return null;

        // Use selected packages if any are checked; otherwise derive from selected variants.
        let effectivePackages: string[];
        if (selectedPackages.length > 0) {
            effectivePackages = selectedPackages;
        } else if (selectedVariantIds.length > 0) {
            const union = new Set<string>();
            for (const vid of selectedVariantIds) {
                for (const pkg of effectiveVariantPackageMap[vid] ?? []) union.add(pkg);
            }
            effectivePackages = [...union];
        } else {
            return null;
        }

        const allowed = new Set<string>();
        for (const [vid, pkgs] of Object.entries(effectiveVariantPackageMap)) {
            if (effectivePackages.some(p => pkgs.includes(p))) allowed.add(vid);
        }
        return allowed.size > 0 ? allowed : null;
    }, [effectiveVariantPackageMap, selectedPackages, selectedVariantIds]);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);

    const internalTriggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    // Reset selected packages when the available list changes (e.g. navigating to a different vuln)
    useEffect(() => {
        setSelectedPackages(initialPackages);
    }, [initialPackages]);

    // Auto-select single variant when variants load asynchronously (e.g. Edit from Actions column)
    useEffect(() => {
        setSelectedVariantIds(variants?.length === 1 ? [variants[0].id] : []);
    }, [variants]);

    // When a variant is unchecked, drop packages that are no longer reachable.
    const handleVariantToggle = (variantId: string, checked: boolean) => {
        const nextVariants = checked
            ? [...selectedVariantIds, variantId]
            : selectedVariantIds.filter(id => id !== variantId);
        setSelectedVariantIds(nextVariants);

        if (!checked && effectiveVariantPackageMap) {
            const stillAllowed = new Set<string>();
            for (const vid of nextVariants) {
                for (const pkg of effectiveVariantPackageMap[vid] ?? []) stillAllowed.add(pkg);
            }
            if (stillAllowed.size > 0) {
                setSelectedPackages(prev => prev.filter(p => stillAllowed.has(p)));
            } else {
                setSelectedPackages([]);
            }
        }
    };

    // When a package is toggled, drop variants that are no longer compatible.
    // Runs on both check and uncheck so a variant that was selected before a
    // conflicting package is checked gets automatically deselected.
    const handlePackageToggle = (pkg: string, checked: boolean) => {
        const nextPackages = checked
            ? [...selectedPackages, pkg]
            : selectedPackages.filter(p => p !== pkg);
        setSelectedPackages(nextPackages);

        if (effectiveVariantPackageMap && nextPackages.length > 0) {
            setSelectedVariantIds(prev =>
                prev.filter(vid =>
                    nextPackages.some(p => (effectiveVariantPackageMap[vid] ?? []).includes(p))
                )
            );
        }
    };

    const handleIncludeOutdatedPackages = (checked: boolean) => {
        setIncludeOutdatedPackages(checked);
        if (!checked) {
            setSelectedPackages(prev => prev.filter(pkg => !outdatedPackages.has(pkg)));
        }
    };

    // Update status when defaultStatus prop changes
    useEffect(() => {
        setStatus(defaultStatus);
    }, [defaultStatus]);

    // Check if fields have changes
    useEffect(() => {
        const hasChanges = (
            status !== defaultStatus ||
            justification !== "none" ||
            statusNotes !== "" ||
            workaround !== "" ||
            impact !== ""
        );
        onFieldsChange?.(hasChanges);
    }, [status, justification, statusNotes, workaround, impact, onFieldsChange, defaultStatus]);

    function addAssessment () {
        if (status == '' || justification == '')
            return;
        if (status == "not_affected" && justification == 'none') {
            if (triggerBanner) {
                triggerBanner("You must provide a justification for this status", "error");
            } else {
                internalTriggerBanner("You must provide a justification for this status", "error");
            }
            return;
        }
        if (status == "false_positive" && impact == '') {
            if (triggerBanner) {
                triggerBanner("You must provide an impact statement for false positive status", "error");
            } else {
                internalTriggerBanner("You must provide an impact statement for false positive status", "error");
            }
            return;
        }
        if (variants && variants.length > 0 && selectedVariantIds.length === 0) {
            if (triggerBanner) {
                triggerBanner("You must select at least one variant", "error");
            } else {
                internalTriggerBanner("You must select at least one variant", "error");
            }
            return;
        }
        if (availablePackages && availablePackages.length > 0 && selectedPackages.length === 0) {
            if (triggerBanner) {
                triggerBanner("You must select at least one package", "error");
            } else {
                internalTriggerBanner("You must select at least one package", "error");
            }
            return;
        }
        onAddAssessment({
            status,
            justification: status == "not_affected" ? justification : undefined,
            status_notes: statusNotes,
            workaround,
            impact_statement: (status == "not_affected" || status == "false_positive") ? impact : undefined,
            variant_ids: selectedVariantIds.length > 0 ? selectedVariantIds : undefined,
            packages: selectedPackages.length > 0 ? selectedPackages : (availablePackages ?? [])
        });
    }

    const clearInputs = useCallback(() => {
        setStatus(defaultStatus);
        setJustification("none");
        setStatusNotes("");
        setWorkaround("");
        setImpact("");
        setIncludeOutdatedPackages(false);
        setSelectedVariantIds(variants?.length === 1 ? [variants[0].id] : []);
        setSelectedPackages(
            (availablePackages?.length === 1 ? availablePackages :
            defaultSelectedPackages?.length === 1 ? defaultSelectedPackages : [])
        );
    }, [defaultStatus, defaultSelectedPackages, availablePackages, variants]);

    useEffect(() => {
        if (shouldClearFields) {
            clearInputs();
        }
    }, [shouldClearFields, clearInputs]);

    return (<>
        {!triggerBanner && bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}

        <h3 className="m-1">
            Status:
            <select
                value={status}
                onChange={(event) => setStatus(event.target.value)}
                className="p-1 px-2 bg-gray-800 mr-4"
                name="new_assessment_status"
            >
                <option value="under_investigation">Pending Assessment</option>
                <option value="affected">Affected / exploitable</option>
                <option value="fixed">Fixed / patched</option>
                <option value="not_affected">Not applicable</option>
                <option value="false_positive">False positive</option>
            </select>
            {status == "not_affected" && <>
                Justification:
                <select
                    value={justification}
                    onChange={(event) => setJustification(event.target.value)}
                    className="p-1 px-2 bg-gray-800"
                    name="new_assessment_justification"
                >
                    <option value="none">No justification</option>
                    <option value="component_not_present">Component not present</option>
                    <option value="vulnerable_code_not_present">vulnerable code not present</option>
                    <option value="code_not_reachable">The vulnerable code is not invoked at runtime</option>
                    <option value="requires_configuration">Exploitability requires a configurable option to be set/unset</option>
                    <option value="requires_environment">Exploitability requires a certain environment which is not present</option>
                    <option value="inline_mitigations_already_exist">Inline Mitigation already exist</option>
                </select>
            </>}
        </h3>
        {variants && variants.length > 0 && (
            <div className="mt-3 rounded-lg border border-gray-600 bg-gray-800/40 p-3">
                <p className="mb-2 text-sm font-medium text-gray-200">Apply to variants:</p>
                <span className="float-right -mt-7 text-xs text-gray-400">{selectedVariantIds.length} selected</span>
                <div className="flex flex-wrap gap-2">
                    {variants.map(v => {
                        const incompatible = allowedVariants !== null && !allowedVariants.has(v.id);
                        const selected = selectedVariantIds.includes(v.id);
                        return (
                        <label
                            key={v.id}
                            className={[
                                'inline-flex items-center rounded-full border px-3 py-1.5 text-sm font-medium transition-colors select-none',
                                selected ? 'border-blue-400 bg-blue-500/20 text-blue-100' : 'border-gray-600 bg-gray-700/60 text-gray-300 hover:border-gray-500',
                                incompatible ? 'cursor-not-allowed opacity-40' : 'cursor-pointer',
                            ].join(' ')}
                            title={incompatible ? 'Not every selected package version applies to this variant' : undefined}
                        >
                            <input
                                type="checkbox"
                                checked={selected}
                                disabled={incompatible}
                                onChange={(e) => handleVariantToggle(v.id, e.target.checked)}
                                className="sr-only"
                            />
                            <span aria-hidden="true" className="mr-1.5 text-xs">{selected ? '✓' : '+'}</span>
                            <span>{v.name}</span>
                        </label>
                        );
                    })}
                </div>
            </div>
        )}
        {availablePackages && (availablePackages.length >= 1 || outdatedPackages.size > 0) && (
            <div className="mt-3 rounded-lg border border-gray-600 bg-gray-800/40 p-3">
                <p className="mb-2 text-sm font-medium text-gray-200">Apply to packages:</p>
                <span className="float-right -mt-7 text-xs text-gray-400">{selectedPackages.length} selected</span>
                {findingsLoading && (
                    <p className="mb-2 text-xs text-gray-400 animate-pulse">Checking for previous package versions…</p>
                )}
                {!findingsLoading && outdatedPackages.size > 0 && (
                    <label className="mb-3 flex items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-200 cursor-pointer select-none">
                        <span>
                            <span className="block font-medium">Include previous package versions</span>
                            <span className="block text-xs text-amber-200/70">Show package versions from previous scans ({outdatedPackages.size})</span>
                        </span>
                        <input
                            type="checkbox"
                            aria-label="Include previous package versions"
                            checked={includeOutdatedPackages}
                            onChange={event => handleIncludeOutdatedPackages(event.target.checked)}
                            className="h-4 w-4 accent-amber-500"
                        />
                    </label>
                )}
                <div className="flex flex-wrap gap-2">
                    {packageOptions.map(pkg => {
                        const isActive = !defaultSelectedPackages || defaultSelectedPackages.length === 0 || defaultSelectedPackages.includes(pkg);
                        const isOutdated = outdatedPackages.has(pkg);
                        const incompatible = allowedPackages !== null && !allowedPackages.has(pkg);
                        const selected = selectedPackages.includes(pkg);
                        return (
                        <label
                            key={pkg}
                            className={[
                                'inline-flex items-center rounded-full border px-3 py-1.5 text-sm transition-colors select-none',
                                selected ? 'border-blue-400 bg-blue-500/20 text-blue-100' : 'border-gray-600 bg-gray-700/60 text-gray-300 hover:border-gray-500',
                                incompatible ? 'cursor-not-allowed opacity-40' : 'cursor-pointer',
                            ].join(' ')}
                            title={incompatible ? 'This package version does not apply to every selected variant' : (isOutdated ? 'From a previous scan' : undefined)}
                        >
                            <input
                                type="checkbox"
                                checked={selected}
                                disabled={incompatible}
                                onChange={(e) => handlePackageToggle(pkg, e.target.checked)}
                                className="sr-only"
                            />
                            <span aria-hidden="true" className="mr-1.5 text-xs">{selected ? '✓' : '+'}</span>
                            <span className={`font-mono ${incompatible ? 'text-gray-500' : isActive ? '' : 'italic'}`}>{formatPkgId(pkg)}</span>
                        </label>
                        );
                    })}
                </div>
            </div>
        )}
        {(status == "not_affected" || status == "false_positive") && <>
            <textarea
                value={impact}
                onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setImpact(event.target.value)}
                name="new_assessment_impact"
                className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 resize-vertical whitespace-pre-wrap"
                rows={3}
                placeholder="why this vulnerability is not exploitable ?"
            /><br/>
        </>}
        <textarea
            value={statusNotes}
            onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setStatusNotes(event.target.value)}
            name="new_assessment_status_notes"
            className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 resize-vertical whitespace-pre-wrap"
            rows={3}
            placeholder="Free text notes about your review, details, actions taken, ..."
        /><br/>
        <textarea
            value={workaround}
            onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setWorkaround(event.target.value)}
            name="new_assessment_workaround"
            className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 text-white resize-vertical whitespace-pre-wrap"
            rows={3}
            placeholder="Describe workaround here if available"
        /><br/>
        <button
            onClick={addAssessment}
            type="button"
            className="mt-2 bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center"
        >Add assessment</button>

        {progressBar !== undefined && <div className="p-4 pb-1 w-full">
             <progress max={1} value={progressBar} className="w-full h-2"></progress>
        </div>}
    </>);
}

export default StatusEditor

export type {PostAssessment}
