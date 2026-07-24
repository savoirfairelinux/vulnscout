import { useState, useEffect, useCallback, useMemo } from "react";
import type { Assessment } from "../handlers/assessments";
import type { Variant } from '../handlers/variant';
import MessageBanner from './MessageBanner';
import { formatPkgId } from '../helpers/pkgId';

type EditAssessmentData = {
    id: string;
    status: string;
    justification?: string;
    impact_statement?: string;
    status_notes?: string;
    workaround?: string;
    variant_ids?: string[];
    packages?: string[];
}

type Props = {
    assessment: Assessment;
    onSaveAssessment: (data: EditAssessmentData) => void;
    onCancel: () => void;
    clearFields?: boolean;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
    availableVariants?: Variant[];
    defaultSelectedVariantIds?: string[];
    availablePackages?: string[];
    defaultSelectedPackages?: string[];
    variantPackageMap?: Record<string, string[]>;
    variantFindingsMap?: Record<string, Array<{ pkg: string; outdated: boolean }>>;
    findingsLoading?: boolean;
}

function EditAssessment({
    assessment,
    onSaveAssessment,
    onCancel,
    clearFields: shouldClearFields,
    onFieldsChange,
    triggerBanner,
    availableVariants,
    defaultSelectedVariantIds,
    availablePackages,
    defaultSelectedPackages,
    variantPackageMap,
    variantFindingsMap,
    findingsLoading = false
}: Readonly<Props>) {
    const isImpactStatus = assessment.status === 'not_affected' || assessment.status === 'false_positive';
    const [status, setStatus] = useState(assessment.status || "under_investigation");
    const [justification, setJustification] = useState(assessment.justification || "none");
    // For non-impact statuses (fixed, affected, …) Yocto stores its notes in impact_statement.
    // Pre-fill status_notes with that value so users see it in the right field.
    const [statusNotes, setStatusNotes] = useState(
        assessment.status_notes || (!isImpactStatus ? (assessment.impact_statement || "") : "")
    );
    const [workaround, setWorkaround] = useState(assessment.workaround || "");
    const [impact, setImpact] = useState(isImpactStatus ? (assessment.impact_statement || "") : "");
    const [selectedVariantIds, setSelectedVariantIds] = useState<string[]>(
        defaultSelectedVariantIds ?? (availableVariants?.length === 1 ? [availableVariants[0].id] : [])
    );
    const [selectedPackages, setSelectedPackages] = useState<string[]>(
        defaultSelectedPackages ?? (availablePackages?.length === 1 ? [availablePackages[0]] : [])
    );
    const [includeOutdatedPackages, setIncludeOutdatedPackages] = useState(false);
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
    const packageOptions = useMemo(() => {
        const options = new Set((availablePackages ?? []).filter(pkg =>
            !outdatedPackages.has(pkg) || packagesWithCurrentFindings.has(pkg)
        ));
        for (const pkg of defaultSelectedPackages ?? []) options.add(pkg);
        if (includeOutdatedPackages) {
            for (const pkg of outdatedPackages) options.add(pkg);
        }
        return [...options];
    }, [availablePackages, defaultSelectedPackages, includeOutdatedPackages, outdatedPackages, packagesWithCurrentFindings]);
    const effectiveVariantPackageMap = useMemo(() => {
        if (!variantPackageMap) return undefined;
        const result: Record<string, string[]> = {};
        for (const [variantId, packages] of Object.entries(variantPackageMap)) {
            const selectable = new Set(packages);
            for (const finding of variantFindingsMap?.[variantId] ?? []) {
                if (finding.outdated && (includeOutdatedPackages || defaultSelectedPackages?.includes(finding.pkg))) {
                    selectable.add(finding.pkg);
                }
            }
            result[variantId] = [...selectable];
        }
        return result;
    }, [variantPackageMap, variantFindingsMap, defaultSelectedPackages, includeOutdatedPackages]);

    // Derived: which packages are reachable from the currently selected variants,
    // and which variants are reachable from the currently selected packages.
    const allowedPackages = useMemo<Set<string> | null>(() => {
        if (!effectiveVariantPackageMap) return null;

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
            const originalPackages = new Set(defaultSelectedPackages ?? []);
            setSelectedPackages(prev => prev.filter(pkg =>
                !outdatedPackages.has(pkg) || originalPackages.has(pkg)
            ));
        }
    };
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

    // Check if fields have changes compared to original assessment
    useEffect(() => {
        const initialStatusNotes = assessment.status_notes || (!isImpactStatus ? (assessment.impact_statement || "") : "");
        const hasChanges = (
            status !== assessment.status ||
            justification !== (assessment.justification || "none") ||
            statusNotes !== initialStatusNotes ||
            workaround !== (assessment.workaround || "") ||
            impact !== (isImpactStatus ? (assessment.impact_statement || "") : "")
        );
        onFieldsChange?.(hasChanges);
    }, [status, justification, statusNotes, workaround, impact, onFieldsChange, assessment, isImpactStatus]);

    // Auto-select single variant when availableVariants load asynchronously (e.g. Edit from Actions column)
    useEffect(() => {
        setSelectedVariantIds(defaultSelectedVariantIds ?? (availableVariants?.length === 1 ? [availableVariants[0].id] : []));
    }, [availableVariants, defaultSelectedVariantIds]);

    function saveAssessment() {
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

        if (availableVariants && availableVariants.length > 0 && selectedVariantIds.length === 0) {
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

        // Justification only applies to not_affected; the impact statement
        // applies to both not_affected and false_positive (mirrors StatusEditor).
        const includeJustification = status == "not_affected";
        const includeImpact = status == "not_affected" || status == "false_positive";

        onSaveAssessment({
            id: assessment.id,
            status,
            justification: includeJustification ? justification : undefined,
            status_notes: statusNotes,
            workaround,
            // For non-impact statuses the value was folded into status_notes; clear impact_statement.
            impact_statement: includeImpact ? impact : "",
            variant_ids: selectedVariantIds.length > 0 ? selectedVariantIds : undefined,
            packages: selectedPackages.length > 0 ? selectedPackages : (availablePackages ?? [])
        });
    }

    const resetToOriginal = useCallback(() => {
        setStatus(assessment.status || "under_investigation");
        setJustification(assessment.justification || "none");
        setStatusNotes(assessment.status_notes || (!isImpactStatus ? (assessment.impact_statement || "") : ""));
        setWorkaround(assessment.workaround || "");
        setImpact(isImpactStatus ? (assessment.impact_statement || "") : "");
        setIncludeOutdatedPackages(false);
        setSelectedVariantIds(defaultSelectedVariantIds ?? (availableVariants?.length === 1 ? [availableVariants[0].id] : []));
        setSelectedPackages(defaultSelectedPackages ?? (availablePackages?.length === 1 ? [availablePackages[0]] : []));
    }, [assessment, isImpactStatus, defaultSelectedVariantIds, defaultSelectedPackages, availableVariants, availablePackages]);

    useEffect(() => {
        if (shouldClearFields) {
            resetToOriginal();
        }
    }, [shouldClearFields, resetToOriginal]);

    return (
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-600">
            {!triggerBanner && bannerVisible && (
                <MessageBanner
                    type={bannerType}
                    message={bannerMessage}
                    isVisible={bannerVisible}
                    onClose={closeBanner}
                />
            )}

            <h4 className="text-lg font-semibold text-white mb-3">Edit Assessment</h4>

            <h3 className="m-1 text-white">
                Status:
                <select
                    value={status}
                    onChange={(event) => setStatus(event.target.value)}
                    className="p-1 px-2 bg-gray-700 text-white mr-4 ml-2 rounded"
                    name="edit_assessment_status"
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
                        className="p-1 px-2 bg-gray-700 text-white ml-2 rounded"
                        name="edit_assessment_justification"
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

            {availableVariants && availableVariants.length > 0 && (
                <div className="mt-3 rounded-lg border border-gray-600 bg-gray-800/40 p-3">
                    <p className="mb-2 text-sm font-medium text-gray-200">Apply to variants:</p>
                    <span className="float-right -mt-7 text-xs text-gray-400">{selectedVariantIds.length} selected</span>
                    <div className="flex flex-wrap gap-2">
                        {availableVariants.map(v => {
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
            {availablePackages && (packageOptions.length > 1 || outdatedPackages.size > 0) && (
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
                                <span className={`font-mono ${incompatible ? 'text-gray-500' : ''}`}>{formatPkgId(pkg)}</span>
                            </label>
                            );
                        })}
                    </div>
                </div>
            )}

            {(status === 'not_affected' || status === 'false_positive') && (
                <><textarea
                        value={impact}
                        onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setImpact(event.target.value)}
                        name="edit_assessment_impact"
                        className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded resize-vertical whitespace-pre-wrap"
                        rows={3}
                        placeholder="Why this vulnerability is not exploitable?"
                    /><br/></>
            )}

                <textarea
                    value={statusNotes}
                    onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setStatusNotes(event.target.value)}
                    name="edit_assessment_status_notes"
                    className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded resize-vertical whitespace-pre-wrap"
                    rows={3}
                    placeholder="Free text notes about your review, details, actions taken, ..."
                /><br/>

                <textarea
                    value={workaround}
                    onChange={(event: React.ChangeEvent<HTMLTextAreaElement>) => setWorkaround(event.target.value)}
                    name="edit_assessment_workaround"
                    className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded resize-vertical whitespace-pre-wrap"
                    rows={3}
                    placeholder="Describe workaround here if available"
                /><br/>

            <div className="flex gap-2 mt-3">
                <button
                    onClick={saveAssessment}
                    type="button"
                    className="bg-green-600 hover:bg-green-700 focus:ring-4 focus:outline-none focus:ring-green-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                >
                    Save Changes
                </button>
                <button
                    onClick={onCancel}
                    type="button"
                    className="bg-gray-600 hover:bg-gray-700 focus:ring-4 focus:outline-none focus:ring-gray-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                >
                    Cancel
                </button>
            </div>
        </div>
    );
}

export default EditAssessment;
export type { EditAssessmentData };
