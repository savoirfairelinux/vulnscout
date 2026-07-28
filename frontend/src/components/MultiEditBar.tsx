import { useState, useMemo, useEffect } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faXmark, faPenToSquare, faClock } from '@fortawesome/free-solid-svg-icons';
import type { Vulnerability } from "../handlers/vulnerabilities";
import { buildStatusSummary } from "../handlers/vulnerabilities";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import TimeEstimateEditor from "./TimeEstimateEditor";
import type { PostTimeEstimate } from "./TimeEstimateEditor";
import { asAssessment, Assessment } from "../handlers/assessments";
import Iso8601Duration from '../handlers/iso8601duration';
import Variants from '../handlers/variant';

type Props = {
    vulnerabilities: Vulnerability[];
    selectedVulns: string[];
    resetVulns: () => void;
    appendAssessment: (added: Assessment) => void;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
    triggerBanner: (message: string, type: 'error' | 'success', source?: 'nvd' | 'epss' | 'ghsa' | 'euvd', refreshActivity?: boolean) => void;
    hideBanner: () => void;
    variantId?: string;
    /** Origin variant when compare mode is active */
    baseVariantId?: string;
    /** 'difference' or 'intersection' when compare mode is active */
    compareOperation?: string;
};

function MultiEditBar ({vulnerabilities, selectedVulns, resetVulns, appendAssessment, patchVuln, triggerBanner, hideBanner, variantId, baseVariantId, compareOperation} : Readonly<Props>) {

    const [panelOpened, setPanelOpened] = useState<number>(0)
    const [isLoading, setIsLoading] = useState<boolean>(false)
    const [affectedVariantNames, setAffectedVariantNames] = useState<string[]>([])
    const [isAllVariantsMode, setIsAllVariantsMode] = useState<boolean>(false)
    const loadingLabel = selectedVulns.length === 1 ? 'Editing selected CVE...' : 'Editing selected CVEs...'
    const hasSelection = selectedVulns.length >= 1
    const closePanel = () => {
        if (!isLoading) setPanelOpened(0)
    }

    useEffect(() => {
        if (selectedVulns.length === 0) {
            setPanelOpened(0);
            setIsLoading(false);
        }
    }, [selectedVulns.length]);

    useEffect(() => {
        if (panelOpened === 0 || isLoading) return;

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setPanelOpened(0);
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [panelOpened, isLoading]);

    // Recompute affected variants whenever the status panel opens or the selection changes
    useEffect(() => {
        if (panelOpened !== 1 || selectedVulns.length === 0) {
            setAffectedVariantNames([]);
            setIsAllVariantsMode(false);
            return;
        }
        let cancelled = false;
        (async () => {
            if (variantId) {
                // Compare or single-variant context — resolve names
                const allVariants = await Variants.listAll().catch(() => []);
                const compareMatch = allVariants.find(v => v.id === variantId);
                const names: string[] = compareMatch ? [compareMatch.name] : [variantId];
                // Intersection mode: also include the base (origin) variant
                if (compareOperation === 'intersection' && baseVariantId) {
                    const baseMatch = allVariants.find(v => v.id === baseVariantId);
                    const baseName = baseMatch ? baseMatch.name : baseVariantId;
                    if (!names.includes(baseName)) names.push(baseName);
                }
                if (!cancelled) {
                    setIsAllVariantsMode(false);
                    setAffectedVariantNames(names);
                }
            } else {
                // All-variants context — each CVE may have different variants, show generic message
                if (!cancelled) {
                    setIsAllVariantsMode(true);
                    setAffectedVariantNames([]);
                }
            }
        })();
        return () => { cancelled = true; };
    }, [panelOpened, selectedVulns, variantId, baseVariantId, compareOperation]);

    // Get the status only if ALL selected vulnerabilities have the exact same status
    const uniformStatus = useMemo((): string | undefined => {
        if (selectedVulns.length === 0) return undefined;

        const selectedVulnerabilities = vulnerabilities.filter(vuln => selectedVulns.includes(vuln.id));
        if (selectedVulnerabilities.length === 0) return undefined;

        const firstStatus = selectedVulnerabilities[0].assessments[selectedVulnerabilities[0].assessments.length - 1]?.status;
        const allHaveSameStatus = selectedVulnerabilities.every(vuln => vuln.assessments[vuln.assessments.length - 1]?.status === firstStatus);

        // Debug logging

        // Only return the status if ALL vulnerabilities have the same status
        return allHaveSameStatus ? firstStatus : undefined;
    }, [selectedVulns, vulnerabilities]);

    function pkg_for_vulns () {
        const pkg_vulns: {[key: string]: string[]} = {}
        for (const vuln of vulnerabilities) {
            if (selectedVulns.includes(vuln.id)) {
                pkg_vulns[vuln.id] = vuln.packages
            }
        }
        return pkg_vulns
    }

    const addAssessment = async (content: PostAssessment) => {
        const pkg_vulns = pkg_for_vulns();
        setIsLoading(true);

        // Build (vuln_id, variant_id | undefined, packages[]) triples.
        // - variantId set  → use that single variant for every vuln
        // - variantId unset → fetch all variants per vuln and fan out
        type Triple = { vuln_id: string; variant_id?: string; packages: string[] };
        const triples: Triple[] = [];

        if (variantId) {
            // Compare or specific variant — one item per vuln for the compared variant
            for (const vuln_id of selectedVulns) {
                const pkgs = pkg_vulns[vuln_id] ?? [];
                triples.push({ vuln_id, variant_id: variantId, packages: pkgs });
            }
            // Intersection mode: also create triples for the base (origin) variant
            if (compareOperation === 'intersection' && baseVariantId) {
                for (const vuln_id of selectedVulns) {
                    const pkgs = pkg_vulns[vuln_id] ?? [];
                    triples.push({ vuln_id, variant_id: baseVariantId, packages: pkgs });
                }
            }
        } else {
            // All-variants context — one item per (vuln, variant, pkg)
            await Promise.all(selectedVulns.map(async (vuln_id) => {
                const variants = await Variants.listByVuln(vuln_id).catch(() => []);
                const pkgs = pkg_vulns[vuln_id] ?? [];
                if (variants.length === 0) {
                    // No variant data — create without variant_id
                    triples.push({ vuln_id, packages: pkgs });
                } else {
                    for (const v of variants) {
                        triples.push({ vuln_id, variant_id: v.id, packages: pkgs });
                    }
                }
            }));
        }

        // Build batch request payload
        const assessmentRequests = triples.map(({ vuln_id, variant_id, packages }) => ({
            vuln_id,
            packages,
            status: content.status,
            status_notes: content.status_notes,
            justification: content.justification,
            impact_statement: content.impact_statement,
            workaround: content.workaround,
            ...(variant_id ? { variant_id } : {})
        }));

        try {
            const response = await fetch(import.meta.env.VITE_API_URL + '/api/assessments/batch', {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ assessments: assessmentRequests })
            });

            const data = await response.json().catch(() => ({}));

            if (data?.status === 'success' && Array.isArray(data?.assessments)) {
                // Group new assessments by vuln_id so we call patchVuln exactly
                // once per distinct vuln.  Calling it once-per-assessment caused
                // React to batch the setVulns calls and only keep the last one,
                // leaving all other CVEs unchanged.
                const newAssessmentsByVuln = new Map<string, Assessment[]>();
                for (const assessmentData of data.assessments) {
                    const casted = asAssessment(assessmentData);
                    if (!Array.isArray(casted) && typeof casted === "object") {
                        appendAssessment(casted);
                        const list = newAssessmentsByVuln.get(casted.vuln_id) ?? [];
                        list.push(casted);
                        newAssessmentsByVuln.set(casted.vuln_id, list);
                    }
                }
                for (const [vuln_id, newAssessments] of newAssessmentsByVuln.entries()) {
                    const vuln = vulnerabilities.find(v => v.id === vuln_id);
                    if (vuln) {
                        const updatedAssessments = [...vuln.assessments, ...newAssessments];
                        const statusSummary = buildStatusSummary(updatedAssessments, vuln.packages_current);
                        patchVuln(vuln_id, {
                            ...vuln,
                            assessments: updatedAssessments,
                            simplified_status: statusSummary.dominant_status,
                            status_summary: statusSummary,
                        });
                    }
                }

                const vulnCount = data.vuln_count ?? data.count;
                const errorMsg = data.error_count ? ` (${data.error_count} failed)` : '';
                triggerBanner(`Successfully added assessments to ${vulnCount} vulnerabilities${errorMsg}`, 'success');
                resetVulns();
            } else {
                const errorMsg = data?.errors?.length
                    ? `Errors: ${data.errors.map((e: {error?: string}) => e.error).join(', ')}`
                    : `HTTP ${response.status}`;
                triggerBanner(`Failed to add assessments: ${errorMsg}`, 'error');
            }
        } catch (e) {
            triggerBanner(`Failed to add assessments: ${e}`, 'error');
        }

        setIsLoading(false);
        setPanelOpened(0);
    };

    const saveTimeEstimation = async (content: PostTimeEstimate) => {
        setIsLoading(true);

        // Build variant-scoped updates for every selected vulnerability.
        const vulnerabilityUpdates: Array<{
            id: string;
            variant_id: string;
            effort: {
                optimistic: string;
                likely: string;
                pessimistic: string;
            };
        }> = [];

        if (variantId) {
            for (const vuln_id of selectedVulns) {
                vulnerabilityUpdates.push({
                    id: vuln_id,
                    variant_id: variantId,
                    effort: {
                        optimistic: content.optimistic.formatAsIso8601(),
                        likely: content.likely.formatAsIso8601(),
                        pessimistic: content.pessimistic.formatAsIso8601()
                    }
                });
            }
        } else {
            await Promise.all(selectedVulns.map(async (vuln_id) => {
                const variants = await Variants.listByVuln(vuln_id).catch(() => []);
                for (const variant of variants) {
                    vulnerabilityUpdates.push({
                        id: vuln_id,
                        variant_id: variant.id,
                        effort: {
                            optimistic: content.optimistic.formatAsIso8601(),
                            likely: content.likely.formatAsIso8601(),
                            pessimistic: content.pessimistic.formatAsIso8601()
                        }
                    });
                }
            }));
        }

        if (vulnerabilityUpdates.length === 0) {
            triggerBanner('No variants found for selected vulnerabilities.', 'error');
            setIsLoading(false);
            return;
        }

        try {
            const response = await fetch(import.meta.env.VITE_API_URL + '/api/vulnerabilities/batch', {
                method: 'PATCH',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ vulnerabilities: vulnerabilityUpdates })
            });

            const data = await response.json().catch(() => ({}));

            if (data?.status === 'success' && Array.isArray(data?.vulnerabilities)) {
                // Process successful updates
                for (const vulnData of data.vulnerabilities) {
                    const vuln = vulnerabilities.find(v => v.id === vulnData.id);
                    if (vuln) {
                        if (typeof vulnData?.effort?.optimistic === "string")
                            vuln.effort.optimistic = new Iso8601Duration(vulnData.effort.optimistic);
                        if (typeof vulnData?.effort?.likely === "string")
                            vuln.effort.likely = new Iso8601Duration(vulnData.effort.likely);
                        if (typeof vulnData?.effort?.pessimistic === "string")
                            vuln.effort.pessimistic = new Iso8601Duration(vulnData.effort.pessimistic);

                        patchVuln(vuln.id, vuln);
                    }
                }

                const errorMsg = data.error_count ? ` (${data.error_count} failed)` : '';
                triggerBanner(`Successfully updated ${data.count} variant-scoped time estimates${errorMsg}`, 'success');
                resetVulns();
            } else {
                const errorMsg = data?.errors?.length
                    ? `Errors: ${data.errors.map((e: {error?: string}) => e.error).join(', ')}`
                    : `HTTP ${response.status}`;
                triggerBanner(`Failed to save time estimates: ${errorMsg}`, 'error');
            }
        } catch (e) {
            triggerBanner(`Failed to save time estimates: ${e}`, 'error');
        }

        setIsLoading(false);
        setPanelOpened(0);
    }

    return (<>
        {panelOpened > 0 && (
            <div
                data-testid="multi-edit-backdrop"
                className="fixed inset-0 z-30 bg-black/40"
                onMouseDown={closePanel}
            ></div>
        )}

        {isLoading && (
            <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40">
                <div className="flex flex-col items-center gap-3 text-white">
                    <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span className="text-sm font-semibold">{loadingLabel}</span>
                </div>
            </div>
        )}

        <div className="relative mb-4 z-40 w-full">
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-cyan-600/40 bg-gradient-to-r from-cyan-800 via-sky-800 to-sky-900 px-3 py-2 shadow-lg ring-1 ring-black/10">

                {/* Selection summary */}
                <div className="flex items-center gap-2 pr-3 mr-1 border-r border-white/15">
                    <span className={[
                        "inline-flex items-center justify-center min-w-[1.75rem] h-7 px-2 rounded-full text-sm font-bold transition-colors",
                        hasSelection ? "bg-cyan-400 text-cyan-950" : "bg-white/15 text-white/70"
                    ].join(' ')} data-testid="selected-vulns-count">
                        {selectedVulns.length}
                    </span>
                    <span className="text-sm font-medium text-cyan-50 whitespace-nowrap">
                        Selected vulnerabilities
                    </span>
                </div>

                {/* Reset selection */}
                <button
                    className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-white bg-white/10 hover:bg-white/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white/10"
                    disabled={!hasSelection}
                    onClick={() => { hideBanner(); resetVulns(); }}
                >
                    <FontAwesomeIcon icon={faXmark} />
                    Reset selection
                </button>

                <div className="w-px h-6 bg-white/15 mx-1"></div>

                {/* Change status */}
                <button
                    className={[
                        "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-semibold transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed",
                        panelOpened === 1
                            ? "border-cyan-300/80 bg-cyan-300 text-cyan-950 shadow-sm shadow-cyan-950/20 hover:bg-cyan-200"
                            : "border-white/20 text-cyan-50 bg-white/10 hover:bg-white/20 hover:border-white/35 disabled:hover:bg-white/10"
                    ].join(' ')}
                    disabled={!hasSelection}
                    aria-pressed={panelOpened === 1}
                    onClick={() => { hideBanner(); setPanelOpened(panelOpened == 1 ? 0 : 1); }}
                >
                    <FontAwesomeIcon icon={faPenToSquare} />
                    Change status
                </button>

                {/* Change estimated time */}
                <button
                    className={[
                        "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-semibold transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed",
                        panelOpened === 2
                            ? "border-cyan-300/80 bg-cyan-300 text-cyan-950 shadow-sm shadow-cyan-950/20 hover:bg-cyan-200"
                            : "border-white/20 text-cyan-50 bg-white/10 hover:bg-white/20 hover:border-white/35 disabled:hover:bg-white/10"
                    ].join(' ')}
                    disabled={!hasSelection}
                    aria-pressed={panelOpened === 2}
                    onClick={() => { hideBanner(); setPanelOpened(panelOpened == 2 ? 0 : 2); }}
                >
                    <FontAwesomeIcon icon={faClock} />
                    Change time estimate
                </button>
                    </div>
                </div>

            <div className="relative z-50 w-full">
                <div className={[
                    'absolute left-0 top-0 mt-1 z-50 w-full max-w-4xl rounded-lg border border-sky-700/60 bg-neutral-900 shadow-xl p-3',
                    panelOpened == 1 ? 'block' : 'hidden'
                ].join(' ')} data-testid="multi-edit-status-panel">
                    <StatusEditor
                        onAddAssessment={(data) => addAssessment(data)}
                        progressBar={undefined}
                        defaultStatus={uniformStatus}
                    />
                    {(isAllVariantsMode || affectedVariantNames.length > 0) && (
                        <div className="mt-3 pt-3 border-t border-slate-500">
                            {isAllVariantsMode ? (
                                <p className="text-sm font-medium text-gray-300">
                                    Will be applied to all possible variants on each CVE
                                </p>
                            ) : (
                                <>
                                    <p className="text-sm font-medium text-gray-300 mb-1">
                                        Will be applied to variant{affectedVariantNames.length > 1 ? 's' : ''}:
                                    </p>
                                    <div className="flex flex-wrap gap-1">
                                        {affectedVariantNames.map(name => (
                                            <span key={name} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                                {name}
                                            </span>
                                        ))}
                                    </div>
                                </>
                            )}
                        </div>
                    )}
                </div>

                <div className={[
                    'absolute left-0 top-0 mt-1 z-50 w-full max-w-4xl rounded-lg border border-sky-700/60 bg-neutral-900 shadow-xl p-3',
                    panelOpened == 2 ? 'block' : 'hidden'
                ].join(' ')} data-testid="multi-edit-time-panel">
                    <TimeEstimateEditor
                        onSaveTimeEstimation={(data) => saveTimeEstimation(data)}
                        progressBar={undefined}
                        actualEstimate={{optimistic: '', likely: '', pessimistic: ''}}
                    />
                </div>
            </div>
    </>);
}

export default MultiEditBar;
