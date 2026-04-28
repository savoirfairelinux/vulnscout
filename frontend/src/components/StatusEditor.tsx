import { useState, useEffect, useCallback } from "react";
import MessageBanner from './MessageBanner';
import type { Variant } from '../handlers/variant';

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
}

function StatusEditor ({onAddAssessment, progressBar, clearFields: shouldClearFields, onFieldsChange, triggerBanner, defaultStatus = "under_investigation", variants, availablePackages, defaultSelectedPackages}: Readonly<Props>) {
    const [status, setStatus] = useState(defaultStatus);
    const [justification, setJustification] = useState("none");
    const [statusNotes, setStatusNotes] = useState("");
    const [workaround, setWorkaround] = useState("");
    const [impact, setImpact] = useState("");
    const [selectedVariantIds, setSelectedVariantIds] = useState<string[]>(
        variants?.length === 1 ? [variants[0].id] : []
    );
    const [selectedPackages, setSelectedPackages] = useState<string[]>(defaultSelectedPackages ?? availablePackages ?? []);
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
        setSelectedPackages(defaultSelectedPackages ?? availablePackages ?? []);
    }, [availablePackages, defaultSelectedPackages]);

    // Auto-select single variant when variants load asynchronously (e.g. Edit from Actions column)
    useEffect(() => {
        setSelectedVariantIds(variants?.length === 1 ? [variants[0].id] : []);
    }, [variants]);

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
        setSelectedVariantIds(variants?.length === 1 ? [variants[0].id] : []);
        setSelectedPackages(defaultSelectedPackages ?? availablePackages ?? []);
    }, [defaultStatus, availablePackages, defaultSelectedPackages, variants]);

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
            <div className="mt-2 mb-2 ml-1">
                <p className="text-sm font-medium text-gray-300 mb-1">Apply to variants:</p>
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                    {variants.map(v => (
                        <label key={v.id} className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
                            <input
                                type="checkbox"
                                checked={selectedVariantIds.includes(v.id)}
                                onChange={(e) => {
                                    if (e.target.checked) {
                                        setSelectedVariantIds(prev => [...prev, v.id]);
                                    } else {
                                        setSelectedVariantIds(prev => prev.filter(id => id !== v.id));
                                    }
                                }}
                                className="accent-blue-500"
                            />
                            <span className="text-gray-200">{v.name}</span>
                        </label>
                    ))}
                </div>
            </div>
        )}
        {availablePackages && availablePackages.length > 1 && (
            <div className="mt-2 mb-2 ml-1">
                <p className="text-sm font-medium text-gray-300 mb-1">Apply to packages:</p>
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                    {availablePackages.map(pkg => {
                        const isActive = !defaultSelectedPackages || defaultSelectedPackages.includes(pkg);
                        return (
                        <label key={pkg} className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
                            <input
                                type="checkbox"
                                checked={selectedPackages.includes(pkg)}
                                onChange={(e) => {
                                    if (e.target.checked) {
                                        setSelectedPackages(prev => [...prev, pkg]);
                                    } else {
                                        setSelectedPackages(prev => prev.filter(p => p !== pkg));
                                    }
                                }}
                                className="accent-blue-400"
                            />
                            <span className={`font-mono ${isActive ? 'text-gray-200' : 'text-gray-500 italic'}`}
                                  title={isActive ? undefined : 'Not in active SBOM'}>{pkg}</span>
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
