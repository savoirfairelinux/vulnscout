import { useState, useEffect, useCallback } from "react";
import type { Assessment } from "../handlers/assessments";
import type { Variant } from '../handlers/variant';
import MessageBanner from './MessageBanner';

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
    defaultSelectedPackages
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

        const includeJustificationAndImpact = status == "not_affected";

        onSaveAssessment({
            id: assessment.id,
            status,
            justification: includeJustificationAndImpact ? justification : undefined,
            status_notes: statusNotes,
            workaround,
            // For non-impact statuses the value was folded into status_notes; clear impact_statement.
            impact_statement: includeJustificationAndImpact ? impact : "",
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
        setSelectedVariantIds(defaultSelectedVariantIds ?? (availableVariants?.length === 1 ? [availableVariants[0].id] : []));
        setSelectedPackages(defaultSelectedPackages ?? (availablePackages?.length === 1 ? [availablePackages[0]] : []));
    }, [assessment, isImpactStatus, defaultSelectedVariantIds, defaultSelectedPackages]);

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
                <div className="mt-2 mb-2 ml-1">
                    <p className="text-sm font-medium text-gray-300 mb-1">Apply to variants:</p>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                        {availableVariants.map(v => (
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
                        {availablePackages.map(pkg => (
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
                                <span className="font-mono text-gray-200">{pkg}</span>
                            </label>
                        ))}
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
