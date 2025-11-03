import { useState, useEffect, useCallback } from "react";
import type { Assessment } from "../handlers/assessments";
import MessageBanner from './MessageBanner';

type EditAssessmentData = {
    id: string;
    status: string;
    justification?: string;
    impact_statement?: string;
    status_notes?: string;
    workaround?: string;
}

type Props = {
    assessment: Assessment;
    onSaveAssessment: (data: EditAssessmentData) => void;
    onCancel: () => void;
    clearFields?: boolean;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
}

function EditAssessment({ 
    assessment, 
    onSaveAssessment, 
    onCancel, 
    clearFields: shouldClearFields, 
    onFieldsChange, 
    triggerBanner 
}: Readonly<Props>) {
    const [status, setStatus] = useState(assessment.status || "under_investigation");
    const [justification, setJustification] = useState(assessment.justification || "none");
    const [statusNotes, setStatusNotes] = useState(assessment.status_notes || "");
    const [workaround, setWorkaround] = useState(assessment.workaround || "");
    const [impact, setImpact] = useState(assessment.impact_statement || "");
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
        const hasChanges = (
            status !== assessment.status ||
            justification !== (assessment.justification || "none") ||
            statusNotes !== (assessment.status_notes || "") ||
            workaround !== (assessment.workaround || "") ||
            impact !== (assessment.impact_statement || "")
        );
        onFieldsChange?.(hasChanges);
    }, [status, justification, statusNotes, workaround, impact, onFieldsChange, assessment]);

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
        
        // Determine if we should include justification and impact_statement
        const isRelevantStatus = status == "not_affected" || status == "false_positive";
        
        onSaveAssessment({
            id: assessment.id,
            status,
            justification: isRelevantStatus ? justification : "",
            status_notes: statusNotes,
            workaround,
            impact_statement: isRelevantStatus ? impact : ""
        });
    }

    const resetToOriginal = useCallback(() => {
        setStatus(assessment.status || "under_investigation");
        setJustification(assessment.justification || "none");
        setStatusNotes(assessment.status_notes || "");
        setWorkaround(assessment.workaround || "");
        setImpact(assessment.impact_statement || "");
    }, [assessment]);

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
                    <option value="under_investigation">Community analysis pending</option>
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
            
            {(status == "not_affected" || status == "false_positive") && <>
                <input
                    value={impact}
                    onInput={(event: React.ChangeEvent<HTMLInputElement>) => setImpact(event.target.value)}
                    name="edit_assessment_impact"
                    className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded"
                    type="text"
                    placeholder="why this vulnerability is not exploitable ?"
                /><br/>
            </>}
            
            <input
                value={statusNotes}
                onInput={(event: React.ChangeEvent<HTMLInputElement>) => setStatusNotes(event.target.value)}
                name="edit_assessment_status_notes"
                className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded"
                type="text"
                placeholder="Free text notes about your review, details, actions taken, ..."
            /><br/>
            
            <input
                value={workaround}
                onInput={(event: React.ChangeEvent<HTMLInputElement>) => setWorkaround(event.target.value)}
                name="edit_assessment_workaround"
                className="bg-gray-700 text-white m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 rounded"
                type="text"
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