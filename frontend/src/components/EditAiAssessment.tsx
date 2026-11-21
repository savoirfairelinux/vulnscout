import EditAssessment from "./EditAssessment";
import { initialStatusNotes } from "../handlers/assessments";
import type { EditAssessmentData } from "./EditAssessment";
import type { AiAssessmentEdits, Assessment } from "../handlers/assessments";

type Props = {
    assessment: Assessment;
    /** Persist the edited content and approve the suggestion. */
    onConfirm: (edits: AiAssessmentEdits) => void;
    /** Discard the edits and leave edit mode. */
    onCancel: () => void;
    saving?: boolean;
    errorMessage?: string | null;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
}

function toAiAssessmentEdits(data: EditAssessmentData, original: Assessment): AiAssessmentEdits {
    const edits: AiAssessmentEdits = {};
    if (data.status !== original.status) edits.status = data.status;
    if (data.justification !== undefined && data.justification !== original.justification)
        edits.justification = data.justification;
    if (['not_affected', 'false_positive'].includes(data.status) && data.impact_statement !== (original.impact_statement || ""))
        edits.impact_statement = data.impact_statement;
    // Compare against what the edited row would display without a notes override.
    // A status or impact edit can remove the fallback that prefilled the form.
    if (data.status_notes !== initialStatusNotes({ ...original, ...edits })) edits.status_notes = data.status_notes;
    if (data.workaround !== (original.workaround || "")) edits.workaround = data.workaround;
    return edits;
}

/** Edit the content of a pending AI assessment before approving it.
 *  Targets are not editable here: the suggestion keeps its packages/variants. */
function EditAiAssessment({
    assessment,
    onConfirm,
    onCancel,
    saving = false,
    errorMessage,
    onFieldsChange,
    triggerBanner,
}: Readonly<Props>) {
    return (
        <EditAssessment
            assessment={assessment}
            onSaveAssessment={data => onConfirm(toAiAssessmentEdits(data, assessment))}
            onCancel={onCancel}
            onFieldsChange={onFieldsChange}
            triggerBanner={triggerBanner}
            contentOnly={true}
            requireMessage={true}
            title="Edit AI assessment"
            saveLabel={saving ? "Approving…" : "Confirm and approve"}
            cancelLabel="Cancel changes"
            saving={saving}
            errorMessage={errorMessage}
        />
    );
}

export default EditAiAssessment;
