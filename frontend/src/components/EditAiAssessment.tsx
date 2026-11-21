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
    replaced?: boolean;
    errorMessage?: string | null;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
}

function toAiAssessmentEdits(data: EditAssessmentData, original: Assessment): AiAssessmentEdits {
    // Never silently downgrade an editor confirmation to an unconditional approval.
    const edits: AiAssessmentEdits = { expected_fingerprint: original.approval_fingerprint ?? "" };
    if (data.justification !== undefined && data.justification !== (original.justification || ""))
        edits.justification = data.justification;
    const hasImpactField = ['not_affected', 'false_positive'].includes(original.status);
    if (hasImpactField &&
        data.impact_statement !== (original.impact_statement || "")) edits.impact_statement = data.impact_statement;
    if (data.status_notes !== initialStatusNotes(original)) {
        if (!hasImpactField && !original.status_notes && original.impact_statement)
            edits.impact_statement = data.status_notes;
        else
            edits.status_notes = data.status_notes;
    }
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
    replaced = false,
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
            allowImpactInsteadOfJustification
            title="Edit AI assessment"
            saveLabel={saving ? "Approving…" : "Confirm and approve"}
            cancelLabel="Cancel changes"
            saving={saving}
            saveDisabled={replaced}
            errorMessage={replaced ? "This suggestion is no longer pending here. Copy your draft or cancel changes." : errorMessage}
        />
    );
}

export default EditAiAssessment;
