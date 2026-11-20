import EditAssessment from "./EditAssessment";
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

function toAiAssessmentEdits(data: EditAssessmentData): AiAssessmentEdits {
    return {
        status: data.status,
        justification: data.justification,
        impact_statement: data.impact_statement,
        status_notes: data.status_notes,
        workaround: data.workaround,
    };
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
            onSaveAssessment={data => onConfirm(toAiAssessmentEdits(data))}
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
