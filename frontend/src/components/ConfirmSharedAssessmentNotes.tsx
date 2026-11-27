import ConfirmationModal from "./ConfirmationModal";

type Props = {
    isOpen: boolean;
    onConfirm: () => void;
    onCancel: () => void;
};

export default function ConfirmSharedAssessmentNotes({ isOpen, onConfirm, onCancel }: Readonly<Props>) {
    return (
        <ConfirmationModal
            isOpen={isOpen}
            title="Do these Notes apply to the new targets?"
            message="Confirm that the shared Notes, including any citations and supporting evidence, apply to every newly added package and variant pair. Go back to revise the Notes if needed."
            confirmText="Confirm and save"
            cancelText="Back to edit"
            suspendUnderlyingDialogs
            onConfirm={onConfirm}
            onCancel={onCancel}
        />
    );
}
