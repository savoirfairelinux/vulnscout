import type { ReactNode } from "react";
import ModalShell, { ModalActions, ModalButton } from "./ModalShell";

type Props = {
    isOpen: boolean;
    title?: string;
    message: string;
    confirmText?: string;
    cancelText?: string;
    showTitleIcon?: boolean;
    children?: ReactNode;
    onConfirm: () => void;
    onCancel: () => void;
};

function ConfirmationModal({
    isOpen,
    title = "Confirm Action",
    message,
    confirmText = "Yes",
    cancelText = "No",
    showTitleIcon = false,
    children,
    onConfirm,
    onCancel
}: Readonly<Props>) {
    return (
        <ModalShell
            isOpen={isOpen}
            title={showTitleIcon ? <><svg className="mr-2 w-5 h-5 text-yellow-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20"><path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM9.5 4a1.5 1.5 0 0 1 3 0v4a1.5 1.5 0 0 1-3 0V4Zm0 8a1.5 1.5 0 0 1 3 0v1a1.5 1.5 0 0 1-3 0v-1Z" /></svg>{title}</> : title}
            onClose={onCancel}
            testId="confirmation-modal-backdrop"
            size="compact"
        >
            {children ?? (
                <p className="text-lg font-normal text-gray-500 dark:text-gray-400">{message}</p>
            )}
            <div className="mt-5">
                <ModalActions>
                <ModalButton
                    onClick={onConfirm}
                    variant="danger"
                >
                    {confirmText}
                </ModalButton>
                <ModalButton
                    onClick={onCancel}
                >
                    {cancelText}
                </ModalButton>
                </ModalActions>
            </div>
        </ModalShell>
    );
}

export default ConfirmationModal;
