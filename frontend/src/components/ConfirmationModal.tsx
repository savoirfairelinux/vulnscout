import type { ReactNode } from "react";
import Popup from "./Popup";

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
        <Popup
            isOpen={isOpen}
            title={showTitleIcon ? <><svg className="mr-2 w-5 h-5 text-yellow-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20"><path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM9.5 4a1.5 1.5 0 0 1 3 0v4a1.5 1.5 0 0 1-3 0V4Zm0 8a1.5 1.5 0 0 1 3 0v1a1.5 1.5 0 0 1-3 0v-1Z" /></svg>{title}</> : title}
            onClose={onCancel}
            testId="confirmation-modal-backdrop"
        >
            {children ?? (
                <p className="text-lg font-normal text-gray-500 dark:text-gray-400">{message}</p>
            )}
            <div className="mt-5 flex justify-center gap-4">
                <button
                    onClick={onConfirm}
                    type="button"
                    className="inline-flex items-center rounded-lg bg-red-600 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-red-800 focus:outline-none focus:ring-4 focus:ring-red-300 dark:focus:ring-red-800"
                >
                    {confirmText}
                </button>
                <button
                    onClick={onCancel}
                    type="button"
                    className="rounded-lg border border-gray-200 bg-white px-5 py-2.5 text-sm font-medium text-gray-500 hover:bg-gray-100 hover:text-gray-900 focus:outline-none focus:ring-4 focus:ring-primary-300 dark:border-gray-500 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600 dark:hover:text-white dark:focus:ring-gray-600"
                >
                    {cancelText}
                </button>
            </div>
        </Popup>
    );
}

export default ConfirmationModal;
