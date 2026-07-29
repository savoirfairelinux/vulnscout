import { useEffect } from "react";
import type { ReactNode } from "react";

type Props = {
    isOpen: boolean;
    title: ReactNode;
    children: ReactNode;
    onClose: () => void;
    testId?: string;
    contentClassName?: string;
};

function Popup({
    isOpen,
    title,
    children,
    onClose,
    testId = "popup-backdrop",
    contentClassName = "",
}: Readonly<Props>) {
    useEffect(() => {
        if (!isOpen) return;

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === "Escape") onClose();
        };

        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    return (
        <div
            data-testid={testId}
            tabIndex={-1}
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) onClose();
            }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50"
        >
            <section role="dialog" aria-modal="true" className="relative mx-4 w-full max-w-md rounded-lg bg-white shadow dark:bg-gray-700">
                <header className="flex items-center justify-between border-b p-4 md:p-5 dark:border-gray-600">
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close modal"
                        className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-sm text-gray-400 hover:bg-gray-200 hover:text-gray-900 dark:hover:bg-gray-600 dark:hover:text-white"
                    >
                        <svg className="h-3 w-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                            <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6" />
                        </svg>
                    </button>
                </header>
                <div className={`p-4 text-left md:p-5 ${contentClassName}`.trim()}>{children}</div>
            </section>
        </div>
    );
}

export default Popup;