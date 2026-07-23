import { RefObject, useEffect, useRef } from "react";

const focusableSelector = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(', ');

function getFocusableElements(container: HTMLElement): HTMLElement[] {
    return Array.from(container.querySelectorAll<HTMLElement>(focusableSelector))
        .filter(element => !element.hasAttribute('disabled') && element.getClientRects().length > 0);
}

export function useDialogFocus(
    isOpen: boolean,
    dialogRef: RefObject<HTMLElement>,
    initialFocusRef?: RefObject<HTMLElement>,
) {
    const previousFocusRef = useRef<HTMLElement | null>(null);

    useEffect(() => {
        if (!isOpen) return;

        previousFocusRef.current = document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null;

        const dialog = dialogRef.current;
        if (!dialog) return;
        const initialFocus = initialFocusRef?.current ?? getFocusableElements(dialog).at(0) ?? dialog;
        initialFocus?.focus();

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key !== 'Tab') return;

            const focusableElements = getFocusableElements(dialog);
            if (focusableElements.length === 0) {
                event.preventDefault();
                dialog.focus();
                return;
            }

            const first = focusableElements[0];
            const last = focusableElements[focusableElements.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
            if (previousFocusRef.current?.isConnected) previousFocusRef.current.focus();
        };
    }, [isOpen, dialogRef, initialFocusRef]);
}