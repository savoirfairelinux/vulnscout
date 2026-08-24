import { useEffect } from "react";
import type { RefObject } from "react";

type DismissableRef = RefObject<HTMLElement | null>;

type Options = {
    closeOnEscape?: boolean;
    closeOnOutsidePointer?: boolean;
};

export default function useDismissablePopover(
    open: boolean,
    refs: DismissableRef | readonly DismissableRef[],
    onDismiss: () => void,
    { closeOnEscape = true, closeOnOutsidePointer = true }: Options = {},
): void {
    useEffect(() => {
        if (!open) return;

        const insideRefs = Array.isArray(refs) ? refs : [refs];
        const handlePointerDown = (event: MouseEvent) => {
            if (insideRefs.some(ref => ref.current?.contains(event.target as Node))) return;
            onDismiss();
        };
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === "Escape") onDismiss();
        };

        if (closeOnOutsidePointer) document.addEventListener("mousedown", handlePointerDown);
        if (closeOnEscape) document.addEventListener("keydown", handleKeyDown);

        return () => {
            if (closeOnOutsidePointer) document.removeEventListener("mousedown", handlePointerDown);
            if (closeOnEscape) document.removeEventListener("keydown", handleKeyDown);
        };
    }, [closeOnEscape, closeOnOutsidePointer, onDismiss, open, refs]);
}