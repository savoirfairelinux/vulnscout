import { useEffect, useRef } from "react";
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
    const refsRef = useRef(refs);
    const onDismissRef = useRef(onDismiss);
    refsRef.current = refs;
    onDismissRef.current = onDismiss;

    useEffect(() => {
        if (!open) return;

        const handlePointerDown = (event: MouseEvent) => {
            const insideRefs = Array.isArray(refsRef.current) ? refsRef.current : [refsRef.current];
            if (insideRefs.some(ref => ref.current?.contains(event.target as Node))) return;
            onDismissRef.current();
        };
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key !== "Escape") return;
            event.preventDefault();
            event.stopPropagation();
            onDismissRef.current();
        };

        if (closeOnOutsidePointer) document.addEventListener("mousedown", handlePointerDown);
        if (closeOnEscape) document.addEventListener("keydown", handleKeyDown, true);

        return () => {
            if (closeOnOutsidePointer) document.removeEventListener("mousedown", handlePointerDown);
            if (closeOnEscape) document.removeEventListener("keydown", handleKeyDown, true);
        };
    }, [closeOnEscape, closeOnOutsidePointer, open]);
}
