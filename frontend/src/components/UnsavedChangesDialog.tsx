import { useEffect, useId, useRef } from "react";
import { BUTTON_PRIMARY, BUTTON_SECONDARY } from "./aiContext/styles";

type Props = {
    label: string;
    onSave: () => void;
    onDiscard: () => void;
    onCancel: () => void;
};

/** Save / Discard / Cancel prompt shown before leaving an item with unsaved edits. */
function UnsavedChangesDialog({ label, onSave, onDiscard, onCancel }: Readonly<Props>) {
    const titleId = useId();
    const textId = useId();
    const panelRef = useRef<HTMLDivElement>(null);
    const saveRef = useRef<HTMLButtonElement>(null);
    const onCancelRef = useRef(onCancel);
    onCancelRef.current = onCancel;

    useEffect(() => {
        const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        saveRef.current?.focus();
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === "Escape") {
                event.stopPropagation();
                onCancelRef.current();
                return;
            }
            if (event.key !== "Tab" || !panelRef.current) return;
            const buttons = Array.from(panelRef.current.querySelectorAll<HTMLElement>("button"));
            const first = buttons[0];
            const last = buttons[buttons.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        };
        // Capture phase, so Escape does not also reach popovers listening on document.
        document.addEventListener("keydown", handleKeyDown, true);
        return () => {
            document.removeEventListener("keydown", handleKeyDown, true);
            trigger?.focus();
        };
    }, []);

    return (
        <div className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/70 p-4">
            <div
                ref={panelRef}
                role="alertdialog"
                aria-modal="true"
                aria-labelledby={titleId}
                aria-describedby={textId}
                className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-800 p-5 text-neutral-100 shadow-2xl"
            >
                <h2 id={titleId} className="text-lg font-semibold text-white">Unsaved changes</h2>
                <p id={textId} className="mt-2 text-sm text-zinc-300">You have unsaved changes in {label}.</p>
                <div className="mt-5 flex justify-end gap-3">
                    <button ref={saveRef} type="button" className={BUTTON_PRIMARY} onClick={onSave}>Save</button>
                    <button type="button" className={BUTTON_SECONDARY} onClick={onDiscard}>Discard</button>
                    <button type="button" className={BUTTON_SECONDARY} onClick={onCancel}>Cancel</button>
                </div>
            </div>
        </div>
    );
}

export default UnsavedChangesDialog;
