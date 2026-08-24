import { useCallback, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCircleQuestion } from "@fortawesome/free-solid-svg-icons";
import useDismissablePopover from "../hooks/useDismissablePopover";
import PopoverSurface from "./PopoverSurface";

type Props = {
    ariaLabel: string;
    children: ReactNode;
    heading?: ReactNode;
    title?: string;
    open?: boolean;
    onOpenChange?: (open: boolean) => void;
    className?: string;
    buttonClassName?: string;
    surfaceClassName?: string;
    role?: "dialog" | "tooltip";
};

export default function HelpPopover({
    ariaLabel,
    children,
    heading,
    title,
    open: controlledOpen,
    onOpenChange,
    className = "",
    buttonClassName = "",
    surfaceClassName = "",
    role = "dialog",
}: Readonly<Props>) {
    const [internalOpen, setInternalOpen] = useState(false);
    const rootRef = useRef<HTMLDivElement>(null);
    const panelId = useId();
    const open = controlledOpen ?? internalOpen;
    const setOpen = useCallback((nextOpen: boolean) => {
        if (controlledOpen === undefined) setInternalOpen(nextOpen);
        onOpenChange?.(nextOpen);
    }, [controlledOpen, onOpenChange]);
    const dismiss = useCallback(() => setOpen(false), [setOpen]);

    useDismissablePopover(open, rootRef, dismiss);

    return (
        <div ref={rootRef} className={`relative ${className}`.trim()}>
            <button
                type="button"
                aria-label={ariaLabel}
                aria-expanded={open}
                aria-controls={open ? panelId : undefined}
                title={title ?? ariaLabel}
                className={`text-neutral-300 transition-colors hover:text-white ${buttonClassName}`.trim()}
                onClick={() => setOpen(!open)}
            >
                <FontAwesomeIcon icon={faCircleQuestion} aria-hidden="true" />
            </button>
            {open && (
                <PopoverSurface id={panelId} role={role} className={surfaceClassName}>
                    {heading && <h3 className="mb-3 font-semibold text-white">{heading}</h3>}
                    {children}
                </PopoverSurface>
            )}
        </div>
    );
}