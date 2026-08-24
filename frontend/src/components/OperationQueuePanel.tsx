/**
 * One operation in the queue: collapsible card with progress bar and logs.
 *
 * Consumes the shared `Operation` shape, so scans, refreshes, uploads and
 * exports all render through this single component.
 */

import { useEffect, useId, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBan, faCheck, faChevronRight, faXmark } from "@fortawesome/free-solid-svg-icons";
import type { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import type { Operation } from "../types/operation";
import { isActive, percentOf } from "../types/operation";

type ColorScheme = {
    border: string;
    headerBg: string;
    iconText: string;
    titleText: string;
    subtitleText: string;
    bar: string;
};

type Props = {
    operation: Operation;
    icon: IconDefinition;
    colors: ColorScheme;
    /** e.g. " (variant 2 of 3)" — the caller knows the batch grouping. */
    positionLabel?: string;
    onDismiss: () => void;
    onCancel?: () => void;
};

export default function OperationQueuePanel({
    operation, icon, colors, positionLabel = "", onDismiss, onCancel,
}: Readonly<Props>) {
    const { status, label, scope, progress, logs } = operation;
    const pct = percentOf(operation);
    const hasProgressContent = logs.length > 0 || progress.total > 0 || progress.current > 0;
    const isActivelyRunning = status === "running" && hasProgressContent;
    const expandsForStatus = isActivelyRunning || status === "error";
    const [isOpen, setIsOpen] = useState(expandsForStatus);
    const contentId = useId();
    const title = scope?.variant_name ?? label;

    const logBoxRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        setIsOpen(expandsForStatus);
    }, [expandsForStatus]);

    useEffect(() => {
        const el = logBoxRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [logs.length]);

    let statusText: string;
    if (status === "queued" || (status === "running" && !isActivelyRunning)) statusText = "queued";
    else if (isActivelyRunning) statusText = "in progress";
    else if (status === "error") statusText = "failed";
    else if (status === "cancelled") statusText = "cancelled";
    else statusText = "complete";

    return (
        <section className="bg-neutral-900">
            <div className={`px-4 py-2 flex items-center gap-3 ${colors.headerBg}`}>
                <button
                    type="button"
                    onClick={() => setIsOpen(open => !open)}
                    aria-expanded={isOpen}
                    aria-controls={contentId}
                    className="flex min-w-0 flex-1 items-center gap-3 text-left"
                >
                    <FontAwesomeIcon
                        icon={faChevronRight}
                        className={`w-3 text-neutral-400 transition-transform ${isOpen ? "rotate-90" : ""}`}
                    />
                    <FontAwesomeIcon icon={icon} className={colors.iconText} />
                    <span className={`text-sm font-semibold ${colors.titleText}`}>
                        {label} – {title} {statusText}{positionLabel}
                    </span>
                    {status === "done" && (
                        <FontAwesomeIcon icon={faCheck} className="text-green-400" aria-label="Complete" />
                    )}
                    <span className={`text-xs ${colors.subtitleText} ml-auto`}>
                        {progress.message ?? ""}
                        {progress.total > 0 && ` (${pct}%)`}
                    </span>
                </button>
                {isActive(operation) && onCancel && (
                    <button
                        type="button"
                        onClick={onCancel}
                        title="Cancel"
                        aria-label={`Cancel ${label} – ${title}`}
                        className="text-neutral-400 hover:text-red-400 transition-colors ml-1"
                    >
                        <FontAwesomeIcon icon={faBan} className="text-sm" />
                    </button>
                )}
                {!isActive(operation) && (
                    <button
                        type="button"
                        onClick={onDismiss}
                        title="Close"
                        className="text-neutral-400 hover:text-white transition-colors ml-1"
                    >
                        <FontAwesomeIcon icon={faXmark} className="text-sm" />
                    </button>
                )}
            </div>

            {isOpen && (
                <div id={contentId}>
                    <div className="w-full h-2 bg-neutral-800">
                        {!isActivelyRunning && status !== "done" && status !== "error" && status !== "cancelled" ? (
                            <div className="h-full w-full bg-neutral-600 animate-pulse" />
                        ) : (
                            <div
                                className={[
                                    "h-full transition-all duration-500 ease-out",
                                    status === "done" ? "bg-green-500" : colors.bar,
                                ].join(" ")}
                                style={{ width: `${pct}%` }}
                            />
                        )}
                    </div>

                    <div
                        ref={logBoxRef}
                        className="max-h-52 overflow-y-auto px-4 py-2 font-mono text-xs text-neutral-300 space-y-0.5 scrollbar-thin scrollbar-thumb-neutral-700"
                    >
                        {logs.map((line, i) => {
                            let tone = "";
                            if (line.includes("ERROR")) tone = "text-red-400";
                            else if (line.startsWith("✓")) tone = "text-green-400 font-semibold";
                            return <div key={i} className={tone}>{line}</div>;
                        })}
                    </div>
                </div>
            )}
        </section>
    );
}
