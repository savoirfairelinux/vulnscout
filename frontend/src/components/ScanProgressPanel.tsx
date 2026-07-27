/**
 * ScanProgressPanel — reusable per-variant scan progress / log panel.
 *
 * Renders a collapsible card with:
 *  - coloured header showing scan type + variant name
 *  - progress bar
 *  - scrollable log box
 *  - dismiss button (when not running)
 */

import { useEffect, useId, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCheck, faChevronRight, faXmark } from "@fortawesome/free-solid-svg-icons";
import type { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import type { ScanEntryState } from "../handlers/scanStateManager";

type ColorScheme = {
    border: string;   // e.g. "border-purple-700/60"
    headerBg: string; // e.g. "bg-purple-900/40"
    iconText: string; // e.g. "text-purple-400"
    titleText: string; // e.g. "text-purple-200"
    subtitleText: string; // e.g. "text-purple-300/80"
    bar: string;      // e.g. "bg-purple-500"
};

type Props = {
    entry: ScanEntryState;
    label: string;        // e.g. "Grype Scan"
    icon: IconDefinition;
    colors: ColorScheme;
    onDismiss: () => void;
};

export default function ScanProgressPanel({ entry, label, icon, colors, onDismiss }: Props) {
    const { status, variantName, variantPosition, variantCount, progress, logs, total, doneCount } = entry;
    const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
    const hasProgressContent = logs.length > 0 || total > 0 || doneCount > 0;
    const isActivelyScanning = status === "running" && hasProgressContent;
    const expandsForStatus = isActivelyScanning || status === "error";
    const [isOpen, setIsOpen] = useState(expandsForStatus);
    const contentId = useId();
    const variantProgress = variantPosition && variantCount && variantCount > 1
        ? ` (variant ${variantPosition} of ${variantCount})`
        : "";

    const logBoxRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        setIsOpen(expandsForStatus);
    }, [expandsForStatus]);

    useEffect(() => {
        const el = logBoxRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [logs.length]);

    const statusText =
        status === "queued" || (status === "running" && !isActivelyScanning) ? "queued"
            : isActivelyScanning ? "in progress"
                : status === "error" ? "failed"
                    : "complete";

    return (
        <section className="bg-neutral-900">
            {/* Header */}
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
                        {label} – {variantName} {statusText}{variantProgress}
                    </span>
                    {status === "done" && (
                        <FontAwesomeIcon icon={faCheck} className="text-green-400" aria-label="Complete" />
                    )}
                    <span className={`text-xs ${colors.subtitleText} ml-auto`}>
                        {progress ?? ""}
                        {total > 0 && ` (${pct}%)`}
                    </span>
                </button>
                {status !== "running" && status !== "queued" && (
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
                    {/* Progress bar */}
                    <div className="w-full h-2 bg-neutral-800">
                        {!isActivelyScanning && status !== "done" && status !== "error" ? (
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

                    {/* Log box */}
                    <div
                        ref={logBoxRef}
                        className="max-h-52 overflow-y-auto px-4 py-2 font-mono text-xs text-neutral-300 space-y-0.5 scrollbar-thin scrollbar-thumb-neutral-700"
                    >
                        {logs.map((line, i) => (
                            <div
                                key={i}
                                className={
                                    line.startsWith("[") && line.includes("ERROR")
                                        ? "text-red-400"
                                        : line.startsWith("✓")
                                            ? "text-green-400 font-semibold"
                                            : ""
                                }
                            >
                                {line}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </section>
    );
}
