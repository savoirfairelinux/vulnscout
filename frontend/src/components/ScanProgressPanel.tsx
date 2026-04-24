/**
 * ScanProgressPanel — reusable per-variant scan progress / log panel.
 *
 * Renders a collapsible card with:
 *  - coloured header showing scan type + variant name
 *  - progress bar
 *  - scrollable log box
 *  - dismiss button (when not running)
 */

import { useEffect, useRef } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark } from "@fortawesome/free-solid-svg-icons";
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
    const { status, variantName, progress, logs, total, doneCount } = entry;
    const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0;

    const logBoxRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const el = logBoxRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [logs.length]);

    const statusText =
        status === "running" ? "in progress"
            : status === "error" ? "failed"
                : "complete";

    return (
        <div className={`mb-4 rounded-lg border ${colors.border} bg-neutral-900 overflow-hidden`}>
            {/* Header */}
            <div className={`px-4 py-2 flex items-center gap-3 ${colors.headerBg}`}>
                <FontAwesomeIcon icon={icon} className={colors.iconText} />
                <span className={`text-sm font-semibold ${colors.titleText}`}>
                    {label} – {variantName} {statusText}
                </span>
                <span className={`text-xs ${colors.subtitleText} ml-auto`}>
                    {progress ?? ""}
                    {total > 0 && ` (${pct}%)`}
                </span>
                {status !== "running" && (
                    <button
                        onClick={onDismiss}
                        title="Close"
                        className="text-neutral-400 hover:text-white transition-colors ml-1"
                    >
                        <FontAwesomeIcon icon={faXmark} className="text-sm" />
                    </button>
                )}
            </div>

            {/* Progress bar */}
            <div className="w-full h-2 bg-neutral-800">
                <div
                    className={[
                        "h-full transition-all duration-500 ease-out",
                        status === "done" ? "bg-green-500" : colors.bar,
                    ].join(" ")}
                    style={{ width: `${pct}%` }}
                />
            </div>

            {/* Log box */}
            <div
                ref={logBoxRef}
                className="max-h-52 overflow-y-auto px-4 py-2 font-mono text-xs text-neutral-300 space-y-0.5 scrollbar-thin scrollbar-thumb-neutral-700"
            >
                {logs.length === 0 && status === "running" && (
                    <div className="text-neutral-500 italic">Waiting for first results…</div>
                )}
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
    );
}
