/**
 * Every operation of one enqueued batch, collapsed into a single queue entry.
 *
 * A scan launched on several scanners and variants creates one operation per
 * step; this panel shows the batch's overall progress and expands to the
 * individual steps.
 */

import { useId, useState } from "react";
import type { ReactNode } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBan, faCheck, faChevronRight, faLayerGroup, faXmark } from "@fortawesome/free-solid-svg-icons";
import type { Operation } from "../types/operation";
import { isActive, percentOf } from "../types/operation";
import { runStatus } from "../helpers/operationRuns";

type Props = {
    steps: readonly Operation[];
    renderStep: (step: Operation) => ReactNode;
    onDismiss: () => void;
    onCancel?: () => void;
};

const STATUS_TEXT: Record<string, string> = {
    queued: "queued",
    running: "in progress",
    error: "failed",
    cancelled: "cancelled",
    done: "complete",
};

const BAR_CLASS: Record<string, string> = {
    done: "bg-green-500",
    error: "bg-red-500",
};

function runTitle(steps: readonly Operation[]): string {
    const label = steps.some(step => step.kind === "scan") ? "Scan run" : "Vulnerability data refresh";
    const variants = [...new Set(steps.flatMap(step => step.scope ? [step.scope.variant_name] : []))];
    if (variants.length === 0) return label;
    return `${label} – ${variants.length === 1 ? variants[0] : `${variants.length} variants`}`;
}

export default function OperationRunPanel({ steps, renderStep, onDismiss, onCancel }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const contentId = useId();
    const status = runStatus(steps);
    const active = steps.some(isActive);
    const finished = steps.filter(step => !isActive(step)).length;
    const current = steps.find(step => step.status === "running");
    const pct = status === "done"
        ? 100
        : Math.round(((finished + (current ? percentOf(current) / 100 : 0)) / steps.length) * 100);
    const title = runTitle(steps);
    const currentLabel = current
        ? `${current.label}${current.scope ? ` – ${current.scope.variant_name}` : ""}: ${current.progress.message}`
        : "";

    return (
        <section className="bg-neutral-900">
            <div className="px-4 py-2 flex items-center gap-3 bg-cyan-900/40">
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
                    <FontAwesomeIcon icon={faLayerGroup} className="text-cyan-400" />
                    <span className="text-sm font-semibold text-cyan-200">
                        {title} {STATUS_TEXT[status]} ({finished} of {steps.length} steps)
                    </span>
                    {status === "done" && (
                        <FontAwesomeIcon icon={faCheck} className="text-green-400" aria-label="Complete" />
                    )}
                    <span className="ml-auto truncate text-xs text-cyan-300/80">
                        {currentLabel}{active && ` (${pct}%)`}
                    </span>
                </button>
                {active && onCancel && (
                    <button
                        type="button"
                        onClick={onCancel}
                        title="Cancel"
                        aria-label={`Cancel ${title}`}
                        className="text-neutral-400 hover:text-red-400 transition-colors ml-1"
                    >
                        <FontAwesomeIcon icon={faBan} className="text-sm" />
                    </button>
                )}
                {!active && (
                    <button
                        type="button"
                        onClick={onDismiss}
                        title="Close"
                        aria-label={`Close ${title}`}
                        className="text-neutral-400 hover:text-white transition-colors ml-1"
                    >
                        <FontAwesomeIcon icon={faXmark} className="text-sm" />
                    </button>
                )}
            </div>
            <div className="w-full h-1 bg-neutral-800">
                <div
                    className={`h-full transition-all duration-500 ease-out ${BAR_CLASS[status] ?? "bg-cyan-500"}`}
                    style={{ width: `${pct}%` }}
                />
            </div>
            {isOpen && (
                <div id={contentId} className="pl-6 divide-y divide-neutral-800">
                    {steps.map(step => <div key={step.op_id}>{renderStep(step)}</div>)}
                </div>
            )}
        </section>
    );
}
