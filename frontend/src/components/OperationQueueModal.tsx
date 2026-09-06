/**
 * The operation queue window.
 *
 * Subscribes to the single event stream instead of the six separate stores the
 * polling implementation needed.
 */

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faArrowsRotate, faBug, faCrosshairs, faFileExport, faFileImport,
    faLeaf, faSeedling, faShieldHalved, faXmark,
} from "@fortawesome/free-solid-svg-icons";
import type { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import OperationQueuePanel from "./OperationQueuePanel";
import Operations from "../handlers/operations";
import { getConnectionState, getSnapshot, subscribe } from "../handlers/operationStore";
import type { Operation } from "../types/operation";
import { isActive } from "../types/operation";

type Props = {
    isOpen: boolean;
    onClose: () => void;
};

type Appearance = { icon: IconDefinition; colors: Record<string, string> };

const purple = { border: "border-purple-700/60", headerBg: "bg-purple-900/40", iconText: "text-purple-400", titleText: "text-purple-200", subtitleText: "text-purple-300/80", bar: "bg-purple-500" };
const orange = { border: "border-orange-700/60", headerBg: "bg-orange-900/40", iconText: "text-orange-400", titleText: "text-orange-200", subtitleText: "text-orange-300/80", bar: "bg-orange-500" };
const green = { border: "border-green-700/60", headerBg: "bg-green-900/40", iconText: "text-green-400", titleText: "text-green-200", subtitleText: "text-green-300/80", bar: "bg-green-500" };
const sky = { border: "border-sky-700/60", headerBg: "bg-sky-900/40", iconText: "text-sky-400", titleText: "text-sky-200", subtitleText: "text-sky-300/80", bar: "bg-sky-500" };
const cyan = { border: "border-cyan-700/60", headerBg: "bg-cyan-900/40", iconText: "text-cyan-400", titleText: "text-cyan-200", subtitleText: "text-cyan-300/80", bar: "bg-cyan-500" };
const teal = { border: "border-teal-700/60", headerBg: "bg-teal-900/40", iconText: "text-teal-400", titleText: "text-teal-200", subtitleText: "text-teal-300/80", bar: "bg-teal-500" };
const amber = { border: "border-amber-700/60", headerBg: "bg-amber-900/40", iconText: "text-amber-400", titleText: "text-amber-200", subtitleText: "text-amber-300/80", bar: "bg-amber-500" };

const SCAN_APPEARANCE: Record<string, Appearance> = {
    grype: { icon: faBug, colors: purple },
    nvd: { icon: faShieldHalved, colors: orange },
    osv: { icon: faLeaf, colors: green },
    scc: { icon: faCrosshairs, colors: sky },
};

function appearanceFor(operation: Operation): Appearance {
    if (operation.kind === "scan") {
        return SCAN_APPEARANCE[operation.source] ?? { icon: faCrosshairs, colors: sky };
    }
    if (operation.kind === "refresh") return { icon: faArrowsRotate, colors: cyan };
    if (operation.kind === "export") return { icon: faFileExport, colors: teal };
    if (operation.kind === "upload") return { icon: faFileImport, colors: amber };
    return { icon: faSeedling, colors: green };
}

/**
 * " (variant 2 of 3)" for multi-variant scan batches.
 *
 * The backend numbers positions across the whole batch, so the index is
 * recomputed within each scan source.
 */
function positionLabelFor(operation: Operation, all: readonly Operation[]): string {
    if (operation.kind !== "scan" || operation.queue_id === null) return "";
    const siblings = all.filter(
        candidate => candidate.kind === "scan"
            && candidate.source === operation.source
            && candidate.queue_id === operation.queue_id,
    );
    if (siblings.length < 2) return "";
    const index = siblings.findIndex(candidate => candidate.op_id === operation.op_id);
    return ` (variant ${index + 1} of ${siblings.length})`;
}

function OperationQueueModal({ isOpen, onClose }: Readonly<Props>) {
    const overlayRef = useRef<HTMLDivElement>(null);
    const operations = useSyncExternalStore(subscribe, getSnapshot);
    const connection = useSyncExternalStore(subscribe, getConnectionState);
    // Cancellations awaiting their terminal event, so the button cannot be spammed.
    const [cancelRequested, setCancelRequested] = useState<Set<string>>(new Set());

    useEffect(() => {
        setCancelRequested(previous => {
            const stillActive = [...previous].filter(opId => {
                const operation = operations.find(candidate => candidate.op_id === opId);
                return operation !== undefined && isActive(operation);
            });
            return stillActive.length === previous.size ? previous : new Set(stillActive);
        });
    }, [operations]);

    const requestCancel = (opId: string) => {
        setCancelRequested(previous => new Set(previous).add(opId));
        const restore = () => setCancelRequested(previous => {
            const next = new Set(previous);
            next.delete(opId);
            return next;
        });
        Operations.cancel(opId).then(cancelled => {
            if (!cancelled) restore();
        }).catch(restore);
    };

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
            ref={overlayRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="operation-queue-title"
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4"
            onMouseDown={event => {
                if (event.target === overlayRef.current) onClose();
            }}
        >
            <div className="flex max-h-[min(42rem,calc(100vh-2rem))] w-full max-w-3xl flex-col overflow-hidden rounded-lg bg-neutral-900 shadow-xl">
                <div className="flex items-center justify-between border-b border-neutral-700 px-4 py-3">
                    <div>
                        <h2 id="operation-queue-title" className="text-lg font-semibold text-white">Operation queue</h2>
                        <p className="text-sm text-neutral-400">This window can be safely closed. Track the operation queue in the navigation bar.</p>
                    </div>
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close operation queue"
                        className="inline-flex h-8 w-8 items-center justify-center rounded text-neutral-400 transition-colors hover:bg-neutral-700 hover:text-white"
                    >
                        <FontAwesomeIcon icon={faXmark} />
                    </button>
                </div>
                {connection === "reconnecting" && (
                    <p role="status" className="border-b border-amber-700/60 bg-amber-900/30 px-4 py-2 text-xs text-amber-200">
                        Reconnecting to the operation stream…
                    </p>
                )}
                <div className="overflow-y-auto p-4">
                    {operations.length > 0 ? (
                        <div className="overflow-hidden rounded-lg border border-neutral-700 divide-y divide-neutral-700">
                            {operations.map(operation => {
                                const { icon, colors } = appearanceFor(operation);
                                return (
                                    <OperationQueuePanel
                                        key={operation.op_id}
                                        operation={operation}
                                        icon={icon}
                                        colors={colors as never}
                                        positionLabel={positionLabelFor(operation, operations)}
                                        onDismiss={() => void Operations.dismiss(operation.op_id)}
                                        onCancel={operation.cancellable && isActive(operation) && !cancelRequested.has(operation.op_id)
                                            ? () => requestCancel(operation.op_id)
                                            : undefined}
                                    />
                                );
                            })}
                        </div>
                    ) : (
                        <p className="py-8 text-center text-sm text-neutral-400">No operations to display.</p>
                    )}
                </div>
            </div>
        </div>
    );
}

export default OperationQueueModal;
