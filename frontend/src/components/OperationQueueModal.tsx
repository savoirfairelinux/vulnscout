/**
 * The operation queue window.
 *
 * Subscribes to the single event stream instead of the six separate stores the
 * polling implementation needed.
 */

import { useEffect, useState, useSyncExternalStore } from "react";
import {
    faArrowsRotate, faBug, faCrosshairs, faFileExport, faFileImport,
    faLeaf, faSeedling, faShieldHalved,
} from "@fortawesome/free-solid-svg-icons";
import type { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import OperationQueuePanel from "./OperationQueuePanel";
import OperationRunPanel from "./OperationRunPanel";
import ModalShell from "./ModalShell";
import Operations from "../handlers/operations";
import { downloadExport } from "../handlers/exportQueue";
import { getConnectionState, getSnapshot, subscribe } from "../handlers/operationStore";
import { groupQueueItems } from "../helpers/operationRuns";
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

// Keys of cancelled runs in the pending-cancellation set, next to plain op ids.
const RUN_KEY = "run:";

function OperationQueueModal({ isOpen, onClose }: Readonly<Props>) {
    const operations = useSyncExternalStore(subscribe, getSnapshot);
    const connection = useSyncExternalStore(subscribe, getConnectionState);
    // Cancellations awaiting their terminal event, so the button cannot be spammed.
    const [cancelRequested, setCancelRequested] = useState<Set<string>>(new Set());
    const [downloadError, setDownloadError] = useState<string | null>(null);

    useEffect(() => {
        setCancelRequested(previous => {
            const stillActive = [...previous].filter(key => operations.some(operation => isActive(operation)
                && (key.startsWith(RUN_KEY)
                    ? operation.queue_id === key.slice(RUN_KEY.length)
                    : operation.op_id === key)));
            return stillActive.length === previous.size ? previous : new Set(stillActive);
        });
    }, [operations]);

    const requestCancel = (key: string, send: () => Promise<boolean>) => {
        setCancelRequested(previous => new Set(previous).add(key));
        const restore = () => setCancelRequested(previous => {
            const next = new Set(previous);
            next.delete(key);
            return next;
        });
        send().then(cancelled => {
            if (!cancelled) restore();
        }).catch(restore);
    };

    const renderOperation = (operation: Operation, inRun: boolean) => {
        const { icon, colors } = appearanceFor(operation);
        const cancelBlocked = cancelRequested.has(operation.op_id)
            || (inRun && cancelRequested.has(RUN_KEY + operation.queue_id));
        return (
            <OperationQueuePanel
                key={operation.op_id}
                operation={operation}
                icon={icon}
                colors={colors as never}
                onDismiss={inRun ? undefined : () => void Operations.dismiss(operation.op_id)}
                onDownload={operation.kind === "export" && operation.status === "done" && operation.result?.download_ready
                    ? () => void downloadExport(operation.op_id).catch(error =>
                        setDownloadError(error instanceof Error ? error.message : "Failed to download export"))
                    : undefined}
                onCancel={operation.cancellable && isActive(operation) && !cancelBlocked
                    ? () => requestCancel(operation.op_id, () => Operations.cancel(operation.op_id))
                    : undefined}
            />
        );
    };

    if (!isOpen) return null;

    return (
        <ModalShell
            isOpen={isOpen}
            title="Operation queue"
            subtitle="This window can be safely closed. Track the operation queue in the navigation bar."
            titleId="operation-queue-title"
            onClose={onClose}
            closeLabel="Close operation queue"
            size="large"
            contentClassName="overflow-y-auto"
        >
            {connection === "reconnecting" && (
                <p role="status" className="border-b border-amber-700/60 bg-amber-900/30 px-4 py-2 text-xs text-amber-200">
                    Reconnecting to the operation stream…
                </p>
            )}
            {downloadError && <p role="alert" className="px-4 py-2 text-sm text-red-300">{downloadError}</p>}
            {operations.length > 0 ? (
                <div className="overflow-hidden rounded-lg border border-neutral-700 divide-y divide-neutral-700">
                    {groupQueueItems(operations).map(item => item.type === "operation"
                        ? renderOperation(item.operation, false)
                        : (
                            <OperationRunPanel
                                key={item.queueId}
                                steps={item.steps}
                                renderStep={step => renderOperation(step, true)}
                                onDismiss={() => item.steps.forEach(step => void Operations.dismiss(step.op_id))}
                                onCancel={item.steps.some(step => step.cancellable && isActive(step))
                                    && !cancelRequested.has(RUN_KEY + item.queueId)
                                    ? () => requestCancel(RUN_KEY + item.queueId, () => Operations.cancelQueue(item.queueId))
                                    : undefined}
                            />
                        ))}
                </div>
            ) : (
                <p className="py-8 text-center text-sm text-neutral-400">No operations to display.</p>
            )}
        </ModalShell>
    );
}

export default OperationQueueModal;
