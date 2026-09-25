/**
 * Groups the operation snapshot into queue entries.
 *
 * Every operation enqueued in the same request shares a `queue_id`; a batch of
 * two or more is shown as one run so a multi-scanner, multi-variant launch
 * does not flood the queue.
 */

import type { Operation, OperationStatus } from "../types/operation";
import { isActive } from "../types/operation";

export type QueueItem =
    | { type: "operation"; operation: Operation }
    | { type: "run"; queueId: string; steps: Operation[] };

/** Keeps the snapshot order, placing each run where its first step appears. */
export function groupQueueItems(operations: readonly Operation[]): QueueItem[] {
    const batchSizes = new Map<string, number>();
    operations.forEach(operation => {
        if (operation.queue_id) {
            batchSizes.set(operation.queue_id, (batchSizes.get(operation.queue_id) ?? 0) + 1);
        }
    });

    const runs = new Map<string, Operation[]>();
    const items: QueueItem[] = [];
    operations.forEach(operation => {
        const queueId = operation.queue_id;
        if (!queueId || (batchSizes.get(queueId) ?? 0) < 2) {
            items.push({ type: "operation", operation });
            return;
        }
        let steps = runs.get(queueId);
        if (steps === undefined) {
            steps = [];
            runs.set(queueId, steps);
            items.push({ type: "run", queueId, steps });
        }
        steps.push(operation);
    });
    runs.forEach(steps => steps.sort((a, b) => (a.position ?? 0) - (b.position ?? 0)));
    return items;
}

export const isQueueItemActive = (item: QueueItem): boolean =>
    item.type === "operation" ? isActive(item.operation) : item.steps.some(isActive);

/** Active while any step is, then the worst outcome among its steps. */
export function runStatus(steps: readonly Operation[]): OperationStatus {
    if (steps.some(isActive)) {
        return steps.every(step => step.status === "queued") ? "queued" : "running";
    }
    if (steps.some(step => step.status === "error")) return "error";
    if (steps.some(step => step.status === "cancelled")) return "cancelled";
    return "done";
}
