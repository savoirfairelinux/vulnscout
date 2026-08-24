/**
 * HTTP client for the operation queue.
 *
 * Progress never comes back through these calls; it arrives on the event
 * stream. These only enqueue, cancel and dismiss.
 */

import type { Operation, OperationJob, RefreshSource, ScanSource } from "../types/operation";

export type EnqueueResult =
    | { ok: true; queueId: string; operations: Operation[] }
    | { ok: false; error: string; conflicts?: string[] };

const api = (path: string) => import.meta.env.VITE_API_URL + path;

async function errorFrom(response: Response): Promise<{ error: string; conflicts?: string[] }> {
    const data = await response.json().catch(() => ({}));
    return {
        error: data?.error ?? `HTTP ${response.status}`,
        conflicts: Array.isArray(data?.operations) ? data.operations : undefined,
    };
}

class Operations {
    /** Queue a batch. The backend orders scans before refreshes. */
    static async enqueue(jobs: OperationJob[]): Promise<EnqueueResult> {
        const response = await fetch(api("/api/operations"), {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jobs }),
        });
        if (response.status === 202) {
            const data = await response.json();
            return { ok: true, queueId: data.queue_id, operations: data.operations };
        }
        return { ok: false, ...(await errorFrom(response)) };
    }

    static scanJob(
        source: ScanSource,
        variantIds: string[],
        options: { excludeKernel?: boolean; mode?: "local" | "api" } = {},
    ): OperationJob {
        return {
            kind: "scan",
            source,
            variant_ids: variantIds,
            options: {
                exclude_kernel: options.excludeKernel ?? true,
                mode: options.mode ?? "local",
            },
        };
    }

    static refreshJob(
        source: RefreshSource,
        ids: string[],
        options: { mode?: "local" | "api" } = {},
    ): OperationJob {
        return { kind: "refresh", source, ids, options: { mode: options.mode ?? "local" } };
    }

    static deferredRefreshJob(
        source: RefreshSource,
        variantIds: string[],
        excludeIds: string[],
        options: { mode?: "local" | "api" } = {},
    ): OperationJob {
        return {
            kind: "refresh",
            source,
            variant_ids: variantIds,
            exclude_ids: excludeIds,
            options: { mode: options.mode ?? "local" },
        };
    }

    static async cancel(opId: string): Promise<boolean> {
        const response = await fetch(api(`/api/operations/${encodeURIComponent(opId)}/cancel`), {
            method: "POST",
            mode: "cors",
        });
        return response.ok;
    }

    static async cancelQueue(queueId: string): Promise<number> {
        const response = await fetch(api(`/api/operations/queue/${encodeURIComponent(queueId)}/cancel`), {
            method: "POST",
            mode: "cors",
        });
        if (!response.ok) return 0;
        const data = await response.json().catch(() => ({}));
        return data?.cancelled ?? 0;
    }

    /** Drop a finished operation so it disappears for every connected client. */
    static async dismiss(opId: string): Promise<boolean> {
        const response = await fetch(api(`/api/operations/${encodeURIComponent(opId)}`), {
            method: "DELETE",
            mode: "cors",
        });
        return response.ok;
    }

    /** Fallback snapshot for clients that cannot hold a stream open. */
    static async list(): Promise<Operation[]> {
        const response = await fetch(api("/api/operations"), { mode: "cors" });
        if (!response.ok) return [];
        const data = await response.json().catch(() => null);
        return Array.isArray(data?.operations) ? data.operations : [];
    }
}

export default Operations;
