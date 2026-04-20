/**
 * Module-level singleton that manages NVD CPE scan state globally.
 *
 * Mirrors grypeScanState.ts — polling and status live outside the
 * component tree so a scan keeps running when the user navigates away.
 */

import ScansHandler from "./scans";

// ---- public state shape ----
export type NvdState = {
    status: "idle" | "running" | "done" | "error";
    error: string | null;
    progress: string | null;
    logs: string[];
    total: number;
    doneCount: number;
};

// ---- internal module state ----
let stateRef: NvdState = { status: "idle", error: null, progress: null, logs: [], total: 0, doneCount: 0 };
let pollTimer: ReturnType<typeof setInterval> | null = null;
let activeVariantIds: string[] = [];
const listeners = new Set<(s: NvdState) => void>();

let onDoneCallback: (() => void) | null = null;

function emit() {
    listeners.forEach((fn) => fn(stateRef));
}

function setState(patch: Partial<NvdState>) {
    stateRef = { ...stateRef, ...patch };
    emit();
}

function stopPolling() {
    if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

function startPolling() {
    stopPolling();
    pollTimer = setInterval(async () => {
        try {
            const statuses = await Promise.all(
                activeVariantIds.map((vid) => ScansHandler.getNvdScanStatus(vid))
            );
            const anyError = statuses.find((s) => s.status === "error");
            const allDone = statuses.every(
                (s) => s.status === "done" || s.status === "idle"
            );

            // Capture latest progress string
            const running = statuses.find((s) => s.status === "running");
            if (running && running.progress) {
                setState({
                    progress: running.progress,
                    logs: running.logs ?? stateRef.logs,
                    total: running.total ?? stateRef.total,
                    doneCount: running.done_count ?? stateRef.doneCount,
                });
            }

            if (anyError) {
                stopPolling();
                setState({
                    status: "error",
                    error: anyError.error ?? "NVD scan failed",
                    progress: null,
                });
            } else if (allDone && statuses.some((s) => s.status === "done")) {
                stopPolling();
                const doneInfo = statuses.find((s) => s.status === "done");
                setState({
                    status: "done",
                    error: null,
                    progress: doneInfo?.progress ?? null,
                    logs: doneInfo?.logs ?? stateRef.logs,
                    total: doneInfo?.total ?? stateRef.total,
                    doneCount: doneInfo?.done_count ?? stateRef.doneCount,
                });
                onDoneCallback?.();
            }
        } catch {
            // network hiccup — keep polling
        }
    }, 3000);
}

// ---- public API ----

export function subscribe(fn: (s: NvdState) => void): () => void {
    listeners.add(fn);
    return () => {
        listeners.delete(fn);
    };
}

export function getSnapshot(): NvdState {
    return stateRef;
}

export function setOnDone(cb: (() => void) | null) {
    onDoneCallback = cb;
}

/** Dismiss the log panel (reset state to idle). */
export function dismiss() {
    stopPolling();
    setState({ status: "idle", error: null, progress: null, logs: [], total: 0, doneCount: 0 });
}

export async function triggerScan(variantIds: string[]) {
    if (variantIds.length === 0) return;
    setState({ status: "running", error: null, progress: "starting", logs: [], total: 0, doneCount: 0 });
    activeVariantIds = [...variantIds];

    for (const vid of variantIds) {
        const result = await ScansHandler.triggerNvdScan(vid);
        if (!result.ok) {
            setState({
                status: "error",
                error: result.error ?? "Failed to start NVD scan",
                progress: null,
            });
            return;
        }
    }

    startPolling();
}
