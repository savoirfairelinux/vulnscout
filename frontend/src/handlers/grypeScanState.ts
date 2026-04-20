/**
 * Module-level singleton that manages Grype scan state globally.
 *
 * Because ScanHistory is conditionally rendered (unmounts on tab change),
 * the polling and status must live outside the component tree so a scan
 * keeps running even when the user navigates away from the Scans tab.
 */

import ScansHandler from "./scans";

// ---- public state shape ----
export type GrypeState = {
    status: "idle" | "running" | "done" | "error";
    error: string | null;
    progress: string | null;
    logs: string[];
    total: number;
    doneCount: number;
};

// ---- internal module state ----
// IMPORTANT: `stateRef` is the object returned by getSnapshot() and must be
// referentially stable (same object identity) when nothing has changed,
// because useSyncExternalStore compares with Object.is.
let stateRef: GrypeState = { status: "idle", error: null, progress: null, logs: [], total: 0, doneCount: 0 };
let pollTimer: ReturnType<typeof setInterval> | null = null;
let activeVariantIds: string[] = [];
const listeners = new Set<(s: GrypeState) => void>();

// callback invoked when a scan finishes (allows the consumer to refresh data)
let onDoneCallback: (() => void) | null = null;

function emit() {
    listeners.forEach((fn) => fn(stateRef));
}

function setState(patch: Partial<GrypeState>) {
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
                activeVariantIds.map((vid) => ScansHandler.getGrypeScanStatus(vid))
            );
            const anyError = statuses.find((s) => s.status === "error");
            const allDone = statuses.every(
                (s) => s.status === "done" || s.status === "idle"
            );

            // Capture latest progress
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
                    error: anyError.error ?? "Grype scan failed",
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

/** Subscribe to state changes.  Returns an unsubscribe function. */
export function subscribe(fn: (s: GrypeState) => void): () => void {
    listeners.add(fn);
    return () => {
        listeners.delete(fn);
    };
}

/** Read the current snapshot (must return a referentially stable object). */
export function getSnapshot(): GrypeState {
    return stateRef;
}

/** Register a callback fired once when the running scan finishes. */
export function setOnDone(cb: (() => void) | null) {
    onDoneCallback = cb;
}

/** Dismiss the log panel (reset state to idle). */
export function dismiss() {
    stopPolling();
    setState({ status: "idle", error: null, progress: null, logs: [], total: 0, doneCount: 0 });
}

/** Trigger Grype scans for the given variant IDs. */
export async function triggerScan(variantIds: string[]) {
    if (variantIds.length === 0) return;
    setState({ status: "running", error: null, progress: "starting", logs: [], total: 0, doneCount: 0 });
    activeVariantIds = [...variantIds];

    for (const vid of variantIds) {
        const result = await ScansHandler.triggerGrypeScan(vid);
        if (!result.ok) {
            setState({
                status: "error",
                error: result.error ?? "Failed to start Grype scan",
            });
            return;
        }
    }

    startPolling();
}
