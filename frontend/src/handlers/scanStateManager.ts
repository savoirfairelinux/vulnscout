/**
 * Generic scan-state manager that tracks per-variant progress.
 *
 * Each scan type (Grype / NVD / OSV) creates one instance.
 * State survives component unmounts because the instance lives at
 * module scope, outside the React tree.
 *
 * The public API (`subscribe` / `getSnapshot`) follows the
 * useSyncExternalStore contract so consumers can simply do:
 *
 *   const entries = useSyncExternalStore(manager.subscribe, manager.getSnapshot);
 */

// ---- public types ----
export type ScanEntryState = {
    variantId: string;
    variantName: string;
    status: "idle" | "queued" | "running" | "done" | "error";
    error: string | null;
    progress: string | null;
    logs: string[];
    total: number;
    doneCount: number;
};

export type ScanManagerSnapshot = readonly ScanEntryState[];

// Status response shape returned by the backend polling endpoints
type StatusResponse = {
    status: string;
    error?: string | null;
    progress?: string | null;
    logs?: string[];
    total?: number;
    done_count?: number;
};

// ---- manager class ----

export class ScanStateManager {
    /** Per-variant state keyed by variant id */
    private states = new Map<string, ScanEntryState>();

    /** Single poll timer – polls all running variants */
    private pollTimer: ReturnType<typeof setInterval> | null = null;

    /** Listeners registered via subscribe() */
    private listeners = new Set<() => void>();

    /**
     * Referentially-stable snapshot array.
     * Recreated only when state actually changes.
     */
    private snapshotRef: ScanManagerSnapshot = [];

    /** Optional callback invoked when *all* running scans finish */
    private onDoneCallback: (() => void) | null = null;

    /** Queue of variants waiting to be triggered (serial mode only) */
    private pendingQueue: Array<{ id: string; name: string }> = [];

    constructor(
        /** Function to trigger a scan for one variant */
        private triggerFn: (vid: string) => Promise<{ ok: boolean; error?: string }>,
        /** Function to poll status for one variant */
        private statusFn: (vid: string) => Promise<StatusResponse>,
        /** Human label for error messages (e.g. "Grype") */
        private label: string,
        /**
         * When true, run scans one variant at a time — the next scan
         * only starts after the previous one finishes.  This prevents
         * concurrent backend processes that share global state (e.g.
         * ``flask process``) from interfering with each other.
         */
        private serial: boolean = false,
    ) {}

    // ---- useSyncExternalStore API ----

    subscribe = (fn: () => void): (() => void) => {
        this.listeners.add(fn);
        return () => {
            this.listeners.delete(fn);
        };
    };

    getSnapshot = (): ScanManagerSnapshot => {
        return this.snapshotRef;
    };

    // ---- lifecycle ----

    setOnDone = (cb: (() => void) | null) => {
        this.onDoneCallback = cb;
    };

    /** Dismiss one variant's panel */
    dismiss = (variantId: string) => {
        this.states.delete(variantId);
        this.rebuildSnapshot();
        // Stop the timer if nothing is left to poll
        if (![...this.states.values()].some((s) => s.status === "running")) {
            this.stopPolling();
        }
    };

    /** Dismiss all panels */
    dismissAll = () => {
        this.stopPolling();
        this.states.clear();
        this.rebuildSnapshot();
    };

    /**
     * Trigger scans for one or more variants.
     * Each variant gets its own state entry and log panel.
     *
     * In **serial** mode only the first variant is triggered immediately;
     * the rest are queued and started one-by-one as each finishes.
     */
    triggerScan = async (variants: Array<{ id: string; name: string }>) => {
        if (variants.length === 0) return;

        if (this.serial) {
            // Show all entries immediately; first is "running", rest are "queued"
            for (let i = 0; i < variants.length; i++) {
                const v = variants[i];
                this.states.set(v.id, {
                    variantId: v.id,
                    variantName: v.name,
                    status: i === 0 ? "running" : "queued",
                    error: null,
                    progress: i === 0 ? "starting" : "Queued",
                    logs: i === 0 ? [] : ["Waiting for previous scan to finish…"],
                    total: 0,
                    doneCount: 0,
                });
            }
            this.pendingQueue = variants.slice(1);
            this.rebuildSnapshot();

            // Trigger only the first variant
            const first = variants[0];
            const result = await this.triggerFn(first.id);
            if (!result.ok) {
                this.setVariantState(first.id, {
                    status: "error",
                    error: result.error ?? `Failed to start ${this.label} scan`,
                    progress: null,
                });
                this.triggerNextInQueue();
            }

            // Start polling (will also advance the queue as variants finish)
            if ([...this.states.values()].some((s) => s.status === "running")) {
                this.startPolling();
            }
            return;
        }

        // ---- parallel mode (default) ----
        // Create "running" entries
        for (const v of variants) {
            this.states.set(v.id, {
                variantId: v.id,
                variantName: v.name,
                status: "running",
                error: null,
                progress: "starting",
                logs: [],
                total: 0,
                doneCount: 0,
            });
        }
        this.rebuildSnapshot();

        // Trigger each scan sequentially (avoids overwhelming the backend)
        for (const v of variants) {
            const result = await this.triggerFn(v.id);
            if (!result.ok) {
                this.setVariantState(v.id, {
                    status: "error",
                    error: result.error ?? `Failed to start ${this.label} scan`,
                    progress: null,
                });
            }
        }

        // Start polling if any variant is still running
        if ([...this.states.values()].some((s) => s.status === "running")) {
            this.startPolling();
        }
    };

    // ---- internal helpers ----

    private emit() {
        this.listeners.forEach((fn) => fn());
    }

    private rebuildSnapshot() {
        // Only include non-idle entries
        this.snapshotRef = [...this.states.values()];
        this.emit();
    }

    private setVariantState(variantId: string, patch: Partial<ScanEntryState>) {
        const current = this.states.get(variantId);
        if (!current) return;
        this.states.set(variantId, { ...current, ...patch });
        this.rebuildSnapshot();
    }

    private stopPolling() {
        if (this.pollTimer !== null) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    /**
     * (Serial mode only) Trigger the next queued variant, if any.
     */
    private triggerNextInQueue() {
        if (!this.serial || this.pendingQueue.length === 0) return;
        const next = this.pendingQueue.shift()!;
        this.setVariantState(next.id, {
            status: "running",
            progress: "starting",
            logs: [],
        });
        this.triggerFn(next.id).then((result) => {
            if (!result.ok) {
                this.setVariantState(next.id, {
                    status: "error",
                    error: result.error ?? `Failed to start ${this.label} scan`,
                    progress: null,
                });
                // Keep going — try next in queue
                this.triggerNextInQueue();
            }
            // Polling is already running, will pick up the new running variant
        });
    }

    private startPolling() {
        this.stopPolling();
        this.pollTimer = setInterval(async () => {
            try {
                // Only poll variants that are actually running (not queued)
                const activeIds = [...this.states.entries()]
                    .filter(([, s]) => s.status === "running")
                    .map(([id]) => id);

                if (activeIds.length === 0) {
                    // Nothing running; if there are queued items, don't stop
                    if (this.pendingQueue.length === 0) {
                        this.stopPolling();
                    }
                    return;
                }

                const results = await Promise.all(
                    activeIds.map(async (vid) => {
                        const status = await this.statusFn(vid);
                        return { vid, status };
                    }),
                );

                let anyChanged = false;
                let anyJustFinished = false;

                for (const { vid, status } of results) {
                    const current = this.states.get(vid);
                    if (!current || current.status !== "running") continue;

                    if (status.status === "error") {
                        this.states.set(vid, {
                            ...current,
                            status: "error",
                            error: status.error ?? `${this.label} scan failed`,
                            progress: null,
                        });
                        anyChanged = true;
                        anyJustFinished = true;
                    } else if (status.status === "done" || status.status === "idle") {
                        this.states.set(vid, {
                            ...current,
                            status: "done",
                            error: null,
                            progress: status.progress ?? null,
                            logs: status.logs ?? current.logs,
                            total: status.total ?? current.total,
                            doneCount: status.done_count ?? current.doneCount,
                        });
                        anyChanged = true;
                        anyJustFinished = true;
                    } else if (status.status === "running" && status.progress) {
                        this.states.set(vid, {
                            ...current,
                            progress: status.progress,
                            logs: status.logs ?? current.logs,
                            total: status.total ?? current.total,
                            doneCount: status.done_count ?? current.doneCount,
                        });
                        anyChanged = true;
                    }
                }

                if (anyChanged) {
                    this.rebuildSnapshot();
                }

                // In serial mode, advance the queue when a scan finishes
                if (anyJustFinished) {
                    this.triggerNextInQueue();
                }

                // If nothing is running and nothing queued, stop and fire onDone
                const stillRunning = [...this.states.values()].some(
                    (s) => s.status === "running",
                );
                if (!stillRunning && this.pendingQueue.length === 0) {
                    this.stopPolling();
                    this.onDoneCallback?.();
                }
            } catch {
                // Network hiccup — keep polling
            }
        }, 3000);
    }
}
