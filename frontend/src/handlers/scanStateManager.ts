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
    variantPosition?: number;
    variantCount?: number;
    status: "idle" | "queued" | "running" | "done" | "error" | "cancelled";
    error: string | null;
    progress: string | null;
    logs: string[];
    total: number;
    doneCount: number;
};

export type ScanManagerSnapshot = readonly ScanEntryState[];

/** Options forwarded to the per-variant trigger call. */
export type ScanTriggerOptions = {
    /** Exclude kernel companion packages from scanner inputs (default true). */
    excludeKernel?: boolean;
    /** NVD data source: "local" (default) uses local NVD-FKIE DB; "api" uses NVD REST API. */
    nvdMode?: "local" | "api";
};

// Status response shape returned by the backend polling endpoints
type StatusResponse = {
    status: string;
    error?: string | null;
    progress?: string | null;
    logs?: string[];
    total?: number;
    done_count?: number;
};

const MAX_CONSECUTIVE_STATUS_FAILURES = 10;

// ---- manager class ----

export class ScanStateManager {
    /** Per-variant state keyed by variant id */
    private states = new Map<string, ScanEntryState>();

    /** Single poll timer – polls all running variants */
    private pollTimer: ReturnType<typeof setInterval> | null = null;

    /** Prevents slow status requests from creating overlapping poll ticks. */
    private pollInFlight = false;

    /** Listeners registered via subscribe() */
    private listeners = new Set<() => void>();

    /**
     * Referentially-stable snapshot array.
     * Recreated only when state actually changes.
     */
    private snapshotRef: ScanManagerSnapshot = [];

    /** Optional callback invoked when *all* running scans finish */
    private onDoneCallback: (() => void) | null = null;

    /** Resolves when the current scan batch has no running or queued entries. */
    private completionPromise: Promise<void> | null = null;

    /** Resolver for the current scan batch completion promise. */
    private resolveCompletion: (() => void) | null = null;

    /** Queue of variants waiting to be triggered (serial mode only) */
    private pendingQueue: Array<{ id: string; name: string }> = [];

    /** Options forwarded to every triggerFn call of the current run */
    private currentOptions: ScanTriggerOptions = {};

    /** Consecutive unavailable/invalid status responses per running variant. */
    private pollFailureCounts = new Map<string, number>();

    constructor(
        /** Function to trigger a scan for one variant */
        private triggerFn: (vid: string, opts: ScanTriggerOptions) => Promise<{ ok: boolean; error?: string }>,
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

    waitForCompletion = (): Promise<void> => this.completionPromise ?? Promise.resolve();

    /**
     * Register a serial scan batch without starting it, so callers can show
     * the entire global queue before allowing its turn to begin.
     */
    queueScan = async (variants: Array<{ id: string; name: string }>, opts: ScanTriggerOptions = {}) => {
        if (variants.length === 0 || this.hasActiveWork()) return;

        this.currentOptions = opts;
        this.completionPromise = new Promise(resolve => {
            this.resolveCompletion = resolve;
        });

        for (let i = 0; i < variants.length; i++) {
            const variant = variants[i];
            this.states.set(variant.id, {
                variantId: variant.id,
                variantName: variant.name,
                variantPosition: i + 1,
                variantCount: variants.length,
                status: "queued",
                error: null,
                progress: "Queued",
                logs: ["Waiting for previous scan to finish…"],
                total: 0,
                doneCount: 0,
            });
        }
        this.pendingQueue = [...variants];
        this.rebuildSnapshot();
    };

    /** Start the next previously queued serial scan batch. */
    startQueuedScan = async () => {
        if (!this.serial || this.pendingQueue.length === 0) return;

        this.triggerNextInQueue();
        if ([...this.states.values()].some((state) => state.status === "running")) {
            this.startPolling();
        } else {
            this.completeRunIfFinished();
        }
    };

    /** Dismiss one variant's panel */
    dismiss = (variantId: string) => {
        const state = this.states.get(variantId);
        if (!state || state.status === "running" || state.status === "queued") return;
        this.states.delete(variantId);
        this.pollFailureCounts.delete(variantId);
        this.rebuildSnapshot();
        // Stop the timer if nothing is left to poll
        if (![...this.states.values()].some((s) => s.status === "running")) {
            this.stopPolling();
        }
    };

    /** Dismiss all panels */
    dismissAll = () => {
        for (const [variantId, state] of this.states) {
            if (state.status === "running" || state.status === "queued") continue;
            this.states.delete(variantId);
            this.pollFailureCounts.delete(variantId);
        }
        this.rebuildSnapshot();
        if (!this.hasActiveWork()) this.stopPolling();
    };

    /**
     * Re-seed in-progress scans after a page refresh from status data that
     * the caller has already fetched (typically via the bulk
     * ``/api/scans/running`` endpoint, so no per-variant polling is needed).
     *
     * Each entry whose backend status is "running" is added to the local
     * state map and polling is (re)started. Variants already tracked in
     * memory are left untouched, so a scan triggered earlier in this session
     * is never clobbered.
     *
     * Note: queued-but-not-yet-started variants (serial mode) are not
     * restored — they were never started server-side, so there is nothing to
     * resume.
     *
     * @param entries  Running-scan entries with variant id, name and status.
     */
    restoreFromStatus = (
        entries: Array<{ variantId: string; name: string; status: StatusResponse }>,
    ) => {
        let anyRestored = false;

        for (const { variantId, name, status } of entries) {
            // Skip if already tracked (e.g. triggered in this session before restore ran)
            if (this.states.has(variantId)) continue;
            // Only restore actively running scans
            if (status.status !== "running") continue;

            this.states.set(variantId, {
                variantId,
                variantName: name,
                status: "running",
                error: null,
                progress: status.progress ?? "starting",
                logs: status.logs ?? [],
                total: status.total ?? 0,
                doneCount: status.done_count ?? 0,
            });
            anyRestored = true;
        }

        if (anyRestored) {
            if (!this.completionPromise) {
                this.completionPromise = new Promise(resolve => {
                    this.resolveCompletion = resolve;
                });
            }
            this.rebuildSnapshot();
            this.startPolling();
        }
    };

    /**
     * Trigger scans for one or more variants.
     * Each variant gets its own state entry and log panel.
     *
     * In **serial** mode only the first variant is triggered immediately;
     * the rest are queued and started one-by-one as each finishes.
     */
    triggerScan = async (variants: Array<{ id: string; name: string }>, opts: ScanTriggerOptions = {}) => {
        if (variants.length === 0 || this.hasActiveWork()) return;

        this.currentOptions = opts;
        this.completionPromise = new Promise(resolve => {
            this.resolveCompletion = resolve;
        });

        if (this.serial) {
            // Show all entries immediately; first is "running", rest are "queued"
            for (let i = 0; i < variants.length; i++) {
                const v = variants[i];
                this.states.set(v.id, {
                    variantId: v.id,
                    variantName: v.name,
                    variantPosition: i + 1,
                    variantCount: variants.length,
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
            const result = await this.invokeTrigger(first.id);
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
            } else {
                this.completeRunIfFinished();
            }
            return;
        }

        // ---- parallel mode (default) ----
        // Create "running" entries
        for (let i = 0; i < variants.length; i++) {
            const v = variants[i];
            this.states.set(v.id, {
                variantId: v.id,
                variantName: v.name,
                variantPosition: i + 1,
                variantCount: variants.length,
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
            const result = await this.invokeTrigger(v.id);
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
        } else {
            this.completeRunIfFinished();
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

    private hasActiveWork() {
        return this.pendingQueue.length > 0 || [...this.states.values()].some(
            state => state.status === "running" || state.status === "queued",
        );
    }

    private setVariantState(variantId: string, patch: Partial<ScanEntryState>) {
        const current = this.states.get(variantId);
        if (!current) return;
        this.states.set(variantId, { ...current, ...patch });
        this.rebuildSnapshot();
    }

    private async invokeTrigger(variantId: string): Promise<{ ok: boolean; error?: string }> {
        try {
            return await this.triggerFn(variantId, this.currentOptions);
        } catch (error) {
            return {
                ok: false,
                error: error instanceof Error ? error.message : `Failed to start ${this.label} scan`,
            };
        }
    }

    private stopPolling() {
        if (this.pollTimer !== null) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    private completeRunIfFinished() {
        const hasRunningScan = [...this.states.values()].some((s) => s.status === "running");
        if (hasRunningScan || this.pendingQueue.length > 0) return;

        this.stopPolling();
        if (!this.completionPromise) return;
        const resolveCompletion = this.resolveCompletion;
        this.resolveCompletion = null;
        this.completionPromise = null;
        resolveCompletion?.();
        this.onDoneCallback?.();
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
        this.invokeTrigger(next.id).then((result) => {
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
            if (this.pollInFlight) return;
            this.pollInFlight = true;
            try {
                // Only poll variants that are actually running (not queued)
                const activeIds = [...this.states.entries()]
                    .filter(([, s]) => s.status === "running")
                    .map(([id]) => id);

                if (activeIds.length === 0) {
                    // Nothing running; if there are queued items, don't stop
                    if (this.pendingQueue.length === 0) {
                        this.completeRunIfFinished();
                    }
                    return;
                }

                const results = await Promise.all(
                    activeIds.map(async (vid) => {
                        try {
                            const status = await this.statusFn(vid);
                            return { vid, status };
                        } catch {
                            return { vid, status: null };
                        }
                    }),
                );

                let anyChanged = false;
                let anyJustFinished = false;

                for (const { vid, status } of results) {
                    const current = this.states.get(vid);
                    if (!current || current.status !== "running") continue;

                    if (!status || !["running", "done", "idle", "error"].includes(status.status)) {
                        const failures = (this.pollFailureCounts.get(vid) ?? 0) + 1;
                        this.pollFailureCounts.set(vid, failures);
                        if (failures >= MAX_CONSECUTIVE_STATUS_FAILURES) {
                            const message = `Lost ${this.label} scan status`;
                            this.states.set(vid, {
                                ...current,
                                status: "error",
                                error: message,
                                progress: null,
                                logs: [...current.logs, message],
                            });
                            this.pollFailureCounts.delete(vid);
                            anyChanged = true;
                            anyJustFinished = true;
                        }
                        continue;
                    }
                    this.pollFailureCounts.delete(vid);

                    if (status.status === "error") {
                        this.states.set(vid, {
                            ...current,
                            status: "error",
                            error: status.error ?? `${this.label} scan failed`,
                            progress: null,
                            logs: status.logs ?? current.logs,
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
                    } else if (status.status === "running") {
                        this.states.set(vid, {
                            ...current,
                            progress: status.progress ?? current.progress,
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
                    this.completeRunIfFinished();
                }
            } catch {
                // Network hiccup — keep polling
            } finally {
                this.pollInFlight = false;
            }
        }, 3000);
    }
}
