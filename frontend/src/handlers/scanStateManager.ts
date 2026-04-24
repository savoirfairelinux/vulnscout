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
    status: "idle" | "running" | "done" | "error";
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

    constructor(
        /** Function to trigger a scan for one variant */
        private triggerFn: (vid: string) => Promise<{ ok: boolean; error?: string }>,
        /** Function to poll status for one variant */
        private statusFn: (vid: string) => Promise<StatusResponse>,
        /** Human label for error messages (e.g. "Grype") */
        private label: string,
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
     */
    triggerScan = async (variants: Array<{ id: string; name: string }>) => {
        if (variants.length === 0) return;

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

    private startPolling() {
        this.stopPolling();
        this.pollTimer = setInterval(async () => {
            try {
                const activeIds = [...this.states.entries()]
                    .filter(([, s]) => s.status === "running")
                    .map(([id]) => id);

                if (activeIds.length === 0) {
                    this.stopPolling();
                    return;
                }

                const results = await Promise.all(
                    activeIds.map(async (vid) => {
                        const status = await this.statusFn(vid);
                        return { vid, status };
                    }),
                );

                let anyChanged = false;

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

                // If nothing is running any more, stop and fire onDone
                const stillRunning = [...this.states.values()].some(
                    (s) => s.status === "running",
                );
                if (!stillRunning) {
                    this.stopPolling();
                    this.onDoneCallback?.();
                }
            } catch {
                // Network hiccup — keep polling
            }
        }, 3000);
    }
}
