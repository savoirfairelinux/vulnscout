import { getSnapshot as getGrypeSnapshot, waitForCompletion as waitForGrypeCompletion } from "./grypeScanState";
import { getSnapshot as getNvdSnapshot, waitForCompletion as waitForNvdCompletion } from "./nvdScanState";
import { getSnapshot as getOsvSnapshot, waitForCompletion as waitForOsvCompletion } from "./osvScanState";
import { getSnapshot as getSccSnapshot, waitForCompletion as waitForSccCompletion } from "./sccScanState";
import type { ScanEntryState, ScanManagerSnapshot } from "./scanStateManager";

const isActive = (status: string) => status === "queued" || status === "running";

export async function waitForActiveScans(): Promise<boolean> {
    const scanQueues = [
        [getGrypeSnapshot, waitForGrypeCompletion],
        [getNvdSnapshot, waitForNvdCompletion],
        [getOsvSnapshot, waitForOsvCompletion],
        [getSccSnapshot, waitForSccCompletion],
    ] as const;
    const activeQueues = scanQueues.filter(([getSnapshot]) => getSnapshot().some(scan => isActive(scan.status)));
    if (activeQueues.length === 0) return false;

    await Promise.all(activeQueues.map(([, waitForCompletion]) => waitForCompletion()));
    return true;
}

const REFRESH_ID = "vulnerability-data-refresh";
let refreshEntry: ScanEntryState | null = null;
let refreshSnapshot: ScanManagerSnapshot = [];
const refreshListeners = new Set<() => void>();

const publishRefreshEntry = (entry: ScanEntryState | null) => {
    refreshEntry = entry;
    refreshSnapshot = entry ? [entry] : [];
    refreshListeners.forEach(listener => listener());
};

export const subscribeToRefreshQueue = (listener: () => void): (() => void) => {
    refreshListeners.add(listener);
    return () => refreshListeners.delete(listener);
};

export const getRefreshQueueSnapshot = (): ScanManagerSnapshot => refreshSnapshot;

export const dismissRefreshQueueEntry = () => publishRefreshEntry(null);

export function queueVulnerabilityRefresh(runRefresh: () => Promise<void>): boolean {
    if (refreshEntry?.status === "queued" || refreshEntry?.status === "running") return false;

    publishRefreshEntry({
        variantId: REFRESH_ID,
        variantName: "Selected vulnerability sources",
        status: "queued",
        error: null,
        progress: "Queued",
        logs: ["Waiting for active scans to finish..."],
        total: 0,
        doneCount: 0,
    });

    void (async () => {
        try {
            await waitForActiveScans();
            publishRefreshEntry({
                ...refreshEntry!,
                status: "running",
                progress: "Starting refresh",
                logs: [],
            });
            await runRefresh();
            publishRefreshEntry({
                ...refreshEntry!,
                status: "done",
                progress: "Refresh started",
                logs: ["Vulnerability data refresh started successfully."],
                doneCount: 1,
                total: 1,
            });
        } catch (error) {
            const message = error instanceof Error ? error.message : "Failed to start vulnerability data refresh";
            publishRefreshEntry({
                ...refreshEntry!,
                status: "error",
                error: message,
                progress: null,
                logs: [message],
            });
        }
    })();
    return true;
}