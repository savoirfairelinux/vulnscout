import { BulkEpssRefreshHandler, BulkEuvdRefreshHandler, BulkGhsaRefreshHandler, BulkNvdRefreshHandler } from "./bulkRefresh";
import EPSSProgressHandler from "./epss_progress";
import EUVDProgressHandler from "./euvd_progress";
import { getSnapshot as getGrypeSnapshot, waitForCompletion as waitForGrypeCompletion } from "./grypeScanState";
import GHSAProgressHandler from "./ghsa_progress";
import { getSnapshot as getNvdSnapshot, waitForCompletion as waitForNvdCompletion } from "./nvdScanState";
import NVDProgressHandler from "./nvd_progress";
import { getSnapshot as getOsvSnapshot, waitForCompletion as waitForOsvCompletion } from "./osvScanState";
import type { ScanEntryState, ScanManagerSnapshot } from "./scanStateManager";
import { getSnapshot as getSccSnapshot, waitForCompletion as waitForSccCompletion } from "./sccScanState";
import type { Vulnerability } from "./vulnerabilities";

export type RefreshType = "nvd" | "epss" | "ghsa" | "euvd";

type RefreshProgress = {
    in_progress: boolean;
    phase: string;
    current: number;
    total: number;
    message: string;
    last_update?: string;
    started_at?: string;
};

type QueueOptions = {
    refreshTypes: RefreshType[];
    nvdMode: "local" | "api";
    loadVulnerabilities: () => Promise<Vulnerability[]>;
    onRefreshComplete?: () => void;
};

type RefreshSource = {
    label: string;
    noun: string;
    getProgress: () => Promise<RefreshProgress>;
    trigger: (cveIds: string[], ghsaIds: string[], nvdMode: "local" | "api") => Promise<{ total: number } | null>;
};

const REFRESH_ORDER: RefreshType[] = ["nvd", "epss", "ghsa", "euvd"];
const POLL_INTERVAL_MS = 3000;
const MAX_STARTUP_POLLS = 20;
const MAX_CONSECUTIVE_POLL_FAILURES = 10;
const sources: Record<RefreshType, RefreshSource> = {
    nvd: { label: "NVD", noun: "CVEs", getProgress: NVDProgressHandler.getProgress, trigger: (cveIds, _ghsaIds, nvdMode) => BulkNvdRefreshHandler.trigger(cveIds, nvdMode) },
    epss: { label: "EPSS", noun: "CVEs", getProgress: EPSSProgressHandler.getProgress, trigger: cveIds => BulkEpssRefreshHandler.trigger(cveIds) },
    ghsa: { label: "GHSA", noun: "advisories", getProgress: GHSAProgressHandler.getProgress, trigger: (_cveIds, ghsaIds) => BulkGhsaRefreshHandler.trigger(ghsaIds) },
    euvd: { label: "ENISA EUVD", noun: "CVEs", getProgress: EUVDProgressHandler.getProgress, trigger: cveIds => BulkEuvdRefreshHandler.trigger(cveIds) },
};

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

let refreshEntries = new Map<RefreshType, ScanEntryState>();
let refreshSnapshot: ScanManagerSnapshot = [];
const refreshListeners = new Set<() => void>();
let refreshRestorePromise: Promise<void> | null = null;

const publishRefreshEntries = () => {
    refreshSnapshot = REFRESH_ORDER.flatMap(type => {
        const entry = refreshEntries.get(type);
        return entry ? [entry] : [];
    });
    refreshListeners.forEach(listener => listener());
};

const setRefreshEntry = (type: RefreshType, patch: Partial<ScanEntryState>) => {
    const current = refreshEntries.get(type);
    if (!current) return;
    refreshEntries.set(type, { ...current, ...patch });
    publishRefreshEntries();
};

export const subscribeToRefreshQueue = (listener: () => void): (() => void) => {
    refreshListeners.add(listener);
    return () => refreshListeners.delete(listener);
};

export const getRefreshQueueSnapshot = (): ScanManagerSnapshot => refreshSnapshot;
export const hasActiveRefreshes = (): boolean => refreshSnapshot.some(entry => isActive(entry.status));

const waitForTrackedRefreshes = (): Promise<void> => {
    if (!refreshSnapshot.some(entry => isActive(entry.status))) return Promise.resolve();

    return new Promise(resolve => {
        const unsubscribe = subscribeToRefreshQueue(() => {
            if (refreshSnapshot.some(entry => isActive(entry.status))) return;
            unsubscribe();
            resolve();
        });
    });
};

async function monitorRestoredRefresh(type: RefreshType, initialProgress: RefreshProgress) {
    const source = sources[type];
    let progress = initialProgress;
    let consecutivePollFailures = 0;

    while (progress.in_progress) {
        await delay();
        try {
            progress = await source.getProgress();
            consecutivePollFailures = 0;
        } catch {
            consecutivePollFailures += 1;
            if (consecutivePollFailures < MAX_CONSECUTIVE_POLL_FAILURES) continue;
            const message = `Lost ${source.label} refresh progress`;
            setRefreshEntry(type, { status: "error", error: message, progress: null, logs: [message] });
            return;
        }
        const message = progress.message || (progress.in_progress ? "Refreshing" : "Complete");
        setRefreshEntry(type, { progress: message, logs: message ? [message] : [], total: progress.total, doneCount: progress.current });
    }

    if (progress.phase === "error") {
        const message = progress.message || `${source.label} refresh failed`;
        setRefreshEntry(type, { status: "error", error: message, progress: null, logs: [message] });
        return;
    }
    if (progress.phase !== "completed" && progress.phase !== "cancelled") {
        const message = `Unexpected ${source.label} refresh state: ${progress.phase || "unknown"}`;
        setRefreshEntry(type, { status: "error", error: message, progress: null, logs: [message] });
        return;
    }
    const cancelled = progress.phase === "cancelled";
    setRefreshEntry(type, {
        status: cancelled ? "cancelled" : "done",
        progress: cancelled ? "Cancelled" : "Complete",
        logs: [cancelled ? `${source.label} refresh was cancelled.` : `${source.label} refresh completed.`],
        total: progress.total,
        doneCount: progress.current || progress.total,
    });
}

export const restoreActiveRefreshes = (): Promise<void> => {
    if (refreshSnapshot.some(entry => isActive(entry.status))) return Promise.resolve();
    if (refreshRestorePromise) return refreshRestorePromise;

    refreshRestorePromise = (async () => {
        const results = await Promise.allSettled(REFRESH_ORDER.map(type => sources[type].getProgress()));
        if (refreshSnapshot.some(entry => isActive(entry.status))) return;

        const restored = REFRESH_ORDER.flatMap((type, index) => {
            const result = results[index];
            if (result.status !== "fulfilled" || !result.value?.in_progress) return [];
            const progress = result.value;
            return [{ type, progress }];
        });
        if (restored.length === 0) return;

        for (const { type, progress } of restored) {
            refreshEntries.set(type, {
                variantId: type,
                variantName: sources[type].label,
                status: "running",
                error: null,
                progress: progress.message || "Refreshing",
                logs: progress.message ? [progress.message] : [],
                total: progress.total,
                doneCount: progress.current,
            });
        }
        publishRefreshEntries();
        restored.forEach(({ type, progress }) => void monitorRestoredRefresh(type, progress));
    })().finally(() => {
        refreshRestorePromise = null;
    });
    return refreshRestorePromise;
};

export const waitForRefreshCompletion = async (): Promise<void> => {
    await restoreActiveRefreshes();
    await waitForTrackedRefreshes();
};

export const dismissRefreshQueueEntry = (type: RefreshType) => {
    const entry = refreshEntries.get(type);
    if (!entry || isActive(entry.status)) return;
    refreshEntries.delete(type);
    publishRefreshEntries();
};

const delay = () => new Promise<void>(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
const cycleChanged = (baseline: RefreshProgress | null, current: RefreshProgress) =>
    current.in_progress || Boolean(baseline && current.started_at && current.started_at !== baseline.started_at) || Boolean(baseline && current.last_update && current.last_update !== baseline.last_update);

async function runRefresh(type: RefreshType, cveIds: string[], ghsaIds: string[], nvdMode: "local" | "api") {
    const source = sources[type];
    const ids = type === "ghsa" ? ghsaIds : cveIds;
    if (ids.length === 0) {
        setRefreshEntry(type, { status: "done", progress: "No matching vulnerabilities", logs: [`No ${source.noun} were available after scans completed.`] });
        return;
    }

    let baseline: RefreshProgress | null = null;
    try {
        baseline = await source.getProgress();
    } catch {
        // A baseline is optional; active progress still identifies the new cycle.
    }
    setRefreshEntry(type, { status: "running", progress: "Starting", logs: [`Starting ${source.label} refresh for ${ids.length} ${source.noun}...`], total: ids.length, doneCount: 0 });
    const result = await source.trigger(cveIds, ghsaIds, nvdMode);
    if (!result) throw new Error(`Failed to start ${source.label} refresh`);

    let observedNewCycle = false;
    let startupPolls = 0;
    let consecutivePollFailures = 0;
    while (true) {
        await delay();
        let progress: RefreshProgress;
        try {
            progress = await source.getProgress();
        } catch {
            consecutivePollFailures += 1;
            if (consecutivePollFailures >= MAX_CONSECUTIVE_POLL_FAILURES) {
                throw new Error(`Lost ${source.label} refresh progress`);
            }
            continue;
        }
        consecutivePollFailures = 0;
        observedNewCycle ||= cycleChanged(baseline, progress);
        const total = progress.total || result.total || ids.length;
        const message = progress.message || (progress.in_progress ? "Refreshing" : "Waiting for refresh progress");
        setRefreshEntry(type, { progress: message, logs: message ? [message] : [], total, doneCount: progress.current });
        if (!observedNewCycle) {
            startupPolls += 1;
            if (startupPolls >= MAX_STARTUP_POLLS) {
                throw new Error(`${source.label} refresh did not start`);
            }
            continue;
        }
        if (progress.in_progress) continue;

        if (progress.phase === "error") {
            throw new Error(progress.message || `${source.label} refresh failed`);
        }
        if (progress.phase !== "completed" && progress.phase !== "cancelled") {
            throw new Error(`Unexpected ${source.label} refresh state: ${progress.phase || "unknown"}`);
        }

        const cancelled = progress.phase === "cancelled";
        setRefreshEntry(type, { status: cancelled ? "cancelled" : "done", progress: cancelled ? "Cancelled" : "Complete", logs: [cancelled ? `${source.label} refresh was cancelled.` : `${source.label} refresh completed.`], total, doneCount: progress.current || total });
        return;
    }
}

export function queueVulnerabilityRefresh({ refreshTypes, nvdMode, loadVulnerabilities, onRefreshComplete }: QueueOptions): boolean {
    if (refreshSnapshot.some(entry => isActive(entry.status))) return false;
    const selectedTypes = REFRESH_ORDER.filter(type => refreshTypes.includes(type));
    if (selectedTypes.length === 0) return false;

    refreshEntries = new Map(selectedTypes.map(type => [type, {
        variantId: type,
        variantName: sources[type].label,
        status: "queued" as const,
        error: null,
        progress: "Queued",
        logs: ["Waiting for earlier queued operations to finish..."],
        total: 0,
        doneCount: 0,
    }]));
    publishRefreshEntries();

    void (async () => {
        await waitForActiveScans();
        let vulnerabilities: Vulnerability[];
        try {
            vulnerabilities = await loadVulnerabilities();
        } catch (error) {
            const message = error instanceof Error ? error.message : "Failed to reload vulnerabilities";
            selectedTypes.forEach(type => setRefreshEntry(type, { status: "error", error: message, progress: null, logs: [message] }));
            return;
        }
        const cveIds = vulnerabilities.map(vulnerability => vulnerability.id).filter(id => id.toUpperCase().startsWith("CVE-"));
        const ghsaIds = vulnerabilities.map(vulnerability => vulnerability.id).filter(id => id.toUpperCase().startsWith("GHSA-"));
        const applicableTypes = selectedTypes.filter(type => type === "ghsa" ? ghsaIds.length > 0 : cveIds.length > 0);
        const skippedTypes = selectedTypes.filter(type => !applicableTypes.includes(type));
        if (skippedTypes.length > 0) {
            // Drop only our own entries: the map is shared with restoreActiveRefreshes().
            skippedTypes.forEach(type => refreshEntries.delete(type));
            publishRefreshEntries();
        }
        for (const type of applicableTypes) {
            try {
                await runRefresh(type, cveIds, ghsaIds, nvdMode);
            } catch (error) {
                const message = error instanceof Error ? error.message : `Failed to run ${sources[type].label} refresh`;
                setRefreshEntry(type, { status: "error", error: message, progress: null, logs: [message] });
            }
        }
        onRefreshComplete?.();
    })();
    return true;
}