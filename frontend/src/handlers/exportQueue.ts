import type { ScanEntryState, ScanManagerSnapshot } from "./scanStateManager";

export type ExportRequest = {
    project_id: string;
    variant_ids: string[];
    mode: "consolidated" | "per_variant";
    documents: Array<{ name: string; extension: string }>;
};

type ExportStatus = {
    status: "running" | "done" | "error";
    current: number;
    total: number;
    progress: string;
    logs: string[];
    error: string | null;
};

const POLL_INTERVAL_MS = 1000;
const MAX_POLL_FAILURES = 3;
const states = new Map<string, ScanEntryState>();
const listeners = new Set<() => void>();
let snapshot: ScanManagerSnapshot = [];
let nextOperationId = 1;

function publish() {
    snapshot = [...states.values()];
    listeners.forEach(listener => listener());
}

function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
}

function responseFilename(response: Response, fallback: string): string {
    const disposition = response.headers.get("Content-Disposition") ?? "";
    return disposition.match(/filename="?([^";]+)/)?.[1] ?? fallback;
}

function updateEntry(localId: string, update: Partial<ScanEntryState>) {
    const current = states.get(localId);
    if (!current) return;
    states.set(localId, { ...current, ...update });
    publish();
}

async function pollExport(
    localId: string,
    jobId: string,
    fallbackFilename: string,
    failedAttempts = 0,
): Promise<void> {
    try {
        const response = await fetch(`${import.meta.env.VITE_API_URL}/api/documents/export/${jobId}`, { mode: "cors" });
        if (!response.ok) throw new Error(`Failed to check export progress (${response.status})`);
        const status = await response.json() as ExportStatus;
        updateEntry(localId, {
            status: status.status === "error" ? "error" : status.status === "done" ? "done" : "running",
            error: status.error,
            progress: status.progress,
            logs: status.logs,
            total: status.total,
            doneCount: status.status === "done" ? status.total : Math.max(0, status.current - 1),
        });

        if (status.status === "running") {
            setTimeout(() => void pollExport(localId, jobId, fallbackFilename), POLL_INTERVAL_MS);
            return;
        }
        if (status.status === "error") return;

        const download = await fetch(`${import.meta.env.VITE_API_URL}/api/documents/export/${jobId}/download`, { mode: "cors" });
        if (!download.ok) throw new Error(`Failed to download export (${download.status})`);
        downloadBlob(await download.blob(), responseFilename(download, fallbackFilename));
    } catch (reason) {
        const message = reason instanceof Error ? reason.message : String(reason);
        if (failedAttempts < MAX_POLL_FAILURES) {
            updateEntry(localId, { status: "running", error: null, progress: "Reconnecting to export", logs: [message] });
            setTimeout(
                () => void pollExport(localId, jobId, fallbackFilename, failedAttempts + 1),
                POLL_INTERVAL_MS,
            );
            return;
        }
        updateEntry(localId, { status: "error", error: message, progress: "Export failed", logs: [message] });
    }
}

export const subscribe = (listener: () => void): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
};

export const getSnapshot = (): ScanManagerSnapshot => snapshot;

export const dismiss = (localId: string) => {
    const state = states.get(localId);
    if (!state || state.status === "running" || state.status === "queued") return;
    states.delete(localId);
    publish();
};

export async function queueExport(request: ExportRequest, projectName: string): Promise<void> {
    const localId = `export-${nextOperationId++}`;
    const scopeCount = request.mode === "per_variant" ? request.variant_ids.length : 1;
    states.set(localId, {
        variantId: localId,
        variantName: projectName,
        status: "running",
        error: null,
        progress: "Queued",
        logs: [],
        total: scopeCount * request.documents.length,
        doneCount: 0,
    });
    publish();

    try {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/documents/export", {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...request, async: true }),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok || typeof body.job_id !== "string") {
            throw new Error(body.error || `Export failed (${response.status})`);
        }
        const suffix = request.mode === "consolidated" ? "consolidated" : "by_variant";
        const fallbackFilename = `${projectName}_${suffix}_export.zip`;
        void pollExport(localId, body.job_id, fallbackFilename);
    } catch (reason) {
        const message = reason instanceof Error ? reason.message : String(reason);
        updateEntry(localId, { status: "error", error: message, progress: "Export failed", logs: [message] });
        throw reason;
    }
}