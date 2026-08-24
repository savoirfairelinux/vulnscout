/**
 * Document export.
 *
 * Progress is reported on the shared event stream; this module only starts the
 * export and downloads the archive once the operation reports `done`.
 */

import { getOperation, subscribe } from "./operationStore";
import { isActive } from "../types/operation";
import type { Operation } from "../types/operation";

export type ExportRequest = {
    project_id: string;
    variant_ids: string[];
    mode: "consolidated" | "per_variant";
    documents: Array<{ name: string; extension: string }>;
};

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

/** Resolves once the operation has left the queued/running states. */
function waitForOperation(opId: string): Promise<Operation> {
    return new Promise(resolve => {
        let unsubscribe = () => { };
        const check = () => {
            const operation = getOperation(opId);
            if (!operation || isActive(operation)) return;
            unsubscribe();
            resolve(operation);
        };
        unsubscribe = subscribe(check);
        check();
    });
}

async function downloadWhenReady(opId: string, fallbackFilename: string): Promise<void> {
    const operation = await waitForOperation(opId);
    if (operation.status !== "done") return;
    const download = await fetch(
        `${import.meta.env.VITE_API_URL}/api/documents/export/${encodeURIComponent(opId)}/download`,
        { mode: "cors" },
    );
    if (!download.ok) throw new Error(`Failed to download export (${download.status})`);
    downloadBlob(await download.blob(), responseFilename(download, fallbackFilename));
}

export async function queueExport(request: ExportRequest, projectName: string): Promise<void> {
    const response = await fetch(import.meta.env.VITE_API_URL + "/api/documents/export", {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...request, async: true }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.op_id !== "string") {
        throw new Error(body.error || `Export failed (${response.status})`);
    }
    const suffix = request.mode === "consolidated" ? "consolidated" : "by_variant";
    const fallbackFilename = `${projectName}_${suffix}_export.zip`;
    void downloadWhenReady(body.op_id, fallbackFilename).catch(reason => {
        console.error("Export download failed:", reason);
    });
}
