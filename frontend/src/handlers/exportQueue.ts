import { getOperation, subscribe } from "./operationStore";

export type ExportRequest = {
    project_id: string;
    variant_ids: string[];
    mode: "consolidated" | "per_variant";
    documents: Array<{ name: string; extension: string }>;
};

export async function downloadExport(opId: string, fallbackFilename = "export.zip"): Promise<void> {
    const response = await fetch(`${import.meta.env.VITE_API_URL}/api/documents/export/${encodeURIComponent(opId)}/download`, { mode: "cors" });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error ?? `Failed to download export (${response.status})`);
    }
    const filename = response.headers.get("Content-Disposition")?.match(/filename="?([^";]+)/)?.[1] ?? fallbackFilename;
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
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
        throw new Error(body.error ?? `Export failed (${response.status})`);
    }

    const fallbackFilename = `${projectName}_${request.mode === "consolidated" ? "consolidated" : "by_variant"}_export.zip`;
    const opId: string = body.op_id;
    let unsubscribe: (() => void) | undefined;
    let finished = false;
    const onChange = () => {
        if (finished) return;
        const operation = getOperation(opId);
        if (operation?.status === "done" || operation?.status === "error" || operation?.status === "cancelled") {
            finished = true;
            unsubscribe?.();
            unsubscribe = undefined;
            if (operation.status === "done") {
                void downloadExport(opId, fallbackFilename).catch(error => console.error("Export download failed:", error));
            }
        }
    };
    unsubscribe = subscribe(onChange);
    onChange();
}