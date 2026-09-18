/**
 * One shape for every long-running backend operation.
 *
 * Scans, vulnerability refreshes, SBOM uploads, document exports and boot
 * enrichment all arrive on the same event stream in this form.
 */

export type OperationKind = "scan" | "refresh" | "upload" | "export" | "enrichment";

export type OperationStatus = "queued" | "running" | "done" | "error" | "cancelled";

export type OperationLane = "pipeline" | "export" | "upload";

export type ScanSource = "grype" | "nvd" | "osv" | "scc";

export type RefreshSource = "nvd" | "epss" | "ghsa" | "euvd";

export type OperationScope = {
    variant_id: string;
    variant_name: string;
    project_id: string;
};

export type OperationProgress = {
    current: number;
    total: number;
    message: string;
};

export type Operation = {
    op_id: string;
    kind: OperationKind;
    source: string;
    label: string;
    lane: OperationLane;
    scope: OperationScope | null;
    status: OperationStatus;
    progress: OperationProgress;
    logs: string[];
    error: string | null;
    queue_id: string | null;
    position: number | null;
    options: Record<string, unknown>;
    cancellable: boolean;
    created_at: string;
    started_at: string | null;
    finished_at: string | null;
    result: Record<string, unknown> | null;
};

/** Whether the operation still has work ahead of it. */
export const isActive = (operation: Operation): boolean =>
    operation.status === "queued" || operation.status === "running";

/** Whether the operation has settled and can be dismissed. */
export const isTerminal = (operation: Operation): boolean => !isActive(operation);

export const percentOf = (operation: Operation): number => {
    if (operation.status === "done") return 100;
    const { current, total } = operation.progress;
    if (total <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
};

/** A job as sent to `POST /api/operations`. */
export type OperationJob = {
    kind: "scan" | "refresh";
    source: ScanSource | RefreshSource;
    variant_ids?: string[];
    ids?: string[];
    exclude_ids?: string[];
    options?: {
        exclude_kernel?: boolean;
        mode?: "local" | "api";
    };
};
