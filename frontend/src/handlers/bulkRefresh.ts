/**
 * Bulk NVD, EPSS, GHSA and EUVD refresh handlers.
 *
 * These fire-and-forget endpoints return 202 immediately; actual progress
 * is tracked via /api/nvd/progress, /api/epss/progress, /api/ghsa/progress
 * and /api/euvd/progress respectively.
 */

export interface BulkRefreshResponse {
    status: string;
    total: number;
}

export class BulkNvdRefreshHandler {
    static async trigger(cveIds: string[], mode: "local" | "api" = "local"): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-nvd-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds, mode }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkEpssRefreshHandler {
    static async trigger(cveIds: string[]): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-epss-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export interface CancelRefreshResponse {
    status: string;
}

export class BulkNvdRefreshCancelHandler {
    static async trigger(): Promise<CancelRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/cancel-nvd-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkEpssRefreshCancelHandler {
    static async trigger(): Promise<CancelRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/cancel-epss-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkGhsaRefreshHandler {
    static async trigger(ghsaIds: string[]): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-ghsa-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ghsa_ids: ghsaIds }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkGhsaRefreshCancelHandler {
    static async trigger(): Promise<CancelRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/cancel-ghsa-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkEuvdRefreshHandler {
    static async trigger(cveIds: string[]): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-euvd-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkEuvdRefreshCancelHandler {
    static async trigger(): Promise<CancelRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/cancel-euvd-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}
