/**
 * NVD CVE Refresh handler — typed fetch wrappers for refresh endpoints.
 */

import { asVulnerability } from "./vulnerabilities";
import type { Vulnerability } from "./vulnerabilities";

export type RefreshStatus = {
    status: string;
    progress?: number;
    total?: number;
    error?: string;
};

class NvdRefreshHandler {
    static async triggerBulkRefresh(
        variantId: string,
        cveIds?: string[],
    ): Promise<void> {
        const url = `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/nvd-refresh`;
        const body = cveIds ? JSON.stringify({ cve_ids: cveIds }) : undefined;
        const response = await fetch(url, {
            method: "POST",
            headers: body ? { "Content-Type": "application/json" } : {},
            body,
            mode: "cors",
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: "Unknown error" }));
            throw new Error(errorData.message || `HTTP ${response.status}`);
        }
    }

    static async getBulkRefreshStatus(variantId: string): Promise<RefreshStatus> {
        const url = `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/nvd-refresh/status`;
        const response = await fetch(url, { mode: "cors" });
        if (!response.ok) return { status: "error", error: `HTTP ${response.status}` };
        return response.json();
    }

    static async triggerSingleRefresh(cveId: string): Promise<Vulnerability | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(cveId)}/nvd-refresh`;
        const response = await fetch(url, { method: "POST", mode: "cors" });
        if (!response.ok) return null;
        const data = await response.json().catch(() => null);
        const vuln = data?.vulnerabilities?.[0];
        if (!vuln) return null;
        const parsed = asVulnerability(vuln);
        return Array.isArray(parsed) ? null : parsed;
    }
}

export default NvdRefreshHandler;
