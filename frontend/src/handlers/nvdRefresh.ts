/**
 * NVD CVE Refresh handler — typed fetch wrappers for refresh endpoints.
 */

import { asVulnerability } from "./vulnerabilities";
import type { Vulnerability } from "./vulnerabilities";

export type NvdRefreshSuccess = { kind: "success"; vuln: Vulnerability };
export type NvdRefreshError = {
    kind: "error";
    code: "rate_limited" | "unauthorized" | "unavailable";
    apiKeyConfigured: boolean;
};
export type NvdRefreshResult = NvdRefreshSuccess | NvdRefreshError;

class NvdRefreshHandler {
    static async triggerSingleRefresh(
        cveId: string,
        mode: "local" | "api" = "local",
    ): Promise<NvdRefreshResult> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(cveId)}/nvd-refresh`;
        const response = await fetch(url, {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode }),
        });
        if (!response.ok) {
            const body = await response.json().catch(() => null);
            const code = body?.error_code === "rate_limited"
                ? "rate_limited"
                : body?.error_code === "unauthorized"
                    ? "unauthorized"
                    : "unavailable";
            const apiKeyConfigured = typeof body?.api_key_configured === "boolean"
                ? body.api_key_configured
                : true;
            return { kind: "error", code, apiKeyConfigured };
        }
        const data = await response.json().catch(() => null);
        const vuln = data?.vulnerabilities?.[0];
        if (!vuln) return { kind: "error", code: "unavailable", apiKeyConfigured: true };
        const parsed = asVulnerability(vuln);
        if (Array.isArray(parsed)) return { kind: "error", code: "unavailable", apiKeyConfigured: true };
        return { kind: "success", vuln: parsed };
    }
}

export default NvdRefreshHandler;
