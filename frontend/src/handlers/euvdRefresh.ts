/**
 * ENISA EUVD CVE Refresh handler — typed fetch wrapper for the EUVD refresh endpoint.
 */

import { asVulnerability } from "./vulnerabilities";
import type { Vulnerability } from "./vulnerabilities";

class EuvdRefreshHandler {
    static async triggerSingleRefresh(cveId: string): Promise<Vulnerability | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(cveId)}/euvd-refresh`;
        const response = await fetch(url, { method: "POST", mode: "cors" });
        if (!response.ok) return null;
        const data = await response.json().catch(() => null);
        const vuln = data?.vulnerabilities?.[0];
        if (!vuln) return null;
        const parsed = asVulnerability(vuln);
        return Array.isArray(parsed) ? null : parsed;
    }
}

export default EuvdRefreshHandler;
