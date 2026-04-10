type Scan = {
    id: string;
    description: string | null;
    scan_type: string;
    timestamp: string;
    variant_id: string;
    variant_name: string | null;
    project_name: string | null;
    finding_count: number;
    package_count: number;
    vuln_count: number;
    is_first: boolean;
    findings_added: number | null;
    findings_removed: number | null;
    findings_upgraded: number | null;
    packages_added: number | null;
    packages_removed: number | null;
    packages_upgraded: number | null;
    vulns_added: number | null;
    vulns_removed: number | null;
};

type FindingDiffEntry = {
    finding_id: string;
    package_name: string;
    package_version: string;
    package_id: string;
    vulnerability_id: string;
};

type PackageDiffEntry = {
    package_id: string;
    package_name: string;
    package_version: string;
};

type PackageUpgradeEntry = {
    package_name: string;
    old_version: string;
    new_version: string;
    old_package_id: string;
    new_package_id: string;
};

type FindingUpgradeEntry = {
    vulnerability_id: string;
    package_name: string;
    old_version: string;
    new_version: string;
};

type ScanDiff = {
    scan_id: string;
    scan_type: string;
    previous_scan_id: string | null;
    is_first: boolean;
    finding_count: number;
    package_count: number;
    vuln_count: number;
    findings_added: FindingDiffEntry[];
    findings_removed: FindingDiffEntry[];
    findings_upgraded: FindingUpgradeEntry[];
    packages_added: PackageDiffEntry[];
    packages_removed: PackageDiffEntry[];
    packages_upgraded: PackageUpgradeEntry[];
    vulns_added: string[];
    vulns_removed: string[];
};

export type { Scan, FindingDiffEntry, FindingUpgradeEntry, PackageDiffEntry, PackageUpgradeEntry, ScanDiff };

class ScansHandler {
    static async list(variantId?: string, projectId?: string): Promise<Scan[]> {
        let url: string;
        if (variantId) {
            url = import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/scans`;
        } else if (projectId) {
            url = import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/scans`;
        } else {
            url = import.meta.env.VITE_API_URL + `/api/scans`;
        }
        const response = await fetch(url, { mode: 'cors' });
        if (!response.ok) return [];
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data.filter(
            (s: any) =>
                typeof s?.id === 'string' &&
                typeof s?.timestamp === 'string' &&
                typeof s?.variant_id === 'string' &&
                typeof s?.finding_count === 'number'
        ) as Scan[];
    }

    static async getDiff(scanId: string): Promise<ScanDiff | null> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/scans/${encodeURIComponent(scanId)}/diff`,
            { mode: 'cors' }
        );
        if (!response.ok) return null;
        const data = await response.json();
        if (typeof data?.scan_id !== 'string') return null;
        return data as ScanDiff;
    }

    static async setDescription(scanId: string, description: string): Promise<boolean> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/scans/${encodeURIComponent(scanId)}`,
            {
                method: 'PATCH',
                mode: 'cors',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description }),
            }
        );
        return response.ok;
    }

    static async triggerGrypeScan(variantId: string): Promise<{ ok: boolean; error?: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/grype-scan`,
            { method: 'POST', mode: 'cors' }
        );
        if (response.ok || response.status === 202) return { ok: true };
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getGrypeScanStatus(variantId: string): Promise<{ status: string; error?: string | null }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/grype-scan/status`,
            { mode: 'cors' }
        );
        if (!response.ok) return { status: 'unknown' };
        return await response.json();
    }
}

export default ScansHandler;
