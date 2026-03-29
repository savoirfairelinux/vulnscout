type Scan = {
    id: string;
    description: string | null;
    timestamp: string;
    variant_id: string;
    variant_name: string | null;
    project_name: string | null;
    finding_count: number;
    package_count: number;
    is_first: boolean;
    findings_added: number | null;
    findings_removed: number | null;
    packages_added: number | null;
    packages_removed: number | null;
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

type ScanDiff = {
    scan_id: string;
    previous_scan_id: string | null;
    is_first: boolean;
    finding_count: number;
    package_count: number;
    findings_added: FindingDiffEntry[];
    findings_removed: FindingDiffEntry[];
    packages_added: PackageDiffEntry[];
    packages_removed: PackageDiffEntry[];
};

export type { Scan, FindingDiffEntry, PackageDiffEntry, ScanDiff };

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
}

export default ScansHandler;
