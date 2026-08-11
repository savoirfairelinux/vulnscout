type Scan = {
    id: string;
    description: string | null;
    scan_type: string;
    scan_source: string | null;
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
    vulns_unchanged: number | null;
    findings_unchanged: number | null;
    packages_unchanged: number | null;
    assessment_count: number | null;
    assessments_added: number | null;
    assessments_removed: number | null;
    assessments_unchanged: number | null;
    newly_detected_findings: number | null;
    newly_detected_vulns: number | null;
    newly_detected_assessments: number | null;
    branch_finding_count: number | null;
    branch_vuln_count: number | null;
    branch_package_count: number | null;
    global_finding_count: number | null;
    global_vuln_count: number | null;
    global_package_count: number | null;
    global_assessment_count: number | null;
    formats: string[];
};

type FindingDiffEntry = {
    finding_id: string;
    package_name: string;
    package_version: string;
    package_supplier?: string;
    package_id: string;
    vulnerability_id: string;
    origin?: string;
};

type PackageDiffEntry = {
    package_id: string;
    package_name: string;
    package_version: string;
    package_supplier?: string;
};

type PackageUpgradeEntry = {
    package_name: string;
    old_version: string;
    new_version: string;
    old_package_id: string;
    new_package_id: string;
    package_supplier?: string;
};

type FindingUpgradeEntry = {
    vulnerability_id: string;
    package_name: string;
    old_version: string;
    new_version: string;
    package_supplier?: string;
    origin?: string;
};

type AssessmentDiffEntry = {
    vulnerability_id: string;
    status: string;
    simplified_status: string;
    justification: string;
    impact_statement: string;
    status_notes: string;
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
    findings_unchanged: FindingDiffEntry[];
    packages_added: PackageDiffEntry[];
    packages_removed: PackageDiffEntry[];
    packages_upgraded: PackageUpgradeEntry[];
    packages_unchanged: PackageDiffEntry[];
    vulns_added: string[];
    vulns_removed: string[];
    vulns_unchanged: string[];
    assessment_count: number;
    assessments_added: AssessmentDiffEntry[];
    assessments_removed: AssessmentDiffEntry[];
    assessments_unchanged: AssessmentDiffEntry[];
    newly_detected_findings: number | null;
    newly_detected_vulns: number | null;
    newly_detected_findings_list: FindingDiffEntry[] | null;
    newly_detected_vulns_list: string[] | null;
    newly_detected_assessments_list: AssessmentDiffEntry[] | null;
    all_findings: FindingDiffEntry[] | null;
    all_vulns: string[] | null;
};

type GlobalResultFinding = {
    finding_id: string;
    package_name: string;
    package_version: string;
    package_supplier?: string;
    package_id: string;
    vulnerability_id: string;
    sources: string[];
};

type GlobalResultPackage = {
    package_id: string;
    package_name: string;
    package_version: string;
    package_supplier?: string;
    sources: string[];
};

type GlobalResultVuln = {
    vulnerability_id: string;
    sources: string[];
};

type GlobalResultAssessment = AssessmentDiffEntry;

type GlobalResult = {
    scan_id: string;
    scan_type: string;
    packages: GlobalResultPackage[];
    findings: GlobalResultFinding[];
    vulnerabilities: GlobalResultVuln[];
    assessments: GlobalResultAssessment[];
    package_count: number;
    finding_count: number;
    vuln_count: number;
    assessment_count: number;
};

export type { Scan, FindingDiffEntry, FindingUpgradeEntry, PackageDiffEntry, PackageUpgradeEntry, AssessmentDiffEntry, ScanDiff, GlobalResult, GlobalResultFinding, GlobalResultPackage, GlobalResultVuln, GlobalResultAssessment };

type ScanStatusResponse = { status: string; error?: string | null; progress?: string | null; logs?: string[]; total?: number; done_count?: number };
type RunningScanEntry = ScanStatusResponse & { variant_id: string };
type RunningScans = {
    grype: RunningScanEntry[];
    nvd: RunningScanEntry[];
    osv: RunningScanEntry[];
    "sbom-cve-check": RunningScanEntry[];
};

export type { ScanStatusResponse, RunningScanEntry, RunningScans };

type OutdatedDataPreview = {
    candidate_ids: {
        observations: string[];
        assessments: string[];
        package_pairs: Array<{ package_id: string; variant_id: string }>;
    };
    packages: Array<{
        project: string;
        variant: string;
        package: string;
        vulnerabilities: string[];
        linked_data: { observations: number; sbom_packages: number; sbom_observations: number };
    }>;
    assessments: Array<{ project: string; vulnerability: string; package: string; variant: string }>;
};

type EmptyScanPreview = {
    id: string;
    description: string;
    timestamp: string;
    project: string;
    variant: string;
};

type OrphanedVulnerabilityPreview = {
    id: string;
    assessments: number;
};

export type { OutdatedDataPreview, EmptyScanPreview, OrphanedVulnerabilityPreview };

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

    static async triggerGrypeScan(variantId: string, excludeKernel: boolean = true): Promise<{ ok: boolean; error?: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/grype-scan?exclude_kernel=${excludeKernel}`,
            { method: 'POST', mode: 'cors' }
        );
        if (response.ok || response.status === 202) return { ok: true };
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getGlobalResult(scanId: string): Promise<GlobalResult | null> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/scans/${encodeURIComponent(scanId)}/global-result`,
            { mode: 'cors' }
        );
        if (!response.ok) return null;
        const data = await response.json();
        if (typeof data?.scan_id !== 'string') return null;
        return data as GlobalResult;
    }

    static async getGrypeScanStatus(variantId: string): Promise<{ status: string; error?: string | null; progress?: string | null; logs?: string[]; total?: number; done_count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/grype-scan/status`,
            { mode: 'cors' }
        );
        if (!response.ok) return { status: 'unknown' };
        return await response.json();
    }

    static async triggerNvdScan(variantId: string, excludeKernel: boolean = true): Promise<{ ok: boolean; error?: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/nvd-scan?exclude_kernel=${excludeKernel}`,
            { method: 'POST', mode: 'cors' }
        );
        if (response.ok || response.status === 202) return { ok: true };
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getNvdScanStatus(variantId: string): Promise<{ status: string; error?: string | null; progress?: string | null; logs?: string[]; total?: number; done_count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/nvd-scan/status`,
            { mode: 'cors' }
        );
        if (!response.ok) return { status: 'unknown' };
        return await response.json();
    }

    static async triggerOsvScan(variantId: string, excludeKernel: boolean = true): Promise<{ ok: boolean; error?: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/osv-scan?exclude_kernel=${excludeKernel}`,
            { method: 'POST', mode: 'cors' }
        );
        if (response.ok || response.status === 202) return { ok: true };
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getOsvScanStatus(variantId: string): Promise<{ status: string; error?: string | null; progress?: string | null; logs?: string[]; total?: number; done_count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/osv-scan/status`,
            { mode: 'cors' }
        );
        if (!response.ok) return { status: 'unknown' };
        return await response.json();
    }

    static async triggerSbomCveCheckScan(variantId: string, excludeKernel: boolean = true): Promise<{ ok: boolean; error?: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/sbom-cve-check-scan?exclude_kernel=${excludeKernel}`,
            { method: 'POST', mode: 'cors' }
        );
        if (response.ok || response.status === 202) return { ok: true };
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getSbomCveCheckScanStatus(variantId: string): Promise<{ status: string; error?: string | null; progress?: string | null; logs?: string[]; total?: number; done_count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/sbom-cve-check-scan/status`,
            { mode: 'cors' }
        );
        if (!response.ok) return { status: 'unknown' };
        return await response.json();
    }

    static async getRunningScans(): Promise<RunningScans> {
        const empty: RunningScans = { grype: [], nvd: [], osv: [], 'sbom-cve-check': [] };
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/scans/running`,
            { mode: 'cors' }
        );
        if (!response.ok) return empty;
        const data = await response.json().catch(() => null);
        if (data === null || typeof data !== 'object') return empty;
        return {
            grype: Array.isArray(data.grype) ? data.grype : [],
            nvd: Array.isArray(data.nvd) ? data.nvd : [],
            osv: Array.isArray(data.osv) ? data.osv : [],
            'sbom-cve-check': Array.isArray(data['sbom-cve-check']) ? data['sbom-cve-check'] : [],
        };
    }

    static async deleteScan(scanId: string): Promise<{ ok: boolean; error?: string; orphaned_findings_removed?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/scans/${encodeURIComponent(scanId)}`,
            { method: 'DELETE', mode: 'cors' }
        );
        if (response.ok) {
            const data = await response.json().catch(() => ({}));
            return { ok: true, orphaned_findings_removed: data?.orphaned_findings_removed };
        }
        const data = await response.json().catch(() => ({}));
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async deleteOutdatedData(candidateIds: OutdatedDataPreview["candidate_ids"]): Promise<{ ok: boolean; error?: string; summary?: Record<string, number> }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + '/api/outdated-data',
            { method: 'DELETE', mode: 'cors', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ candidate_ids: candidateIds }) }
        );
        const data = await response.json().catch(() => ({}));
        if (response.ok) return { ok: true, summary: data };
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getOutdatedDataPreview(): Promise<{ ok: boolean; error?: string; preview?: OutdatedDataPreview }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + '/api/outdated-data',
            { mode: 'cors' }
        );
        const data = await response.json().catch(() => ({}));
        if (response.ok && Array.isArray(data?.packages) && Array.isArray(data?.assessments)) {
            return { ok: true, preview: data as OutdatedDataPreview };
        }
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getEmptyScansPreview(): Promise<{ ok: boolean; error?: string; scans?: EmptyScanPreview[] }> {
        const response = await fetch(import.meta.env.VITE_API_URL + '/api/empty-scans', { mode: 'cors' });
        const data = await response.json().catch(() => ({}));
        if (response.ok && Array.isArray(data?.scans)) return { ok: true, scans: data.scans };
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async deleteEmptyScans(scanIds: string[]): Promise<{ ok: boolean; error?: string; count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + '/api/empty-scans',
            { method: 'DELETE', mode: 'cors', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan_ids: scanIds }) }
        );
        const data = await response.json().catch(() => ({}));
        if (response.ok) return { ok: true, count: data?.scans_deleted ?? 0 };
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async getOrphanedVulnerabilitiesPreview(): Promise<{ ok: boolean; error?: string; vulnerabilities?: OrphanedVulnerabilityPreview[] }> {
        const response = await fetch(import.meta.env.VITE_API_URL + '/api/orphaned-vulnerabilities', { mode: 'cors' });
        const data = await response.json().catch(() => ({}));
        if (response.ok && Array.isArray(data?.vulnerabilities)) {
            return {
                ok: true,
                vulnerabilities: data.vulnerabilities,
            };
        }
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }

    static async deleteOrphanedVulnerabilities(vulnerabilityIds: string[]): Promise<{ ok: boolean; error?: string; count?: number }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + '/api/orphaned-vulnerabilities',
            { method: 'DELETE', mode: 'cors', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ vulnerability_ids: vulnerabilityIds }) }
        );
        const data = await response.json().catch(() => ({}));
        if (response.ok) return { ok: true, count: data?.vulnerabilities_deleted ?? 0 };
        return { ok: false, error: data?.error ?? `HTTP ${response.status}` };
    }
}

export default ScansHandler;
