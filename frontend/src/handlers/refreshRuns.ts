// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

export type RefreshScope = { project_id?: string; variant_id?: string };
export type RefreshCoverage = {
    source: string;
    vuln_id: string;
    status: 'pending' | 'complete' | 'failed' | 'skipped' | 'cancelled';
    error: string | null;
};
export type RefreshChange = {
    vuln_id: string;
    source: string;
    field: string;
    before: unknown;
    after: unknown;
    kind: 'changed' | 'first_enrichment';
    change_type: 'addition' | 'modification' | 'removal';
    changed_at: string;
    packages: { package_id: string; package: string; name: string; version: string; variant_id: string; project_id: string }[];
};
export type RefreshRunMetadata = {
    run_id: string;
    scope: { project_id: string | null; variant_id: string | null };
    sources: string[];
    source_status: Record<string, 'pending' | 'complete' | 'incomplete'>;
    started_at: string;
    finished_at: string | null;
    status: 'running' | 'complete' | 'incomplete';
    coverage: RefreshCoverage[];
    summary: { total_changes: number; changed_vulnerabilities: number; first_enrichments: number };
};
export type RefreshRun = RefreshRunMetadata & {
    changes: RefreshChange[];
    total: number;
    limit: number;
    offset: number;
};
export type RefreshRunList = {
    runs: RefreshRunMetadata[];
    total: number;
    limit: number;
    offset: number;
};
export type RefreshFilters = RefreshScope & {
    vuln_id?: string;
    source?: string;
    field?: string;
    kind?: 'changed' | 'first_enrichment';
    change_type?: 'addition' | 'modification' | 'removal';
    limit?: number;
    offset?: number;
};

async function get<T>(path: string, filters: RefreshFilters, signal?: AbortSignal): Promise<T | null> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== '') params.set(key, String(value));
    });
    const response = await fetch(`${import.meta.env.VITE_API_URL}/api/refresh-runs${path}?${params}`, { mode: 'cors', signal });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Unable to load refresh results (HTTP ${response.status}).`);
    return response.json();
}

const RefreshRuns = {
    latest: (filters: RefreshFilters, signal?: AbortSignal) => get<RefreshRun>('/latest', filters, signal),
    detail: (runId: string, filters: RefreshFilters, signal?: AbortSignal) =>
        get<RefreshRun>(`/${encodeURIComponent(runId)}`, filters, signal),
    list: (filters: RefreshFilters, signal?: AbortSignal) => get<RefreshRunList>('', filters, signal),
};

export default RefreshRuns;
