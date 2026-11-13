// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { asVulnerability, type Vulnerability } from './vulnerabilities';
import type { NvdRefreshResult } from './nvdRefresh';

type ProviderResult = {
    status: number;
    body: { vulnerabilities?: unknown[]; error_code?: string; api_key_configured?: boolean } | null;
};

function vulnerability(result?: ProviderResult): Vulnerability | null {
    const raw = result?.status === 200 && result.body?.vulnerabilities?.[0];
    if (!raw) return null;
    const parsed = asVulnerability(raw);
    return Array.isArray(parsed) ? null : parsed;
}

export async function refreshIndividual(id: string, projectId?: string, variantId?: string) {
    const params = new URLSearchParams();
    if (projectId) params.set('project_id', projectId);
    if (variantId) params.set('variant_id', variantId);
    const response = await fetch(`${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(id)}/refresh?${params}`, {
        method: 'POST', mode: 'cors', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'api' }),
    });
    if (!response.ok) throw new Error(`Individual refresh failed (HTTP ${response.status}).`);
    const data: { results: Record<string, ProviderResult> } = await response.json();
    const nvdVuln = vulnerability(data.results.nvd);
    const nvdBody = data.results.nvd?.body;
    const code = nvdBody?.error_code === 'rate_limited' || nvdBody?.error_code === 'unauthorized'
        ? nvdBody.error_code : 'unavailable';
    const nvd: NvdRefreshResult = nvdVuln
        ? { kind: 'success', vuln: nvdVuln }
        : { kind: 'error', code, apiKeyConfigured: nvdBody?.api_key_configured ?? true };
    return { nvd, epss: vulnerability(data.results.epss), euvd: vulnerability(data.results.euvd),
        ghsa: vulnerability(data.results.ghsa) };
}
