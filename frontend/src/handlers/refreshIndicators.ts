// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

/**
 * New / Updated indicators of a vulnerability, derived by the server from the
 * persisted field-level deltas of the latest refresh that checked it, per source.
 * Nothing here is inferred from fetch timestamps or browser state, and reading
 * indicators never acknowledges or clears them.
 */

import { ROUTES } from '../routes';
import type { CVSS } from './vulnerabilities';

export type IndicatorKind = 'new' | 'updated' | 'removed';

export type RefreshRunReference = {
    run_id: string;
    refresh_type: string;
    status: 'running' | 'complete' | 'incomplete';
    source_status: Record<string, string>;
    started_at: string;
    finished_at: string | null;
};

export type FieldIndicator = {
    field: string;
    before: unknown;
    after: unknown;
    changed_at: string;
    kind: 'first_enrichment' | 'changed';
    indicator: IndicatorKind;
    /** False once another write replaced the refreshed value. */
    current: boolean;
    cvss: { version: string; author: string; metric_id: string } | null;
    /** Collection entries the refresh added or removed, for list-valued fields. */
    added?: unknown[];
    removed?: unknown[];
};

export type SourceIndicators = {
    source: string;
    /** `no_baseline`: no successful check of this source is recorded in this scope. */
    state: 'changed' | 'no_change' | 'no_baseline';
    run: RefreshRunReference | null;
    changes: FieldIndicator[];
    /** Newest check that did not complete; it never replaces the indicators above. */
    later_attempt: { status: string; error: string | null; run: RefreshRunReference } | null;
};

export type VulnerabilityRefreshIndicators = {
    vuln_id: string;
    sources: SourceIndicators[];
};

/** An indicator shown on live data, with the refresh it came from. */
export type ActiveIndicator = FieldIndicator & { source: string; run: RefreshRunReference };

const isObject = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value);

const asRun = (value: unknown): RefreshRunReference | null =>
    isObject(value) && typeof value.run_id === 'string' && typeof value.started_at === 'string'
        ? {
            run_id: value.run_id,
            refresh_type: typeof value.refresh_type === 'string' ? value.refresh_type : 'unknown',
            status: value.status === 'complete' || value.status === 'running' ? value.status : 'incomplete',
            source_status: isObject(value.source_status) ? value.source_status as Record<string, string> : {},
            started_at: value.started_at,
            finished_at: typeof value.finished_at === 'string' ? value.finished_at : null,
        }
        : null;

const asChange = (value: unknown): FieldIndicator[] => {
    if (!isObject(value) || typeof value.field !== 'string' || typeof value.changed_at !== 'string') return [];
    if (value.indicator !== 'new' && value.indicator !== 'updated' && value.indicator !== 'removed') return [];
    const cvss = isObject(value.cvss) && typeof value.cvss.version === 'string' && typeof value.cvss.author === 'string'
        ? { version: value.cvss.version, author: value.cvss.author, metric_id: String(value.cvss.metric_id ?? '') }
        : null;
    return [{
        field: value.field,
        before: value.before ?? null,
        after: value.after ?? null,
        changed_at: value.changed_at,
        kind: value.kind === 'first_enrichment' ? 'first_enrichment' : 'changed',
        indicator: value.indicator,
        current: value.current === true,
        cvss,
        ...(Array.isArray(value.added) ? { added: value.added } : {}),
        ...(Array.isArray(value.removed) ? { removed: value.removed } : {}),
    }];
};

const asSource = (value: unknown): SourceIndicators[] => {
    if (!isObject(value) || typeof value.source !== 'string') return [];
    if (value.state !== 'changed' && value.state !== 'no_change' && value.state !== 'no_baseline') return [];
    const attempt = isObject(value.later_attempt) ? value.later_attempt : null;
    const attemptRun = attempt ? asRun(attempt.run) : null;
    return [{
        source: value.source,
        state: value.state,
        run: asRun(value.run),
        changes: Array.isArray(value.changes) ? value.changes.flatMap(asChange) : [],
        later_attempt: attempt && attemptRun ? {
            status: typeof attempt.status === 'string' ? attempt.status : 'failed',
            error: typeof attempt.error === 'string' ? attempt.error : null,
            run: attemptRun,
        } : null,
    }];
};

export const asRefreshIndicators = (data: unknown): VulnerabilityRefreshIndicators | null =>
    isObject(data) && typeof data.vuln_id === 'string' && Array.isArray(data.sources)
        ? { vuln_id: data.vuln_id, sources: data.sources.flatMap(asSource) }
        : null;

/** Indicators that still describe live data, newest first. */
export const activeIndicators = (data: VulnerabilityRefreshIndicators | null | undefined): ActiveIndicator[] =>
    (data?.sources ?? [])
        .flatMap(source => source.run ? source.changes
            .filter(change => change.current)
            .map(change => ({ ...change, source: source.source, run: source.run as RefreshRunReference })) : [])
        .sort((a, b) => Date.parse(b.changed_at) - Date.parse(a.changed_at));

export const indicatorsFor = (indicators: readonly ActiveIndicator[], ...fields: string[]): ActiveIndicator[] =>
    indicators.filter(indicator => fields.includes(indicator.field) && indicator.indicator !== 'removed');

const sameScore = (indicator: ActiveIndicator, cvss: CVSS): boolean => {
    const after = indicator.after as { score?: unknown; vector?: unknown } | null;
    return after?.score === cvss.base_score && (after?.vector ?? null) === (cvss.vector_string || null);
};

/** The indicator of a provider CVSS score, matched by version and author (and value when ambiguous). */
export const cvssIndicators = (indicators: readonly ActiveIndicator[], cvss: CVSS): ActiveIndicator[] => {
    if (cvss.variant_id) return [];
    const matching = indicators.filter(indicator => indicator.cvss && indicator.indicator !== 'removed'
        && indicator.cvss.version === cvss.version && indicator.cvss.author === (cvss.author || 'unknown'));
    return matching.length > 1 ? matching.filter(indicator => sameScore(indicator, cvss)) : matching;
};

/** Entries of a collection field that the latest refresh added and that are still present. */
export const addedEntries = (indicators: readonly ActiveIndicator[], field: string): Map<string, ActiveIndicator> => {
    const entries = new Map<string, ActiveIndicator>();
    indicators.filter(indicator => indicator.field === field).forEach(indicator => {
        (indicator.added ?? []).forEach(entry => {
            if (!entries.has(String(entry))) entries.set(String(entry), indicator);
        });
    });
    return entries;
};

export const indicatorLabel = (kind: IndicatorKind): string =>
    kind === 'new' ? 'New' : kind === 'updated' ? 'Updated' : 'Removed';

const dateOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: 'numeric',
};

export const formatRefreshDate = (iso: string): string => new Date(iso).toLocaleString(undefined, dateOptions);

export const refreshRunPath = (runId: string): string => `${ROUTES.refresh}?run=${encodeURIComponent(runId)}`;

const RefreshIndicators = {
    async forVulnerability(
        vulnId: string,
        scope: { projectId?: string; variantId?: string },
        signal?: AbortSignal,
    ): Promise<VulnerabilityRefreshIndicators | null> {
        const params = new URLSearchParams();
        if (scope.projectId) params.set('project_id', scope.projectId);
        if (scope.variantId) params.set('variant_id', scope.variantId);
        const query = params.toString() ? `?${params}` : '';
        const response = await fetch(
            `${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(vulnId)}/refresh-indicators${query}`,
            { mode: 'cors', signal },
        );
        if (response.status === 404) return null;
        if (!response.ok) throw new Error(`Unable to load refresh indicators (HTTP ${response.status}).`);
        return asRefreshIndicators(await response.json());
    },
};

export default RefreshIndicators;
