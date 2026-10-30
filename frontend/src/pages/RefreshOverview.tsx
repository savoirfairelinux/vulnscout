// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import RefreshRuns from '../handlers/refreshRuns';
import type { RefreshChange, RefreshCoverage, RefreshFilters, RefreshRun, RefreshRunList } from '../handlers/refreshRuns';
import { describeChange, fieldLabel, formatHistoryValue, sourceLabel } from '../handlers/vulnerabilityHistory';
import { ROUTES } from '../routes';

type Props = { projectId?: string; variantId?: string; dataRevision?: number; comparisonScope?: boolean };
const PAGE_SIZE = 25;
const RUN_PAGE_SIZE = 20;
const control = 'rounded border border-gray-500 bg-gray-800 px-3 py-2 text-white disabled:opacity-40';

function counts(coverage: RefreshCoverage[]) {
    const distinct = (statuses?: RefreshCoverage['status'][]) =>
        new Set(coverage.filter(row => !statuses || statuses.includes(row.status)).map(row => row.vuln_id)).size;
    return {
        Targeted: distinct(), Checked: distinct(['complete']), Skipped: distinct(['skipped']),
        Failed: distinct(['failed']), Cancelled: distinct(['cancelled']), Pending: distinct(['pending']),
    };
}

function changeLabel(change: RefreshChange): string {
    if (change.kind === 'first_enrichment') return 'First enrichment (addition)';
    if (change.change_type === 'removal') return 'Confirmed removal';
    if (change.change_type === 'addition') return 'Addition';
    if (Array.isArray(change.before) && Array.isArray(change.after)) return 'Modified collection (confirmed additions/removals)';
    return 'Modification';
}

function valueText(field: string, value: unknown): string {
    if (value === null) return 'No value';
    if (typeof value === 'object' && !Array.isArray(value) && !field.startsWith('cvss:')) return JSON.stringify(value, null, 2);
    return formatHistoryValue(field, value);
}

export default function RefreshOverview({ projectId, variantId, dataRevision = 0, comparisonScope = false }: Readonly<Props>) {
    const [params, setParams] = useSearchParams();
    const runId = params.get('run') || undefined;
    const [reload, setReload] = useState(0);
    const [run, setRun] = useState<RefreshRun | null>(null);
    const [page, setPage] = useState<RefreshRun | null>(null);
    const [runList, setRunList] = useState<RefreshRunList | null>(null);
    const [listOffset, setListOffset] = useState(0);
    const [offset, setOffset] = useState(0);
    const [source, setSource] = useState('');
    const [changeType, setChangeType] = useState<'' | 'first_enrichment' | 'addition' | 'modification' | 'removal'>('');
    const [error, setError] = useState('');
    const [listError, setListError] = useState('');
    const [pageError, setPageError] = useState('');
    const [loading, setLoading] = useState(true);
    const [pageLoading, setPageLoading] = useState(false);

    useEffect(() => {
        if (comparisonScope) return;
        const controller = new AbortController();
        setRun(null);
        setPage(null);
        setError('');
        setLoading(true);
        setOffset(0);
        setSource('');
        setChangeType('');
        const scope = { project_id: projectId, variant_id: variantId };
        const request = runId ? RefreshRuns.detail(runId, scope, controller.signal) : RefreshRuns.latest(scope, controller.signal);
        request.then(result => {
            if (!controller.signal.aborted) setRun(result);
        }).catch(reason => {
            if (!controller.signal.aborted) setError(String(reason));
        }).finally(() => {
            if (!controller.signal.aborted) setLoading(false);
        });
        return () => controller.abort();
    }, [runId, projectId, variantId, reload, dataRevision, comparisonScope]);

    useEffect(() => {
        if (comparisonScope) return;
        const controller = new AbortController();
        setRunList(null);
        setListError('');
        RefreshRuns.list({ project_id: projectId, variant_id: variantId, limit: RUN_PAGE_SIZE, offset: listOffset }, controller.signal)
            .then(result => { if (!controller.signal.aborted) setRunList(result); })
            .catch(reason => { if (!controller.signal.aborted) setListError(String(reason)); });
        return () => controller.abort();
    }, [projectId, variantId, listOffset, reload, dataRevision, comparisonScope]);

    useEffect(() => {
        if (!run || comparisonScope) return;
        const controller = new AbortController();
        setPage(null);
        setPageError('');
        setPageLoading(true);
        const filters: RefreshFilters = {
            project_id: projectId, variant_id: variantId, source,
            kind: changeType === 'first_enrichment' ? 'first_enrichment' : undefined,
            change_type: changeType && changeType !== 'first_enrichment' ? changeType : undefined,
            offset, limit: PAGE_SIZE,
        };
        RefreshRuns.detail(run.run_id, filters, controller.signal)
            .then(result => {
                if (!controller.signal.aborted) {
                    if (!result) setPageError('This refresh run is no longer available. No other run has been substituted.');
                    setPage(result);
                }
            }).catch(reason => { if (!controller.signal.aborted) setPageError(String(reason)); })
            .finally(() => { if (!controller.signal.aborted) setPageLoading(false); });
        return () => controller.abort();
    }, [run, projectId, variantId, source, changeType, offset, comparisonScope]);

    const summary = run ? counts(run.coverage) : null;
    const sourceNames = run ? [...new Set([...run.sources, ...Object.keys(run.source_status), ...run.coverage.map(row => row.source)])] : [];
    const changedGroups = new Map<string, RefreshChange[]>();
    page?.changes.forEach(change => {
        changedGroups.set(change.vuln_id, [...(changedGroups.get(change.vuln_id) ?? []), change]);
    });
    const incomplete = run?.status === 'incomplete';
    const cancelled = run?.coverage.some(row => row.status === 'cancelled');
    const failed = run?.coverage.some(row => row.status === 'failed');

    if (comparisonScope) return <section className="space-y-3 text-gray-200" aria-label="Refresh changes">
        <h1 className="text-2xl font-bold">Refresh</h1>
        <p role="alert">Refresh results require one project or one variant. Select all variants of a project or a single variant, rather than a variant comparison. No broader scope has been loaded.</p>
    </section>;

    return <section className="space-y-5 text-gray-200" aria-label="Refresh changes">
        <header className="flex flex-wrap items-center justify-between gap-3">
            <div>
                <h1 className="text-2xl font-bold">Refresh</h1>
                <p>Persisted provider-data changes, separate from scan findings and individual field history.</p>
                <p className="text-sm">Viewing scope: {projectId ? `project ${projectId}` : 'all projects'} · {variantId ? `variant ${variantId}` : 'all variants'}</p>
            </div>
            <button type="button" className={control} onClick={() => setReload(value => value + 1)}>Reload results</button>
        </header>
        <div className="space-y-2">
            <h2 className="font-bold">Refresh runs</h2>
            {listError && <p role="alert">{listError}</p>}
            {runList && <ul className="flex flex-wrap gap-2">
                {runList.runs.map(item => <li key={item.run_id}>
                    <button type="button" aria-pressed={run?.run_id === item.run_id} className={control}
                        onClick={() => setParams({ run: item.run_id })}>
                        {item.started_at} · {item.status} · {item.run_id}
                    </button>
                </li>)}
            </ul>}
            {runList && runList.total > RUN_PAGE_SIZE && <nav aria-label="Run pages" className="flex items-center gap-3">
                <button type="button" className={control} disabled={listOffset === 0} onClick={() => setListOffset(value => Math.max(0, value - RUN_PAGE_SIZE))}>Previous runs</button>
                <span>{listOffset + 1}–{Math.min(listOffset + RUN_PAGE_SIZE, runList.total)} of {runList.total} runs</span>
                <button type="button" className={control} disabled={listOffset + RUN_PAGE_SIZE >= runList.total} onClick={() => setListOffset(value => value + RUN_PAGE_SIZE)}>Next runs</button>
            </nav>}
            {runId && <button type="button" className={control} onClick={() => setParams({})}>Show latest matching run</button>}
        </div>
        {loading && <p role="status">Loading refresh results…</p>}
        {error && <p role="alert">{error}</p>}
        {!loading && !error && !run && <p role="status">{runId
            ? 'Requested refresh run is unavailable in this scope. No other run has been substituted.'
            : 'No refresh has been recorded in this scope. No baseline is available; run Refresh Vulnerability Data to begin.'}</p>}
        {run && <>
            <dl className="grid gap-2 rounded bg-gray-800 p-4 sm:grid-cols-2">
                <div><dt className="font-bold">Run ID</dt><dd className="break-all">{run.run_id}</dd></div>
                <div><dt className="font-bold">Status</dt><dd>{run.status}</dd></div>
                <div><dt className="font-bold">Initiating scope</dt><dd className="break-all">Project: {run.scope.project_id ?? 'all'} · Variant: {run.scope.variant_id ?? 'all'}</dd></div>
                <div><dt className="font-bold">Sources</dt><dd>{run.sources.map(sourceLabel).join(', ') || 'None'}</dd></div>
                <div><dt className="font-bold">Started</dt><dd><time>{run.started_at}</time></dd></div>
                <div><dt className="font-bold">Finished</dt><dd>{run.finished_at ? <time>{run.finished_at}</time> : 'Not finished'}</dd></div>
            </dl>
            <div aria-label="Distinct vulnerability counts" className="flex flex-wrap gap-4">
                {Object.entries({ ...summary, Changed: run.summary.changed_vulnerabilities }).map(([label, count]) =>
                    <span key={label}><strong>{label}:</strong> {count}</span>)}
            </div>
            <p className="text-sm">Counts are distinct vulnerabilities in the viewing scope, not source/CVE pairs. Coverage categories may overlap when sources have different outcomes.</p>
            {run.status === 'running' && <p role="status">Refresh in progress. Only committed changes are shown; reload results to see progress.</p>}
            {incomplete && <p role="alert">Incomplete refresh{cancelled ? ' — cancelled coverage' : ''}{failed ? ' — source failures' : ''}. Committed changes are shown below, but coverage gaps are not evidence of unchanged data or removals.</p>}
            {run.summary.first_enrichments > 0 && <p role="status">First enrichment: {run.summary.first_enrichments} values had no recorded previous value. No baseline exists for those fields; these are additions, not modifications.</p>}
            <details className="rounded border border-gray-600 p-3">
                <summary className="cursor-pointer font-bold">Per-source coverage and gaps</summary>
                {sourceNames.map(name => <details key={name} className="my-3">
                    <summary className="cursor-pointer">{sourceLabel(name)} — {run.source_status[name] ?? 'pending'} · {Object.entries(counts(run.coverage.filter(row => row.source === name))).map(([label, value]) => `${label}: ${value}`).join(' · ')}</summary>
                    {run.source_status[name] === 'incomplete' && <p className="text-amber-300">This source did not complete successfully. Missing or deferred responses are coverage gaps, not removals.</p>}
                    <ul className="max-h-80 space-y-1 overflow-auto p-2">
                        {run.coverage.filter(row => row.source === name).map((row, index) =>
                            <li key={`${row.vuln_id}-${index}`} className="break-words">{row.vuln_id}: {row.status}{row.error ? ` — ${row.error}` : ''}</li>)}
                    </ul>
                </details>)}
                {!run.coverage.length && <p>No targeted vulnerabilities recorded.</p>}
            </details>
            <div className="flex flex-wrap gap-4">
                <label>Source <select className={control} value={source} onChange={event => { setSource(event.target.value); setOffset(0); }}>
                    <option value="">All sources</option>
                    {sourceNames.map(name => <option key={name} value={name}>{sourceLabel(name)}</option>)}
                </select></label>
                <label>Change type <select className={control} value={changeType} onChange={event => { setChangeType(event.target.value as typeof changeType); setOffset(0); }}>
                    <option value="">All changes</option>
                    <option value="first_enrichment">First enrichment</option>
                    <option value="addition">Additions</option>
                    <option value="modification">Modifications</option>
                    <option value="removal">Confirmed removals</option>
                </select></label>
            </div>
            {pageLoading && <p role="status">Loading changes…</p>}
            {pageError && <p role="alert">{pageError}</p>}
            {page && <>
                {page.total === 0 && <p role="status">{source || changeType
                    ? 'No changes match these filters.'
                    : run.status === 'complete' && run.coverage.length === 0
                        ? 'No vulnerabilities were targeted in this scope. No comparison baseline is available.'
                    : run.status === 'complete'
                        ? 'Refresh complete: zero changes. Checked data is unchanged.'
                        : 'No committed changes recorded yet. Coverage is incomplete; unchanged data cannot be concluded.'}</p>}
                <p className="text-sm">{page.total} field changes match. A CVE may continue on the next page. Missing provider responses are never treated as removals.</p>
                {[...changedGroups].map(([vulnId, changes]) => <details key={`${offset}-${vulnId}`} className="rounded border border-gray-600 p-3">
                    <summary className="cursor-pointer font-bold">{vulnId} — {changes.length} field changes on this page</summary>
                    <Link className="text-sky-300 underline" to={ROUTES.vulnerabilities} state={{ vulnFilter: { label: 'Vulnerability', value: vulnId, vulnerabilityIds: [vulnId] } }}>Open {vulnId} vulnerability</Link>
                    {changes.map((change, index) => <article key={`${change.source}-${change.field}-${index}`} className="my-4 space-y-2 border-t border-gray-600 pt-3">
                        <h3 className="font-semibold">{fieldLabel(change.field)} · {sourceLabel(change.source)} · {changeLabel(change)}</h3>
                        <time className="text-sm">{change.changed_at}</time>
                        {describeChange(change.field, change.before, change.after) && <p>{describeChange(change.field, change.before, change.after)}</p>}
                        <div className="grid min-w-0 gap-3 md:grid-cols-2">
                            {[['Before', change.before], ['After', change.after]].map(([label, value]) => <div key={String(label)} className="min-w-0">
                                <h4 className="font-bold">{String(label)}</h4>
                                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded bg-gray-800 p-3 text-sm [overflow-wrap:anywhere]">{valueText(change.field, value)}</pre>
                            </div>)}
                        </div>
                        <ul aria-label="Relevant packages" className="flex flex-wrap gap-3">
                            {change.packages.map(pkg => <li key={`${pkg.package_id}-${pkg.variant_id}`}>
                                <Link className="break-all text-sky-300 underline" to={ROUTES.vulnerabilities}
                                    state={{ vulnFilter: { label: 'Package', value: pkg.package, vulnerabilityIds: [vulnId] } }}>
                                    {pkg.name}@{pkg.version} · variant {pkg.variant_id}
                                </Link>
                            </li>)}
                        </ul>
                    </article>)}
                </details>)}
                {page.total > 0 && <nav aria-label="Change pages" className="flex items-center gap-3">
                    <button type="button" className={control} disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - PAGE_SIZE))}>Previous changes</button>
                    <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, page.total)} of {page.total} changes</span>
                    <button type="button" className={control} disabled={offset + PAGE_SIZE >= page.total} onClick={() => setOffset(value => value + PAGE_SIZE)}>Next changes</button>
                </nav>}
            </>}
        </>}
    </section>;
}
