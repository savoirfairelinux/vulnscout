// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowsRotate, faLayerGroup } from '@fortawesome/free-solid-svg-icons';
import RefreshRuns from '../handlers/refreshRuns';
import type { RefreshChange, RefreshCoverage, RefreshFilters, RefreshRun, RefreshRunList } from '../handlers/refreshRuns';
import { describeChange, fieldLabel, formatHistoryValue, sourceLabel } from '../handlers/vulnerabilityHistory';
import { ROUTES } from '../routes';
import RefreshControls from '../components/RefreshControls';
import RefreshHistoryExport from '../components/RefreshHistoryExport';
import ModalShell, { ModalActions, ModalButton } from '../components/ModalShell';
import Vulnerabilities, { type Vulnerability } from '../handlers/vulnerabilities';

type Props = {
    projectId?: string; variantId?: string; dataRevision?: number; comparisonScope?: boolean;
    vulnerabilities?: Vulnerability[]; onRefreshComplete?: () => void;
    baseVariantId?: string; compareOperation?: string; variantIds?: string[]; multiOperation?: string;
};
const PAGE_SIZE = 25;
const RUN_PAGE_SIZE = 20;
const control = 'rounded-md border border-gray-300 dark:border-neutral-600 bg-white dark:bg-neutral-700 px-3 py-2 text-gray-800 dark:text-neutral-200 hover:bg-gray-100 dark:hover:bg-neutral-600 disabled:opacity-40';
const primaryAction = 'inline-flex min-h-10 min-w-36 items-center justify-center rounded-md bg-cyan-700 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-cyan-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500';
const sourceStyles: Record<string, { marker: string; badge: string }> = {
    nvd: { marker: 'bg-orange-400', badge: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300' },
    epss: { marker: 'bg-cyan-400', badge: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' },
    ghsa: { marker: 'bg-purple-400', badge: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300' },
    euvd: { marker: 'bg-sky-400', badge: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300' },
};

function RunStat({ count, label }: Readonly<{ count: number; label: string }>) {
    return <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold text-cyan-600 dark:text-cyan-400 tabular-nums">{count.toLocaleString()}</span>{' '}
        <span className="text-sm font-medium text-neutral-500 dark:text-neutral-300">{label}</span>
    </div>;
}

function formatDate(iso: string): string {
    return new Date(iso).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
    });
}

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

export default function RefreshOverview({ projectId, variantId, dataRevision = 0, comparisonScope = false,
    vulnerabilities = [], onRefreshComplete, baseVariantId, compareOperation, variantIds, multiOperation }: Readonly<Props>) {
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
    const [section, setSection] = useState<'overview' | 'coverage' | 'changes'>('changes');

    useEffect(() => { setListOffset(0); }, [projectId, variantId]);
    useEffect(() => { setSection('changes'); }, [runId, projectId, variantId]);

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
        if (!run || run.run_id !== runId || comparisonScope) return;
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
    }, [run, runId, projectId, variantId, source, changeType, offset, comparisonScope]);

    const summary = run ? counts(run.coverage) : null;
    const sourceNames = run ? [...new Set([...run.sources, ...Object.keys(run.source_status), ...run.coverage.map(row => row.source)])] : [];
    const incomplete = run?.status === 'incomplete';
    const cancelled = run?.coverage.some(row => row.status === 'cancelled');
    const failed = run?.coverage.some(row => row.status === 'failed');
    const closeResult = () => setParams(previous => {
        const next = new URLSearchParams(previous);
        next.delete('run');
        return next;
    });
    const tabClass = (tab: typeof section) =>
        `px-4 py-2 text-sm font-semibold border-b-2 transition-colors ${section === tab
            ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-gray-400 hover:text-gray-200'}`;

    const refreshControls = <RefreshControls vulnerabilities={vulnerabilities} projectId={projectId}
        variantId={comparisonScope ? undefined : variantId}
        getRefreshVulnerabilities={() => Vulnerabilities.list(variantId, projectId, baseVariantId, compareOperation, variantIds, multiOperation)}
        onRefreshComplete={onRefreshComplete} toolbar={<>
            <h1 className="text-lg font-bold">Refresh History</h1>
            {!comparisonScope && <button type="button" className="py-1 px-2 rounded flex items-center gap-1 text-sm font-semibold bg-sky-900 hover:bg-sky-950 transition-colors"
                onClick={() => setReload(value => value + 1)}>
                <FontAwesomeIcon icon={faArrowsRotate} />
                Reload results
            </button>}
            {!comparisonScope && <RefreshHistoryExport projectId={projectId} />}
        </>} />;

    if (comparisonScope) return <section className="w-full px-6 py-6 space-y-3 text-gray-800 dark:text-neutral-200" aria-label="Refresh changes">
        {refreshControls}
        <p role="alert">Refresh results require one project or one variant. Select all variants of a project or a single variant, rather than a variant comparison. No broader scope has been loaded.</p>
    </section>;

    return <section className="w-full px-6 py-6 space-y-5 text-gray-800 dark:text-neutral-200" aria-label="Refresh changes">
        {refreshControls}
        <div className="space-y-2">
            <h2 className="font-bold">Refresh runs</h2>
            {listError && <p role="alert">{listError}</p>}
            {!runList && !listError && <p role="status">Loading refresh runs…</p>}
            {runList && <ul className="relative" aria-label="Refresh runs">
                {runList.runs.map((item, index) => <li key={item.run_id} className="flex items-stretch">
                    <div aria-hidden="true" className="flex-shrink-0 relative w-9 min-h-20">
                        <div className="absolute left-1/2 border-l-2 border-cyan-700 dark:border-cyan-600"
                            style={{ top: index === 0 ? '50%' : 0, bottom: index === runList.runs.length - 1 ? '50%' : 0 }} />
                        <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 grid grid-cols-2 gap-px p-px rounded-sm ring-2 ring-gray-200 dark:ring-neutral-800 bg-neutral-300 dark:bg-neutral-900">
                            {item.sources.length ? item.sources.map(name => <span key={name}
                                className={`w-1.5 h-1.5 ${sourceStyles[name]?.marker ?? 'bg-neutral-400'}`} />)
                                : <span className="w-3 h-3 bg-neutral-400" />}
                        </span>
                    </div>
                    <div className="flex-1 min-w-0 py-2 pl-3">
                        <article aria-label={`Refresh run ${formatDate(item.started_at)} · ${item.sources.map(sourceLabel).join(', ')}`}
                            className={`relative p-4 bg-white dark:bg-neutral-700 rounded-lg shadow-sm border ${runId === item.run_id ? 'border-cyan-600 ring-1 ring-cyan-600' : 'border-gray-100 dark:border-neutral-600'}`}>
                            <div className="flex flex-wrap items-center gap-2 mb-1">
                                <time dateTime={item.started_at} className="text-sm font-semibold text-gray-500 dark:text-neutral-400">{formatDate(item.started_at)}</time>
                                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-300">
                                    <FontAwesomeIcon icon={faLayerGroup} className="mr-1" />
                                    Refresh run · {item.sources.length} providers
                                </span>
                                <span className={`rounded-full px-2 py-0.5 text-xs font-bold ${item.status === 'incomplete' ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300' : 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/40 dark:text-cyan-300'}`}>{item.status}</span>
                                {item.sources.map(name => <span key={name}
                                    className={`rounded-full px-2 py-0.5 text-xs font-semibold ${sourceStyles[name]?.badge ?? 'bg-gray-100 dark:bg-neutral-800'}`}>{sourceLabel(name)}</span>)}
                            </div>
                            <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
                                <div className="min-w-0">
                                    <h3 className="text-sm font-bold text-neutral-700 dark:text-neutral-100 mb-1.5">Refresh result</h3>
                                    <div className="flex items-baseline gap-x-10 gap-y-1.5 flex-wrap">
                                        <RunStat count={item.summary.changed_vulnerabilities} label="vulnerabilities changed" />
                                        <RunStat count={item.summary.total_changes} label="field changes" />
                                    </div>
                                </div>
                                <button type="button" aria-pressed={runId === item.run_id} className={primaryAction}
                                    onClick={() => setParams(previous => {
                                        const next = new URLSearchParams(previous);
                                        next.set('run', item.run_id);
                                        return next;
                                    })}>View Refresh Result</button>
                            </div>
                            <div className="mt-3 pt-3 border-t border-neutral-200 dark:border-neutral-600 text-sm">
                                {item.summary.first_enrichments > 0 && <p className="text-green-600 dark:text-green-400">
                                    <strong>{item.summary.first_enrichments.toLocaleString()}</strong> first enrichments · additions without a previous baseline
                                </p>}
                                {item.status === 'running'
                                    ? <p className="text-cyan-600 dark:text-cyan-400">Refresh in progress · only committed changes are counted.</p>
                                    : item.status === 'incomplete'
                                        ? <p className="text-amber-700 dark:text-amber-300">Incomplete coverage · inspect provider outcomes before concluding data is unchanged.</p>
                                        : <p className="text-neutral-500 dark:text-neutral-400">Refresh complete · view the result for coverage and before/after values.</p>}
                            </div>
                        </article>
                    </div>
                </li>)}
            </ul>}
            {runList && runList.total > RUN_PAGE_SIZE && <nav aria-label="Run pages" className="flex items-center gap-3">
                <button type="button" className={control} disabled={listOffset === 0} onClick={() => setListOffset(value => Math.max(0, value - RUN_PAGE_SIZE))}>Previous runs</button>
                <span>{listOffset + 1}–{Math.min(listOffset + RUN_PAGE_SIZE, runList.total)} of {runList.total} runs</span>
                <button type="button" className={control} disabled={listOffset + RUN_PAGE_SIZE >= runList.total} onClick={() => setListOffset(value => value + RUN_PAGE_SIZE)}>Next runs</button>
            </nav>}
        </div>
        {!runId && <>
            {loading && <p role="status">Loading refresh results…</p>}
            {error && <p role="alert">{error}</p>}
            {!loading && !error && !run && <p role="status">No refresh has been recorded in this scope. Run Refresh Vulnerability Data to begin.</p>}
        </>}
        {runId && <ModalShell isOpen title="Refresh Result" size="fullscreen" onClose={closeResult}
            subtitle={run?.run_id === runId ? `${formatDate(run.started_at)} · ${run.sources.map(sourceLabel).join(', ')} · ${run.status}` : undefined}
            testId="refresh-result-modal-backdrop"
            contentClassName="flex min-h-0 flex-1 flex-col p-0 md:p-0"
            headerActions={<ModalButton onClick={() => setReload(value => value + 1)}>Reload results</ModalButton>}
            footer={<ModalActions><ModalButton onClick={closeResult}>Close</ModalButton></ModalActions>}>
            {run?.run_id === runId && <nav aria-label="Refresh result sections" className="flex flex-wrap border-b border-gray-600 px-4">
                <button type="button" className={tabClass('changes')} aria-pressed={section === 'changes'} onClick={() => setSection('changes')}>
                    Changes <span className="ml-2 rounded-full bg-cyan-900/40 px-1.5 py-0.5 text-xs text-cyan-300">{run.summary.total_changes.toLocaleString()}</span>
                </button>
                <button type="button" className={tabClass('coverage')} aria-pressed={section === 'coverage'} onClick={() => setSection('coverage')}>
                    Coverage <span className="ml-2 rounded-full bg-cyan-900/40 px-1.5 py-0.5 text-xs text-cyan-300">{run.coverage.length.toLocaleString()}</span>
                </button>
                <button type="button" className={tabClass('overview')} aria-pressed={section === 'overview'} onClick={() => setSection('overview')}>Overview</button>
            </nav>}
            <div className="p-4 md:p-5 space-y-4 text-gray-300 flex-1 overflow-auto">
            {loading && <p role="status">Loading refresh results…</p>}
            {error && <p role="alert">{error}</p>}
            {!loading && !error && !run && <p role="status">Requested refresh run is unavailable in this scope. No other run has been substituted.</p>}
            {run?.run_id === runId && <>
            {run.status === 'running' && <p role="status">Refresh in progress. Only committed changes are shown. Reload results to see progress.</p>}
            {incomplete && <p role="alert">Incomplete refresh{cancelled ? ' — cancelled coverage' : ''}{failed ? ' — source failures' : ''}. Committed changes are shown below, but coverage gaps are not evidence of unchanged data or removals.</p>}
            {run.summary.first_enrichments > 0 && <p role="status">First enrichment: {run.summary.first_enrichments} values had no recorded previous value. No baseline exists for those fields. These are additions, not modifications.</p>}
            {section === 'overview' && <>
                <div className="overflow-auto rounded border border-gray-600">
                    <table aria-label="Refresh metadata" className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase"><tr><th className="px-3 py-2">Property</th><th className="px-3 py-2">Value</th></tr></thead>
                        <tbody>
                            <tr className="border-t border-gray-600"><th scope="row" className="px-3 py-2">Status</th><td className="px-3 py-2">{run.status}</td></tr>
                            <tr className="border-t border-gray-600"><th scope="row" className="px-3 py-2">Sources</th><td className="px-3 py-2">{run.sources.map(sourceLabel).join(', ') || 'None'}</td></tr>
                            <tr className="border-t border-gray-600"><th scope="row" className="px-3 py-2">Started</th><td className="px-3 py-2"><time dateTime={run.started_at}>{formatDate(run.started_at)}</time></td></tr>
                            <tr className="border-t border-gray-600"><th scope="row" className="px-3 py-2">Finished</th><td className="px-3 py-2">{run.finished_at ? <time dateTime={run.finished_at}>{formatDate(run.finished_at)}</time> : 'Not finished'}</td></tr>
                        </tbody>
                    </table>
                </div>
                <div className="overflow-auto rounded border border-gray-600">
                    <table aria-label="Distinct vulnerability counts" className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase"><tr><th className="px-3 py-2">Category</th><th className="px-3 py-2">Vulnerabilities</th></tr></thead>
                        <tbody>{Object.entries({ ...summary, Changed: run.summary.changed_vulnerabilities }).map(([label, count]) =>
                            <tr key={label} className="border-t border-gray-600 hover:bg-gray-600/40"><th scope="row" className="px-3 py-2">{label}</th><td className="px-3 py-2 tabular-nums">{count}</td></tr>)}</tbody>
                    </table>
                </div>
                <p className="text-sm">Each vulnerability is counted once per category. A vulnerability may appear in several categories if providers have different outcomes.</p>
            </>}
            {section === 'coverage' && <>
                <h3 className="font-bold text-base">Per-source coverage and gaps</h3>
                <div className="overflow-auto max-h-80 rounded border border-gray-600">
                    <table aria-label="Provider coverage" className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase"><tr>
                            {['Source', 'Status', 'Targeted', 'Checked', 'Skipped', 'Failed', 'Cancelled', 'Pending'].map(label => <th key={label} scope="col" className="px-3 py-2">{label}</th>)}
                        </tr></thead>
                        <tbody>{sourceNames.map(name => <tr key={name} className="border-t border-gray-600 hover:bg-gray-600/40">
                            <th scope="row" className="px-3 py-2">{sourceLabel(name)}</th>
                            <td className="px-3 py-2">{run.source_status[name] ?? 'pending'}
                                {run.source_status[name] === 'incomplete' && <p className="mt-1 text-amber-300">This source has incomplete coverage. Inspect target outcomes and operation logs. Missing or deferred responses are coverage gaps, not removals.</p>}
                            </td>
                            {Object.entries(counts(run.coverage.filter(row => row.source === name))).map(([label, count]) => <td key={label} className="px-3 py-2 tabular-nums">{count}</td>)}
                        </tr>)}</tbody>
                    </table>
                </div>
                {!run.coverage.length ? <p>No targeted vulnerabilities recorded.</p> : <div className="overflow-auto max-h-80 rounded border border-gray-600">
                    <table aria-label="Vulnerability coverage" className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase"><tr>
                            {['Vulnerability', 'Source', 'Outcome', 'Error'].map(label => <th key={label} scope="col" className="px-3 py-2">{label}</th>)}
                        </tr></thead>
                        <tbody>{run.coverage.map((row, index) => <tr key={`${row.source}-${row.vuln_id}-${index}`} className="border-t border-gray-600 hover:bg-gray-600/40">
                            <td className="px-3 py-2 font-mono">{row.vuln_id}</td>
                            <td className="px-3 py-2">{sourceLabel(row.source)}</td>
                            <td className="px-3 py-2">{row.status}</td>
                            <td className="px-3 py-2 break-words">{row.error ?? '—'}</td>
                        </tr>)}</tbody>
                    </table>
                </div>}
            </>}
            {section === 'changes' && <>
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
                        : 'No committed changes recorded yet. Coverage is incomplete. Unchanged data cannot be concluded.'}</p>}
                <p className="text-sm">{page.total} field changes match. A CVE may continue on the next page. Missing provider responses are never treated as removals.</p>
                {page.changes.length > 0 && <div className="overflow-auto max-h-[60vh] rounded border border-gray-600">
                    <table aria-label="Refresh changes" className="w-full min-w-[72rem] text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase"><tr>
                            {['Vulnerability', 'Field', 'Source', 'Change', 'Before', 'After', 'Changed', 'Packages'].map(label => <th key={label} scope="col" className="px-3 py-2">{label}</th>)}
                        </tr></thead>
                        <tbody>{page.changes.map((change, index) => <tr key={`${offset}-${change.vuln_id}-${change.source}-${change.field}-${index}`} className="border-t border-gray-600 hover:bg-gray-600/40">
                            <td className="px-3 py-2 align-top font-mono"><Link className="text-cyan-300 underline" aria-label={`Open ${change.vuln_id} vulnerability`}
                                to={ROUTES.vulnerabilities} state={{ vulnFilter: { label: 'Vulnerability', value: change.vuln_id, vulnerabilityIds: [change.vuln_id] } }}>{change.vuln_id}</Link></td>
                            <td className="px-3 py-2 align-top">{fieldLabel(change.field)}</td>
                            <td className="px-3 py-2 align-top">{sourceLabel(change.source)}</td>
                            <td className="px-3 py-2 align-top">{changeLabel(change)}
                                {describeChange(change.field, change.before, change.after) && <p className="mt-1 text-gray-400">{describeChange(change.field, change.before, change.after)}</p>}
                            </td>
                            {[change.before, change.after].map((value, valueIndex) => <td key={valueIndex} className="px-3 py-2 align-top">
                                <pre className="min-w-48 max-w-sm max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-gray-800 p-2 [overflow-wrap:anywhere]">{valueText(change.field, value)}</pre>
                            </td>)}
                            <td className="px-3 py-2 align-top"><time dateTime={change.changed_at}>{formatDate(change.changed_at)}</time></td>
                            <td className="px-3 py-2 align-top"><ul aria-label="Relevant packages" className="space-y-1">
                                {change.packages.map(pkg => <li key={`${pkg.package_id}-${pkg.variant_id}`}>
                                    <Link className="break-all text-cyan-300 underline" to={ROUTES.vulnerabilities}
                                        state={{ vulnFilter: { label: 'Package', value: pkg.package, vulnerabilityIds: [change.vuln_id] } }}>{pkg.name}@{pkg.version}</Link>
                                </li>)}
                            </ul></td>
                        </tr>)}</tbody>
                    </table>
                </div>}
                {page.total > 0 && <nav aria-label="Change pages" className="flex items-center gap-3">
                    <button type="button" className={control} disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - PAGE_SIZE))}>Previous changes</button>
                    <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, page.total)} of {page.total} changes</span>
                    <button type="button" className={control} disabled={offset + PAGE_SIZE >= page.total} onClick={() => setOffset(value => value + PAGE_SIZE)}>Next changes</button>
                </nav>}
            </>}
            </>}
            </>}
            </div>
        </ModalShell>}
    </section>;
}
