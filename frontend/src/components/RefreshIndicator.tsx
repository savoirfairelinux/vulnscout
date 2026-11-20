// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import type { ReactNode } from 'react';
import { Link, useInRouterContext } from 'react-router-dom';
import { fieldLabel, formatHistoryValue, sourceLabel } from '../handlers/vulnerabilityHistory';
import { formatRefreshDate, indicatorLabel, refreshRunPath } from '../handlers/refreshIndicators';
import type { ActiveIndicator, FieldIndicator, IndicatorKind, RefreshRunReference } from '../handlers/refreshIndicators';

const BADGE_STYLES: Record<IndicatorKind | 'superseded', string> = {
    new: 'border-emerald-500 bg-emerald-900/60 text-emerald-100',
    updated: 'border-amber-500 bg-amber-900/60 text-amber-100',
    removed: 'border-rose-500 bg-rose-900/60 text-rose-100',
    superseded: 'border-gray-500 bg-gray-800 text-gray-200',
};

const REFERENCE_FIELDS = new Set(['links', 'patch_url']);

const valueBox = 'max-h-48 overflow-auto whitespace-pre-wrap break-words [overflow-wrap:anywhere] rounded bg-gray-800 p-2 text-gray-200';

/** Textual badge; colour is never the only signal. */
export function IndicatorBadge({ kind, children }: Readonly<{ kind: IndicatorKind | 'superseded'; children?: ReactNode }>) {
    return <span className={`inline-flex items-center rounded border px-1.5 py-px text-xs font-semibold not-italic ${BADGE_STYLES[kind]}`}>
        {children ?? (kind === 'superseded' ? 'Superseded' : indicatorLabel(kind))}
    </span>;
}

/** Opens the Refresh tab on one run; the current project/variant scope is kept by the app. */
export function RefreshRunLink({ runId, children }: Readonly<{ runId: string; children: ReactNode }>) {
    const className = 'text-sky-300 underline hover:text-sky-100';
    return useInRouterContext()
        ? <Link className={className} to={refreshRunPath(runId)}>{children}</Link>
        : <a className={className} href={refreshRunPath(runId)}>{children}</a>;
}

export function RunStatusNote({ run, source }: Readonly<{ run: RefreshRunReference; source: string }>) {
    if (run.status === 'complete') return null;
    return <p className="text-amber-200">
        {run.status === 'running' ? 'Refresh run still in progress' : 'Partial refresh run (incomplete or cancelled)'}:
        {' '}this vulnerability&apos;s {sourceLabel(source)} check completed, but the run did not cover every source or target.
    </p>;
}

const entryText = (field: string, entry: unknown): string =>
    typeof entry === 'string' ? entry : formatHistoryValue(field, entry);

function EntryList({ field, label, kind, entries }: Readonly<{ field: string; label: string; kind: IndicatorKind; entries: unknown[] }>) {
    if (!entries.length) return null;
    return <div>
        <p className="font-semibold">{label}</p>
        <ul className="space-y-1">
            {entries.map(entry => <li key={entryText(field, entry)} className="flex items-start gap-2">
                <IndicatorBadge kind={kind} />
                <span className="min-w-0 break-words [overflow-wrap:anywhere]">{entryText(field, entry)}</span>
            </li>)}
        </ul>
    </div>;
}

/** Before/after values of one refreshed field, keeping removed values inspectable. */
export function IndicatorValues({ change }: Readonly<{ change: FieldIndicator }>) {
    const listed = change.added !== undefined || change.removed !== undefined;
    const values = <div className="grid min-w-0 gap-2 md:grid-cols-2">
        <div className="min-w-0">
            <p className="font-semibold">Previous value</p>
            <pre className={valueBox}>{change.before === null ? 'No previous value' : formatHistoryValue(change.field, change.before)}</pre>
        </div>
        <div className="min-w-0">
            <p className="font-semibold">Refreshed value</p>
            <pre className={valueBox}>{change.after === null ? 'No value (removed by the provider)' : formatHistoryValue(change.field, change.after)}</pre>
        </div>
    </div>;
    if (!listed) return values;
    return <div className="space-y-2">
        <EntryList field={change.field} label="Added entries" kind="new" entries={change.added ?? []} />
        <EntryList field={change.field} label="Removed entries" kind="removed" entries={change.removed ?? []} />
        <details>
            <summary className="cursor-pointer text-sky-300">Full before/after values</summary>
            <div className="mt-1">{values}</div>
        </details>
    </div>;
}

export function IndicatorNotes({ change, source }: Readonly<{ change: FieldIndicator; source: string }>) {
    return <>
        {change.kind === 'first_enrichment' && <p className="text-gray-300">
            First enrichment: no previous value was recorded. This is newly enriched data from {sourceLabel(source)},
            {' '}not a newly discovered vulnerability.
        </p>}
        {REFERENCE_FIELDS.has(change.field) && (change.added?.length ?? 0) > 0 && <p className="text-gray-300">
            A new reference or patch link does not mean the installed package is patched.
        </p>}
        {!change.current && <p className="text-gray-300">
            Superseded: this value was changed again after the refresh, so it no longer describes the current data.
        </p>}
    </>;
}

/** Expandable New/Updated badge on a field of the vulnerability details. */
export function FieldRefreshIndicator({ indicators }: Readonly<{ indicators: readonly ActiveIndicator[] }>) {
    if (!indicators.length) return null;
    return <>
        {indicators.map(indicator => <details key={`${indicator.source}-${indicator.field}`}
            className="ml-2 inline-block align-middle text-left" data-testid={`refresh-indicator-${indicator.field}`}>
            <summary className="inline-flex cursor-pointer list-none items-center gap-1">
                <IndicatorBadge kind={indicator.indicator} />
                <span className="sr-only">{` ${fieldLabel(indicator.field)} by ${sourceLabel(indicator.source)}: show refresh details`}</span>
            </summary>
            <div className="mt-1 block w-[min(32rem,80vw)] space-y-2 rounded-lg border border-gray-600 bg-gray-900 p-3 text-xs font-normal text-gray-300">
                <p>
                    {indicatorLabel(indicator.indicator)} by the {sourceLabel(indicator.source)} refresh of
                    {' '}<time dateTime={indicator.run.started_at}>{formatRefreshDate(indicator.run.started_at)}</time>
                    {' '}(changed <time dateTime={indicator.changed_at}>{formatRefreshDate(indicator.changed_at)}</time>).
                </p>
                <RunStatusNote run={indicator.run} source={indicator.source} />
                <IndicatorValues change={indicator} />
                <IndicatorNotes change={indicator} source={indicator.source} />
                <RefreshRunLink runId={indicator.run.run_id}>View this refresh in the Refresh tab</RefreshRunLink>
            </div>
        </details>)}
    </>;
}

/** Marks one collection entry (link, CPE) the latest refresh added. */
export function EntryRefreshIndicator({ indicator }: Readonly<{ indicator?: ActiveIndicator }>) {
    if (!indicator) return null;
    return <span className="mr-2 align-middle" title={`Added by the ${sourceLabel(indicator.source)} refresh of ${formatRefreshDate(indicator.run.started_at)}`}>
        <IndicatorBadge kind="new" />
    </span>;
}
