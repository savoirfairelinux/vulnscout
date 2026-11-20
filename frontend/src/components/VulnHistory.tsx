import { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faChevronDown } from "@fortawesome/free-solid-svg-icons";
import VulnerabilityHistory, {
    describeChange,
    fieldLabel,
    formatHistoryValue,
    groupHistory,
    sourceLabel,
} from "../handlers/vulnerabilityHistory";
import type { HistoryEntry } from "../handlers/vulnerabilityHistory";
import { activeIndicators, formatRefreshDate, indicatorLabel } from "../handlers/refreshIndicators";
import type { ActiveIndicator, SourceIndicators, VulnerabilityRefreshIndicators } from "../handlers/refreshIndicators";
import {
    IndicatorBadge, IndicatorNotes, IndicatorValues, RefreshRunLink, RunStatusNote,
} from "./RefreshIndicator";

type Props = {
    vulnId: string;
    /** Bump to reload an open history, e.g. after a refresh. */
    reloadKey?: number;
    /** Server-derived latest-refresh deltas; `undefined` while loading. */
    refreshIndicators?: VulnerabilityRefreshIndicators | null;
    refreshIndicatorsError?: string | null;
};

const dateOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
};

const changeCount = (rows: readonly HistoryEntry[]): string =>
    rows.length === 1 ? '1 change' : `${rows.length} changes`;

const formatDate = (iso: string): string => new Date(iso).toLocaleString(undefined, dateOptions);

const changeLabel = (field: string, row: HistoryEntry, isFirst: boolean): string | null => {
    if (row.old_value === null) return isFirst ? 'first added' : 'added';
    if (row.value === null) return 'cleared';
    return describeChange(field, row.old_value, row.value);
};

const sameInstant = (a: string, b: string): boolean => Date.parse(a) === Date.parse(b);

/** The live indicator a timeline row produced, if it is the latest refresh's change. */
const rowIndicator = (indicators: readonly ActiveIndicator[], field: string, row: HistoryEntry) =>
    indicators.find(indicator => indicator.field === field && indicator.source === row.source
        && sameInstant(indicator.changed_at, row.changed_at));

const indicatorSummary = (indicators: readonly ActiveIndicator[]): string | null => {
    if (!indicators.length) return null;
    const counts = (['new', 'updated', 'removed'] as const)
        .map(kind => [kind, indicators.filter(indicator => indicator.indicator === kind).length] as const)
        .filter(([, count]) => count > 0)
        .map(([kind, count]) => `${count} ${indicatorLabel(kind).toLowerCase()}`);
    return `Latest refresh: ${counts.join(' · ')}`;
};

function SourceRefreshSummary({ entry }: Readonly<{ entry: SourceIndicators }>) {
    const { run, later_attempt: later } = entry;
    return (
        <section aria-label={`${sourceLabel(entry.source)} latest refresh`} className="min-w-0 space-y-2 border-t border-gray-600 pt-2 first:border-t-0 first:pt-0">
            <h5 className="font-semibold text-gray-200">{sourceLabel(entry.source)}</h5>
            {run && <p className="text-xs text-gray-400">
                Last successful check: <time dateTime={run.started_at}>{formatRefreshDate(run.started_at)}</time>
                {' '}· run {run.status} · <RefreshRunLink runId={run.run_id}>View refresh run</RefreshRunLink>
            </p>}
            {run && <RunStatusNote run={run} source={entry.source} />}
            {entry.state === 'no_baseline' && <p>No completed {sourceLabel(entry.source)} refresh is recorded for this vulnerability in this scope: there is no baseline, so no New/Updated indicators.</p>}
            {entry.state === 'no_change' && <p>Checked: no data changed in the latest {sourceLabel(entry.source)} refresh.</p>}
            {later && <p className="text-amber-200">
                A later {sourceLabel(entry.source)} check did not complete: {later.status}
                {later.error ? ` (${later.error})` : ''}, run of <time dateTime={later.run.started_at}>{formatRefreshDate(later.run.started_at)}</time>.
                {run ? ' Indicators from the last successful check are kept.' : ''}
                {' '}<RefreshRunLink runId={later.run.run_id}>View that run</RefreshRunLink>
            </p>}
            {entry.changes.length > 0 && <ul className="space-y-3">
                {entry.changes.map(change => (
                    <li key={change.field} className="min-w-0 space-y-1" data-testid={`refresh-change-${change.field}`}>
                        <div className="flex flex-wrap items-center gap-2">
                            {change.current
                                ? <IndicatorBadge kind={change.indicator} />
                                : <IndicatorBadge kind="superseded" />}
                            <span className="font-semibold text-gray-200">{fieldLabel(change.field)}</span>
                            <span className="text-xs text-gray-400">changed <time dateTime={change.changed_at}>{formatRefreshDate(change.changed_at)}</time></span>
                        </div>
                        <IndicatorValues change={change} />
                        <IndicatorNotes change={change} source={entry.source} />
                    </li>
                ))}
            </ul>}
        </section>
    );
}

function VulnHistory({ vulnId, reloadKey = 0, refreshIndicators, refreshIndicatorsError = null }: Readonly<Props>) {
    const [expanded, setExpanded] = useState(false);
    const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
    const [error, setError] = useState<string | null>(null);

    // Fetched only once opened, so the modal's own mount requests stay unchanged.
    useEffect(() => {
        if (!expanded) return;
        let cancelled = false;
        setError(null);
        VulnerabilityHistory.list(vulnId)
            .then(rows => { if (!cancelled) setEntries(rows); })
            .catch(err => { if (!cancelled) setError(String(err)); });
        return () => { cancelled = true; };
    }, [expanded, vulnId, reloadKey]);

    const live = activeIndicators(refreshIndicators);
    const summary = indicatorSummary(live);

    const renderRefresh = () => {
        if (refreshIndicatorsError) return <p className="text-sm text-red-400">Failed to load refresh indicators: {refreshIndicatorsError}</p>;
        if (refreshIndicators === undefined) return <p className="text-sm text-gray-400">Loading latest refresh…</p>;
        const sources = refreshIndicators?.sources ?? [];
        return (
            <section aria-label="Latest refresh per source" className="space-y-3 rounded-lg bg-gray-800 p-3 text-sm">
                <h4 className="font-semibold text-gray-200">Latest refresh per source</h4>
                <p className="text-xs text-gray-400">
                    Indicators come from the latest refresh that successfully checked this vulnerability, per source, in this scope.
                    {' '}A changed value does not change any assessment.
                </p>
                {sources.length === 0
                    ? <p>No refresh of this vulnerability is recorded in this scope: there is no baseline, so no New/Updated indicators.</p>
                    : sources.map(entry => <SourceRefreshSummary key={entry.source} entry={entry} />)}
            </section>
        );
    };

    const renderBody = () => {
        if (error) return <p className="text-sm text-red-400">Failed to load history: {error}</p>;
        if (entries === null) return <p className="text-sm text-gray-400">Loading history…</p>;
        if (entries.length === 0) return <p className="text-sm text-gray-400">No changes recorded yet.</p>;
        return (
            <div className="space-y-4 rounded-lg bg-gray-800 p-3 text-sm">
                {groupHistory(entries).map(([field, rows]) => (
                    <section key={field} data-testid={`history-${field}`}>
                        <h4 className="font-semibold text-gray-200">
                            {fieldLabel(field)}
                            <span className="ml-2 font-normal text-gray-400">({changeCount(rows)})</span>
                        </h4>
                        <ol className="relative mt-1 ms-2 border-s border-gray-600">
                            {rows[0].old_value !== null && (
                                <li className="ms-4 pb-2">
                                    <div className="absolute -start-1 mt-1.5 h-2 w-2 rounded-full bg-gray-500" />
                                    <div className="text-xs text-gray-400">Before history tracking</div>
                                    <div className="max-h-40 overflow-y-auto whitespace-pre-line break-words text-gray-300">
                                        {formatHistoryValue(field, rows[0].old_value)}
                                    </div>
                                </li>
                            )}
                            {rows.map((row, index) => {
                                const change = changeLabel(field, row, index === 0);
                                const indicator = rowIndicator(live, field, row);
                                return (
                                    <li key={`${row.changed_at}-${index}`} className="ms-4 pb-2">
                                        <div className="absolute -start-1 mt-1.5 h-2 w-2 rounded-full bg-sky-500" />
                                        <div className="text-xs text-gray-400">
                                            <time dateTime={row.changed_at}>{formatDate(row.changed_at)}</time>
                                            <span> · {sourceLabel(row.source)}</span>
                                            {change && <span className="text-sky-300"> · {change}</span>}
                                            {indicator && <span className="ml-2"><IndicatorBadge kind={indicator.indicator} /></span>}
                                        </div>
                                        <div className="max-h-40 overflow-y-auto whitespace-pre-line break-words text-gray-200">
                                            {formatHistoryValue(field, row.value)}
                                        </div>
                                    </li>
                                );
                            })}
                        </ol>
                    </section>
                ))}
            </div>
        );
    };

    return (
        <div className="mb-6 mt-6">
            <div className="mb-2 flex items-center gap-2">
                <h3 className="font-bold">Data history</h3>
                {summary && <span className="text-xs text-gray-300" data-testid="refresh-indicator-summary">{summary}</span>}
                <button
                    aria-expanded={expanded}
                    aria-label={expanded ? "Collapse data history" : "Expand data history"}
                    title={expanded ? "Collapse data history" : "Expand data history"}
                    type="button"
                    className="text-sky-300 transition-colors hover:text-sky-100"
                    onClick={() => setExpanded(current => !current)}
                >
                    <FontAwesomeIcon className={expanded ? "rotate-180 transition-transform" : "transition-transform"} icon={faChevronDown} />
                </button>
            </div>
            {expanded && (
                <div className="space-y-4">
                    {renderRefresh()}
                    <div>
                        <h4 className="mb-2 font-semibold text-gray-200">All recorded changes</h4>
                        {renderBody()}
                    </div>
                </div>
            )}
        </div>
    );
}

export default VulnHistory;
