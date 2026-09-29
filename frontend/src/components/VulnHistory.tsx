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

type Props = {
    vulnId: string;
    /** Bump to reload an open history, e.g. after a refresh. */
    reloadKey?: number;
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

function VulnHistory({ vulnId, reloadKey = 0 }: Readonly<Props>) {
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
                                return (
                                    <li key={`${row.changed_at}-${index}`} className="ms-4 pb-2">
                                        <div className="absolute -start-1 mt-1.5 h-2 w-2 rounded-full bg-sky-500" />
                                        <div className="text-xs text-gray-400">
                                            <time dateTime={row.changed_at}>{formatDate(row.changed_at)}</time>
                                            <span> · {sourceLabel(row.source)}</span>
                                            {change && <span className="text-sky-300"> · {change}</span>}
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
            {expanded && renderBody()}
        </div>
    );
}

export default VulnHistory;
