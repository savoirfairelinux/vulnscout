import { fieldLabel, formatHistoryValue, sourceLabel } from "../handlers/vulnerabilityHistory";
import type { RefreshRun } from "../handlers/vulnerabilityRefreshRun";

type Props = { run: RefreshRun | null; vulnId: string };

const date = (value: string) => new Date(value).toLocaleString();
const valueText = (field: string, value: unknown): string =>
    field === 'epss_score' && typeof value === 'number'
        ? `${formatHistoryValue(field, value)} (raw probability: ${value})`
        : formatHistoryValue(field, value);

function VulnRefreshChanges({ run, vulnId }: Readonly<Props>) {
    if (!run) return (
        <p className="text-sm text-gray-400">
            No recorded refresh run for this vulnerability in this scope. No refresh baseline is available.
        </p>
    );
    const coverage = run.coverage.filter(entry => entry.vuln_id === vulnId);
    const changes = run.changes.filter(change => change.vuln_id === vulnId);
    const checked = coverage.some(entry => entry.status === 'complete');
    const complete = run.status === 'complete' && coverage.length > 0
        && coverage.every(entry => entry.status === 'complete');
    return (
        <section aria-label="Latest vulnerability refresh" className="space-y-3 rounded-lg bg-gray-800 p-3 text-left text-sm">
            <h4 className="font-semibold text-gray-200">Latest refresh for {vulnId}</h4>
            <dl className="space-y-1">
                <div><dt className="inline font-semibold">Run: </dt><dd className="inline break-all font-mono">{run.run_id}</dd></div>
                <div><dt className="inline font-semibold">Started: </dt><dd className="inline"><time dateTime={run.started_at}>{date(run.started_at)}</time></dd></div>
                <div><dt className="inline font-semibold">Finished: </dt><dd className="inline">{run.finished_at ? <time dateTime={run.finished_at}>{date(run.finished_at)}</time> : 'Not finished'}</dd></div>
                <div><dt className="inline font-semibold">Sources: </dt><dd className="inline">{run.sources.map(sourceLabel).join(', ')}</dd></div>
                <div><dt className="inline font-semibold">Requested scope: </dt><dd className="inline break-all">{run.scope.project_id ? `Project ${run.scope.project_id}` : 'All projects'}{run.scope.variant_id ? ` · Variant ${run.scope.variant_id}` : ' · All variants'}</dd></div>
                <div><dt className="inline font-semibold">Run status: </dt><dd className="inline">{run.status}</dd></div>
            </dl>
            <p className="text-xs text-gray-400">Changes below are limited to the selected vulnerability and current scope. Provider metadata may be shared across projects; a data change is not an applicability assessment.</p>
            {!complete && <p role="status" className="text-amber-300">{run.status === 'running' ? 'Refresh is still running.' : 'Refresh coverage is incomplete.'} Missing, failed, skipped or cancelled checks do not prove that data is unchanged.</p>}
            <ul aria-label="Source coverage" className="space-y-1">
                {Object.entries(run.source_status ?? {}).filter(([source]) =>
                    !coverage.some(entry => entry.source === source)
                ).map(([source, status]) => (
                    <li key={source}>{sourceLabel(source)}: {status} — no vulnerability-level comparison recorded</li>
                ))}
                {coverage.map(entry => (
                    <li key={`${entry.source}-${entry.vuln_id}`} className="break-words">
                        {sourceLabel(entry.source)}: {entry.status}
                        {entry.error && <span className="whitespace-pre-wrap"> — {entry.error}</span>}
                    </li>
                ))}
            </ul>
            {changes.length === 0 && (
                <p>{complete ? 'No data changed in this refresh.' : checked ? 'No changes were recorded by the completed checks; other checks are incomplete.' : 'No successful baseline comparison is available for this refresh.'}</p>
            )}
            {changes.map((change, index) => (
                <section key={`${change.source}-${change.field}-${change.changed_at}-${index}`} className="min-w-0 border-t border-gray-600 pt-3">
                    <h5 className="font-semibold break-words">{fieldLabel(change.field)}</h5>
                    <p className="text-xs text-gray-400">{sourceLabel(change.source)} · <time dateTime={change.changed_at}>{date(change.changed_at)}</time> · {change.kind === 'first_enrichment' ? 'First enrichment — no previous value' : 'Changed'}</p>
                    <code className="block break-all text-xs text-gray-400">{change.field}</code>
                    <div className="mt-2 grid min-w-0 gap-2 md:grid-cols-2">
                        {(['before', 'after'] as const).map(side => (
                            <div key={side} className="min-w-0">
                                <h6 className="font-semibold">{side === 'before' ? 'Before' : 'After'}</h6>
                                <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words rounded bg-gray-900 p-2 text-xs">
                                    {side === 'before' && change.kind === 'first_enrichment' ? 'No previous value (first enrichment)' : valueText(change.field, change[side])}
                                </pre>
                            </div>
                        ))}
                    </div>
                    {change.packages.length > 0 && <p className="mt-1 break-words text-xs text-gray-400">Captured packages: {change.packages.map(pkg => `${pkg.name}@${pkg.version}`).join(', ')}</p>}
                </section>
            ))}
        </section>
    );
}

export default VulnRefreshChanges;
