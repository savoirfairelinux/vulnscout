import { useEffect, useState } from 'react';
import ModalShell from './ModalShell';
import type { HealthScope, PackageHealth } from '../handlers/packageHealth';
import {
    REPOSITORY_SOURCE_LABELS, TONE_CLASSES, listPackageHealth, maintenanceActivity, repositoryUrl, scoreTone,
    scorecardViewerUrl,
} from '../handlers/packageHealth';

type Props = HealthScope & {
    packageId: string;
    dataRevision?: number;
    onClose: () => void;
};

const chip = 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold';
const external = { target: '_blank', rel: 'noopener noreferrer', className: 'text-cyan-300 hover:underline' };

function checkScore(score: number | null) {
    if (score === null || score < 0) return <span className="text-neutral-400" title="Inconclusive">?</span>;
    return <span className={`${chip} ${TONE_CLASSES[scoreTone(score)]}`}>{score}</span>;
}

function PackageHealthDetails({ health }: Readonly<{ health: PackageHealth }>) {
    const { repository, scorecard } = health;
    const activity = maintenanceActivity(scorecard);
    return <div className="space-y-4 text-sm">
        <p className="text-neutral-300">
            OpenSSF Scorecard rates the upstream project's security and maintenance practices. It describes the
            maintainers, not whether this package is affected by a vulnerability.
        </p>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2">
            <dt className="text-neutral-400">Repository</dt>
            <dd>{repository
                ? <a href={repositoryUrl(repository)} {...external}>{repository}</a>
                : <span className="text-neutral-400">No upstream repository found</span>}</dd>
            <dt className="text-neutral-400">Found from</dt>
            <dd>{REPOSITORY_SOURCE_LABELS[health.repositorySource]}
                {health.repositoryEvidence && <span className="block break-all font-mono text-xs text-neutral-400">
                    {health.repositoryEvidence}</span>}
            </dd>
            {health.deprecated !== null && <>
                <dt className="text-neutral-400">Registry status</dt>
                <dd>{health.deprecated
                    ? <><span className={`${chip} ${TONE_CLASSES.poor}`}>Deprecated</span>
                        {health.deprecatedReason && <span className="ml-2">{health.deprecatedReason}</span>}</>
                    : 'Not deprecated'}</dd>
            </>}
            {scorecard?.status === 'scored' && <>
                <dt className="text-neutral-400">Scorecard</dt>
                <dd className="flex flex-wrap items-center gap-2">
                    {scorecard.score !== null && <span className={`${chip} ${TONE_CLASSES[scoreTone(scorecard.score)]}`}>
                        {scorecard.score.toFixed(1)} / 10</span>}
                    {activity && <span className={`${chip} ${TONE_CLASSES[activity.tone]}`}>{activity.label}</span>}
                    {scorecard.date && <span className="text-neutral-400">published {scorecard.date.slice(0, 10)}</span>}
                    {repository && <a href={scorecardViewerUrl(scorecard.repository ?? repository)} {...external}>
                        View on scorecard.dev</a>}
                </dd>
            </>}
            {scorecard && scorecard.status !== 'scored' && <>
                <dt className="text-neutral-400">Scorecard</dt>
                <dd className="text-neutral-300">{{
                    unsupported: 'Not covered: OpenSSF Scorecard only publishes GitHub and GitLab repositories.',
                    not_found: 'Not scored: this repository is not in the OpenSSF Scorecard public dataset.',
                    error: 'Unavailable: the last lookup failed. Refresh maintenance data to retry.',
                }[scorecard.status]}</dd>
            </>}
        </dl>
        {scorecard?.checks && scorecard.checks.length > 0 && <table className="w-full border-collapse text-left">
            <thead>
                <tr className="border-b border-neutral-700 text-neutral-400">
                    <th className="py-1 pr-3 font-medium">Check</th>
                    <th className="py-1 pr-3 font-medium">Score</th>
                    <th className="py-1 font-medium">Reason</th>
                </tr>
            </thead>
            <tbody>
                {scorecard.checks.map(check => <tr key={check.name} className="border-b border-neutral-800 align-top">
                    <td className="py-1 pr-3" title={check.description ?? undefined}>
                        {check.url ? <a href={check.url} {...external}>{check.name}</a> : check.name}
                    </td>
                    <td className="py-1 pr-3">{checkScore(check.score)}</td>
                    <td className="py-1 text-neutral-300">{check.reason ?? ''}</td>
                </tr>)}
            </tbody>
        </table>}
    </div>;
}

function PackageHealthModal({ packageId, variantId, projectId, variantIds, compareVariantId, dataRevision,
    onClose }: Readonly<Props>) {
    const [health, setHealth] = useState<PackageHealth | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        listPackageHealth({ variantId, projectId, variantIds: variantIdsKey?.split(','), compareVariantId }, packageId)
            .then(result => { if (!cancelled) setHealth(result.packages[packageId] ?? null); })
            .catch(() => { if (!cancelled) setError('Unable to load maintenance data'); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [packageId, variantId, projectId, variantIdsKey, compareVariantId, dataRevision, retry]);
    return <ModalShell isOpen title={`Maintenance: ${packageId}`} onClose={onClose} size="large">
        {loading ? <p role="status">Loading maintenance data...</p>
            : error ? <div role="alert">{error} <button type="button" onClick={() => setRetry(value => value + 1)}>Retry</button></div>
                : health ? <PackageHealthDetails health={health} />
                    : <p>No maintenance data yet. Refresh maintenance data to look up this package.</p>}
    </ModalShell>;
}

export default PackageHealthModal;
