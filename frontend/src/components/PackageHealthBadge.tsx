import type { PackageHealth, PackageScorecard } from '../handlers/packageHealth';
import { TONE_CLASSES, maintenanceActivity, scoreTone } from '../handlers/packageHealth';

const chip = 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold';

function scorecardStatus(scorecard: PackageScorecard | null, enabled: boolean): { label: string; title: string } {
    switch (scorecard?.status) {
        case 'unsupported':
            return { label: 'Not covered', title: 'OpenSSF Scorecard only publishes results for GitHub and GitLab repositories' };
        case 'not_found':
            return { label: 'Not scored', title: 'This repository is not part of the OpenSSF Scorecard public dataset' };
        case 'error':
            return { label: 'Unavailable', title: 'The last OpenSSF Scorecard lookup failed; refresh to retry' };
        case 'scored':
            return { label: 'No score', title: 'OpenSSF Scorecard published no aggregate score for this repository' };
        default:
            return enabled
                ? { label: 'Not fetched', title: 'Refresh maintenance data to fetch the OpenSSF Scorecard result' }
                : { label: 'Disabled', title: 'OpenSSF Scorecard lookups are disabled on this server' };
    }
}

type Props = {
    health: PackageHealth | undefined;
    enabled: boolean;
};

/** Compact Scorecard score, activity and deprecation chips for one package. */
function PackageHealthBadge({ health, enabled }: Readonly<Props>) {
    if (!health) {
        const status = scorecardStatus(null, enabled);
        return <span className="text-neutral-400" title={status.title}>{status.label}</span>;
    }
    const scorecard = health.repository ? health.scorecard : null;
    const activity = maintenanceActivity(scorecard);
    const status = scorecardStatus(scorecard, enabled);
    return <span className="flex flex-col items-center gap-1">
        {!health.repository
            ? <span className="text-neutral-400"
                title="No upstream repository found in the SBOM, deps.dev or CVE fix data">No repository</span>
            : scorecard?.status === 'scored' && scorecard.score !== null
            ? <span className={`${chip} ${TONE_CLASSES[scoreTone(scorecard.score)]}`}
                title={`OpenSSF Scorecard ${scorecard.score.toFixed(1)}/10 for ${health.repository}`}>
                {scorecard.score.toFixed(1)}
            </span>
            : <span className="text-xs text-neutral-400" title={status.title}>{status.label}</span>}
        {(activity || health.deprecated) && <span className="flex flex-wrap justify-center gap-1">
            {activity && <span className={`${chip} ${TONE_CLASSES[activity.tone]}`}
                title={scorecard?.maintained?.reason ?? undefined}>{activity.label}</span>}
            {health.deprecated && <span className={`${chip} ${TONE_CLASSES.poor}`}
                title={health.deprecatedReason ?? 'Marked deprecated by its package registry'}>Deprecated</span>}
        </span>}
    </span>;
}

export default PackageHealthBadge;
