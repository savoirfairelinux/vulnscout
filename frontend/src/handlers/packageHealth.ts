/**
 * Cached upstream repository and OpenSSF Scorecard data for packages.
 *
 * Scores are a maintenance signal about the upstream project, never an
 * assessment verdict for a vulnerability.
 */

export type ScorecardCheck = {
    name: string;
    score: number | null;
    reason: string | null;
    description: string | null;
    url: string | null;
};

export type ScorecardStatus = 'scored' | 'not_found' | 'unsupported' | 'error';

export type PackageScorecard = {
    status: ScorecardStatus;
    /** Name under which Scorecard published the result, in the repository's canonical case. */
    repository?: string | null;
    score: number | null;
    date: string | null;
    fetchedAt: string | null;
    maintained: { score: number | null; reason: string | null } | null;
    checks?: ScorecardCheck[];
};

export type RepositorySource = 'sbom' | 'deps_dev' | 'osv' | 'none';

export type PackageHealth = {
    repository: string | null;
    repositorySource: RepositorySource;
    repositoryEvidence: string | null;
    deprecated: boolean | null;
    deprecatedReason: string | null;
    resolvedAt: string | null;
    scorecard: PackageScorecard | null;
};

export type PackageHealthMap = {
    enabled: boolean;
    packages: Record<string, PackageHealth>;
};

export type HealthTone = 'good' | 'fair' | 'poor';

export const TONE_CLASSES: Record<HealthTone, string> = {
    good: 'bg-green-900 text-green-200',
    fair: 'bg-amber-900 text-amber-200',
    poor: 'bg-red-900 text-red-200',
};

const SCORECARD_STATUSES: readonly ScorecardStatus[] = ['scored', 'not_found', 'unsupported', 'error'];
const REPOSITORY_SOURCES: readonly RepositorySource[] = ['sbom', 'deps_dev', 'osv', 'none'];
const REPOSITORY_PATTERN = /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/[A-Za-z0-9_][A-Za-z0-9_.-]*)+$/;

const text = (value: unknown): string | null => typeof value === 'string' && value !== '' ? value : null;
const number = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) ? value : null;

function asCheck(value: unknown): ScorecardCheck[] {
    if (typeof value !== 'object' || value === null) return [];
    const check = value as Record<string, unknown>;
    if (typeof check.name !== 'string') return [];
    const url = text(check.url);
    return [{
        name: check.name,
        score: number(check.score),
        reason: text(check.reason),
        description: text(check.description),
        url: url?.startsWith('https://') ? url : null,
    }];
}

function asScorecard(value: unknown): PackageScorecard | null {
    if (typeof value !== 'object' || value === null) return null;
    const data = value as Record<string, unknown>;
    if (!SCORECARD_STATUSES.includes(data.status as ScorecardStatus)) return null;
    const maintained = typeof data.maintained === 'object' && data.maintained !== null
        ? data.maintained as Record<string, unknown> : null;
    const repository = text(data.repository);
    return {
        status: data.status as ScorecardStatus,
        repository: repository && REPOSITORY_PATTERN.test(repository) ? repository : null,
        score: number(data.score),
        date: text(data.date),
        fetchedAt: text(data.fetched_at),
        maintained: maintained ? { score: number(maintained.score), reason: text(maintained.reason) } : null,
        ...(Array.isArray(data.checks) ? { checks: data.checks.flatMap(asCheck) } : {}),
    };
}

export function asPackageHealth(value: unknown): PackageHealth | null {
    if (typeof value !== 'object' || value === null) return null;
    const data = value as Record<string, unknown>;
    const repository = text(data.repository);
    return {
        repository: repository && REPOSITORY_PATTERN.test(repository) ? repository : null,
        repositorySource: REPOSITORY_SOURCES.includes(data.repository_source as RepositorySource)
            ? data.repository_source as RepositorySource : 'none',
        repositoryEvidence: text(data.repository_evidence),
        deprecated: typeof data.deprecated === 'boolean' ? data.deprecated : null,
        deprecatedReason: text(data.deprecated_reason),
        resolvedAt: text(data.resolved_at),
        scorecard: asScorecard(data.scorecard),
    };
}

export type HealthScope = {
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
};

function healthUrl({ variantId, projectId, variantIds, compareVariantId }: HealthScope): URL | undefined {
    const url = new URL(import.meta.env.VITE_API_URL + '/api/packages/health', window.location.href);
    if (variantIds?.length) url.searchParams.set('variant_ids', variantIds.join(','));
    else if (variantId) {
        url.searchParams.set('variant_id', variantId);
        if (compareVariantId) url.searchParams.set('compare_variant_id', compareVariantId);
    } else if (projectId) url.searchParams.set('project_id', projectId);
    else return undefined;
    return url;
}

export async function listPackageHealth(scope: HealthScope, packageId?: string): Promise<PackageHealthMap> {
    const url = healthUrl(scope);
    if (!url) return { enabled: true, packages: {} };
    if (packageId) url.searchParams.set('package_id', packageId);
    const response = await fetch(url.toString(), { mode: 'cors' });
    if (!response.ok) throw new Error('Unable to load maintenance data');
    const data = await response.json();
    const packages: Record<string, PackageHealth> = {};
    if (typeof data?.packages === 'object' && data.packages !== null) {
        for (const [id, value] of Object.entries(data.packages)) {
            const health = asPackageHealth(value);
            if (health) packages[id] = health;
        }
    }
    return { enabled: data?.enabled !== false, packages };
}

export function scoreTone(score: number): HealthTone {
    if (score >= 7) return 'good';
    if (score >= 4) return 'fair';
    return 'poor';
}

/** Activity label from the Scorecard "Maintained" check (commits and issue activity over 90 days). */
export function maintenanceActivity(scorecard: PackageScorecard | null): { label: string; tone: HealthTone } | null {
    const maintained = scorecard?.maintained;
    if (!maintained || maintained.score === null || maintained.score < 0) return null;
    if (maintained.reason?.toLowerCase().includes('archived')) return { label: 'Archived', tone: 'poor' };
    if (maintained.score >= 7) return { label: 'Active', tone: 'good' };
    if (maintained.score >= 1) return { label: 'Low activity', tone: 'fair' };
    return { label: 'Inactive', tone: 'poor' };
}

export const repositoryUrl = (repository: string): string => `https://${repository}`;

export const scorecardViewerUrl = (repository: string): string =>
    `https://scorecard.dev/viewer/?uri=${encodeURIComponent(repository)}`;

export const REPOSITORY_SOURCE_LABELS: Record<RepositorySource, string> = {
    sbom: 'SBOM metadata',
    deps_dev: 'deps.dev package metadata',
    osv: 'CVE fix data (OSV)',
    none: 'Not found',
};

/** Sort key: scored packages by score, then everything else. */
export function healthSortValue(health: PackageHealth | undefined): number {
    return health?.scorecard?.status === 'scored' && health.scorecard.score !== null ? health.scorecard.score : -1;
}
