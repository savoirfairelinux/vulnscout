import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';

import type { Package } from '../../src/handlers/packages';
import TablePackages from '../../src/pages/TablePackages';
import PackageHealthBadge from '../../src/components/PackageHealthBadge';
import PackageHealthModal from '../../src/components/PackageHealthModal';
import Operations from '../../src/handlers/operations';
import {
    asPackageHealth, healthSortValue, listPackageHealth, maintenanceActivity, scoreTone, scorecardViewerUrl,
} from '../../src/handlers/packageHealth';
import type { PackageHealth } from '../../src/handlers/packageHealth';

type Reply = { status?: number; body: unknown };
type Request = { url: URL; method: string; body: unknown };

const requests: Request[] = [];
let restoreFetch: (() => void) | null = null;

/** Answer fetch calls like the VulnScout API would, recording every request. */
function serve(route: (request: Request) => Reply | undefined) {
    const original = global.fetch;
    global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = {
            url: new URL(String(input), 'http://localhost'),
            method: init?.method ?? 'GET',
            body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
        };
        requests.push(request);
        const reply = route(request) ?? { status: 404, body: {} };
        const status = reply.status ?? 200;
        return { ok: status >= 200 && status < 300, status, json: async () => reply.body } as Response;
    }) as typeof fetch;
    restoreFetch = () => { global.fetch = original; };
}

const originalRect = Element.prototype.getBoundingClientRect;

beforeAll(() => {
    global.ResizeObserver = class implements ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
    // jsdom has no layout; the virtualized table needs a viewport to render rows.
    Element.prototype.getBoundingClientRect = () => ({
        width: 2000, height: 1000, top: 0, bottom: 1000, left: 0, right: 2000, x: 0, y: 0, toJSON: () => {},
    });
});

afterAll(() => { Element.prototype.getBoundingClientRect = originalRect; });

beforeEach(() => { requests.length = 0; });
afterEach(() => { restoreFetch?.(); restoreFetch = null; });

const pkg = (name: string): Package => ({
    id: `${name}@1.0`, name, version: '1.0', cpe: [], purl: [], vulnerabilities: {}, maxSeverity: {},
    source: [], variants: [], sbom_documents: [], supplier: '',
});
const packages = ['curl', 'request', 'glibc', 'lonely', 'fresh'].map(pkg);

const raw = {
    'curl@1.0': {
        repository: 'github.com/curl/curl', repository_source: 'sbom',
        repository_evidence: 'https://github.com/curl/curl/releases/download/curl.tar.xz',
        deprecated: false, deprecated_reason: null, resolved_at: '2026-11-09T00:00:00+00:00',
        scorecard: {
            status: 'scored', score: 9.1, date: '2026-11-09T10:00:00Z', commit: 'c', fetched_at: '2026-11-09',
            maintained: { score: 10, reason: '30 commit(s) in the last 90 days' },
        },
    },
    'request@1.0': {
        repository: 'github.com/request/request', repository_source: 'deps_dev', repository_evidence: 'npm:request@1.0',
        deprecated: true, deprecated_reason: 'request has been deprecated', resolved_at: null,
        scorecard: { status: 'scored', score: 3.2, maintained: { score: 0, reason: 'project is archived' } },
    },
    'glibc@1.0': {
        repository: 'sourceware.org/git/glibc', repository_source: 'osv', repository_evidence: 'CVE-2023-4911',
        deprecated: null, scorecard: { status: 'unsupported' },
    },
    'lonely@1.0': { repository: null, repository_source: 'none', scorecard: null },
};
const details = {
    ...raw['curl@1.0'],
    scorecard: {
        ...raw['curl@1.0'].scorecard,
        repository: 'github.com/Curl/curl',
        checks: [
            { name: 'Maintained', score: 10, reason: 'active', description: 'Is it maintained?',
              url: 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained' },
            { name: 'Packaging', score: -1, reason: null, description: null, url: 'javascript:alert(1)' },
        ],
    },
};

function api(overrides: (request: Request) => Reply | undefined = () => undefined) {
    serve(request => {
        const override = overrides(request);
        if (override) return override;
        if (request.url.pathname === '/api/packages/health') {
            const packageId = request.url.searchParams.get('package_id');
            if (packageId) return { body: { enabled: true, packages: packageId === 'curl@1.0' ? { [packageId]: details } : {} } };
            return { body: { enabled: true, packages: raw } };
        }
        if (request.url.pathname === '/api/package-dependencies') return { body: { counts: {}, unrecorded: [] } };
        if (request.url.pathname === '/api/operations') return { status: 202, body: { queue_id: 'q', operations: [] } };
        return undefined;
    });
}

const cellOf = (name: string) => screen.getByRole('button', { name: `View maintenance details for ${name}` });

describe('Maintenance column', () => {
    test('shows scores, activity and deprecation, and opens Scorecard details', async () => {
        api();
        render(<TablePackages packages={packages} variantId="v1" preferenceScopeKey="health-variant" />);
        expect(await screen.findByText('9.1')).toBeInTheDocument();
        expect(within(cellOf('curl')).getByText('Active')).toBeInTheDocument();
        expect(within(cellOf('request')).getByText('Archived')).toBeInTheDocument();
        expect(within(cellOf('request')).getByText('Deprecated')).toHaveAttribute('title', 'request has been deprecated');
        expect(within(cellOf('glibc')).getByText('Not covered')).toBeInTheDocument();
        expect(within(cellOf('lonely')).getByText('No repository')).toBeInTheDocument();
        expect(screen.getByText('Not fetched')).toBeInTheDocument();
        const list = requests.find(request => request.url.pathname === '/api/packages/health')!;
        expect(list.url.searchParams.get('variant_id')).toBe('v1');

        fireEvent.focus(cellOf('curl'));
        fireEvent.click(cellOf('curl'));
        const dialog = await screen.findByRole('dialog', { name: 'Maintenance: curl@1.0' });
        expect(await within(dialog).findByRole('link', { name: 'Maintained' })).toHaveAttribute(
            'href', 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained');
        expect(within(dialog).getByText('Packaging').closest('a')).toBeNull();
        expect(within(dialog).getByTitle('Inconclusive')).toHaveTextContent('?');
        expect(within(dialog).getByRole('link', { name: 'github.com/curl/curl' })).toHaveAttribute(
            'href', 'https://github.com/curl/curl');
        expect(within(dialog).getByRole('link', { name: 'View on scorecard.dev' })).toHaveAttribute(
            'href', scorecardViewerUrl('github.com/Curl/curl'));
        expect(within(dialog).getByText('published 2026-11-09')).toBeInTheDocument();
        expect(within(dialog).getByText('Not deprecated')).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close modal' }));
        expect(screen.queryByRole('dialog')).toBeNull();

        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' }));
        expect(await screen.findByText('Maintenance data refresh queued')).toBeInTheDocument();
        const queued = requests.find(request => request.method === 'POST')!;
        expect(queued.body).toEqual({ jobs: [Operations.scorecardRefreshJob(['v1'])] });
        expect(queued.body).toEqual({ jobs: [
            { kind: 'refresh', source: 'scorecard', variant_ids: ['v1'], options: { force: false } },
        ] });
    });

    test('refreshes every variant of a project and reports queue conflicts', async () => {
        api(request => {
            if (request.url.pathname === '/api/projects/p1/variants') return { body: [
                { id: 'v1', name: 'a', project_id: 'p1' }, { id: 'v2', name: 'b', project_id: 'p1' },
            ] };
            if (request.method === 'POST') return { status: 409, body: { error: 'Some requested operations are already queued or running' } };
            return undefined;
        });
        render(<TablePackages packages={packages} projectId="p1" preferenceScopeKey="health-project" />);
        await screen.findByText('9.1');
        expect(requests.find(request => request.url.pathname === '/api/packages/health')!.url.searchParams.get('project_id')).toBe('p1');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' }));
        expect(await screen.findByText('Some requested operations are already queued or running')).toBeInTheDocument();
        expect(requests.find(request => request.method === 'POST')!.body).toEqual({ jobs: [
            { kind: 'refresh', source: 'scorecard', variant_ids: ['v1', 'v2'], options: { force: false } },
        ] });
    });

    test('compared variants are both looked up and refreshed', async () => {
        api();
        render(<TablePackages packages={packages} variantId="v1" compareVariantId="v2" operation="difference"
            preferenceScopeKey="health-compare" />);
        await screen.findByText('9.1');
        const list = requests.find(request => request.url.pathname === '/api/packages/health')!;
        expect(list.url.searchParams.get('compare_variant_id')).toBe('v2');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' }));
        await screen.findByText('Maintenance data refresh queued');
        expect((requests.find(request => request.method === 'POST')!.body as { jobs: { variant_ids: string[] }[] })
            .jobs[0].variant_ids).toEqual(['v1', 'v2']);
    });

    test('multi-variant selections use variant_ids', async () => {
        api();
        render(<TablePackages packages={packages} variantIds={['v1', 'v3']} preferenceScopeKey="health-multi" />);
        await screen.findByText('9.1');
        expect(requests.find(request => request.url.pathname === '/api/packages/health')!.url.searchParams
            .get('variant_ids')).toBe('v1,v3');
    });

    test('without a scope nothing is fetched and the refresh explains why', async () => {
        api();
        render(<TablePackages packages={packages} preferenceScopeKey="health-unscoped" />);
        expect(screen.getAllByText('Not fetched')).toHaveLength(packages.length);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' }));
        expect(await screen.findByText('Select a project or variant to refresh maintenance data')).toBeInTheDocument();
        expect(requests.some(request => request.url.pathname === '/api/packages/health')).toBe(false);
    });

    test('variant lookup failures are reported', async () => {
        api(request => request.url.pathname === '/api/projects/p1/variants' ? { status: 500, body: {} } : undefined);
        render(<TablePackages packages={packages} projectId="p1" preferenceScopeKey="health-failure" />);
        await screen.findByText('9.1');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh maintenance' }));
        expect(await screen.findByText('Unable to queue the maintenance data refresh')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        await waitFor(() => expect(screen.queryByText('Unable to queue the maintenance data refresh')).toBeNull());
    });

    test('disabled lookups hide the refresh action', async () => {
        api(request => request.url.pathname === '/api/packages/health'
            ? { body: { enabled: false, packages: {} } } : undefined);
        render(<TablePackages packages={packages} variantId="v1" preferenceScopeKey="health-disabled" />);
        await waitFor(() => expect(screen.getAllByText('Disabled')).toHaveLength(packages.length));
        expect(screen.queryByRole('button', { name: 'Refresh maintenance' })).toBeNull();
    });

    test('load failures are not shown as missing data', async () => {
        api(request => request.url.pathname === '/api/packages/health' ? { status: 500, body: {} } : undefined);
        render(<TablePackages packages={packages} variantId="v1" preferenceScopeKey="health-error" />);
        expect(screen.getAllByText('Loading scores…')).toHaveLength(packages.length);
        await waitFor(() => expect(screen.getAllByText('Scores unavailable')).toHaveLength(packages.length));
    });

    test('hiding the column skips the request', async () => {
        localStorage.setItem('vulnscout.tables.packages.health-hidden.visibleColumns', JSON.stringify(['Name']));
        localStorage.setItem('vulnscout.tables.packages.health-hidden.maintenanceColumnDefaulted', 'true');
        api();
        render(<TablePackages packages={packages} variantId="v1" preferenceScopeKey="health-hidden" />);
        await act(async () => { await Promise.resolve(); });
        expect(requests.some(request => request.url.pathname === '/api/packages/health')).toBe(false);
        expect(screen.queryByRole('button', { name: 'Refresh maintenance' })).toBeNull();
    });
});

describe('Maintenance details', () => {
    test('retries failed loads and explains unscored repositories', async () => {
        let failures = 1;
        const health = (packageId: string, value: unknown) => ({ body: { enabled: true, packages: { [packageId]: value } } });
        api(request => {
            const packageId = request.url.searchParams.get('package_id');
            if (packageId === 'curl@1.0' && failures-- > 0) return { status: 503, body: {} };
            if (packageId === 'request@1.0') return health(packageId, { ...raw['request@1.0'], scorecard: { status: 'not_found' } });
            if (packageId === 'glibc@1.0') return health(packageId, raw['glibc@1.0']);
            if (packageId === 'lonely@1.0') return health(packageId, raw['lonely@1.0']);
            if (packageId === 'error@1.0') return health(packageId, { ...raw['curl@1.0'], scorecard: { status: 'error' } });
            if (packageId === 'plain@1.0') return health(packageId, raw['curl@1.0']);
            return undefined;
        });
        const { rerender } = render(<PackageHealthModal packageId="curl@1.0" variantId="v1" onClose={() => {}} />);
        expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load maintenance data');
        fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
        expect(await screen.findByText('9.1 / 10')).toBeInTheDocument();

        rerender(<PackageHealthModal packageId="request@1.0" variantId="v1" onClose={() => {}} />);
        expect(await screen.findByText(/Not scored/)).toBeInTheDocument();
        expect(screen.getByText('request has been deprecated')).toBeInTheDocument();
        expect(screen.getByText('deps.dev package metadata')).toBeInTheDocument();

        rerender(<PackageHealthModal packageId="glibc@1.0" projectId="p1" onClose={() => {}} />);
        expect(await screen.findByText(/Not covered/)).toBeInTheDocument();
        expect(screen.getByText('CVE fix data (OSV)')).toBeInTheDocument();

        rerender(<PackageHealthModal packageId="lonely@1.0" projectId="p1" onClose={() => {}} />);
        expect(await screen.findByText('No upstream repository found')).toBeInTheDocument();

        rerender(<PackageHealthModal packageId="error@1.0" projectId="p1" onClose={() => {}} />);
        expect(await screen.findByText(/Unavailable: the last lookup failed/)).toBeInTheDocument();

        rerender(<PackageHealthModal packageId="plain@1.0" projectId="p1" onClose={() => {}} />);
        expect(await screen.findByRole('link', { name: 'View on scorecard.dev' })).toHaveAttribute(
            'href', scorecardViewerUrl('github.com/curl/curl'));

        rerender(<PackageHealthModal packageId="unknown@1.0" variantIds={['v1', 'v2']} onClose={() => {}} />);
        expect(await screen.findByText(/No maintenance data yet/)).toBeInTheDocument();
    });
});

describe('Maintenance badge', () => {
    const base = asPackageHealth(raw['curl@1.0'])!;
    const withScorecard = (scorecard: unknown): PackageHealth => ({ ...base, scorecard: asPackageHealth({ ...raw['curl@1.0'], scorecard })!.scorecard });

    test.each([
        [{ status: 'not_found' }, 'Not scored'],
        [{ status: 'error' }, 'Unavailable'],
        [{ status: 'scored', score: null }, 'No score'],
        [null, 'Not fetched'],
    ])('%j reads %s', (scorecard, label) => {
        render(<PackageHealthBadge health={withScorecard(scorecard)} enabled />);
        expect(screen.getByText(label)).toBeInTheDocument();
    });

    test('low activity and poor scores are distinguished', () => {
        render(<PackageHealthBadge health={withScorecard({ status: 'scored', score: 2, maintained: { score: 3, reason: 'few commits' } })} enabled />);
        expect(screen.getByText('2.0')).toHaveClass('bg-red-900');
        expect(screen.getByText('Low activity')).toHaveAttribute('title', 'few commits');
    });

    test('deprecation remains visible without a repository', () => {
        render(<PackageHealthBadge health={{
            ...asPackageHealth(raw['request@1.0'])!, repository: null, scorecard: null,
        }} enabled />);
        expect(screen.getByText('No repository')).toBeInTheDocument();
        expect(screen.getByText('Deprecated')).toHaveAttribute('title', 'request has been deprecated');
    });

    test('chips fall back to generic explanations', () => {
        render(<PackageHealthBadge health={{
            ...withScorecard({ status: 'scored', score: 5, maintained: { score: 8 } }), deprecated: true,
        }} enabled />);
        expect(screen.getByText('5.0')).toHaveClass('bg-amber-900');
        expect(screen.getByText('Active')).not.toHaveAttribute('title');
        expect(screen.getByText('Deprecated')).toHaveAttribute('title', 'Marked deprecated by its package registry');
    });
});

describe('Maintenance handler', () => {
    test('validates API data defensively', async () => {
        serve(request => request.url.searchParams.get('variant_id') === 'bad'
            ? { body: { packages: 'nope' } }
            : { body: { enabled: true, packages: {
                'ok@1': {
                    repository: 'javascript:alert(1)', repository_source: 'elsewhere', deprecated: 'yes',
                    scorecard: { status: 'scored', repository: '../evil', score: 'high', maintained: 'x', checks: [
                        { name: 'Code-Review', score: 2, url: 'http://insecure.example' }, { score: 1 }, null,
                    ] },
                },
                'odd@1': { scorecard: { status: 'unknown' } },
                'skip@1': 'invalid',
            } } });
        const result = await listPackageHealth({ variantId: 'v1' });
        expect(result.enabled).toBe(true);
        expect(Object.keys(result.packages)).toEqual(['ok@1', 'odd@1']);
        expect(result.packages['ok@1']).toEqual({
            repository: null, repositorySource: 'none', repositoryEvidence: null, deprecated: null,
            deprecatedReason: null, resolvedAt: null,
            scorecard: { status: 'scored', repository: null, score: null, date: null, fetchedAt: null, maintained: null,
                checks: [{ name: 'Code-Review', score: 2, reason: null, description: null, url: null }] },
        });
        expect(result.packages['odd@1'].scorecard).toBeNull();
        expect(await listPackageHealth({ variantId: 'bad' })).toEqual({ enabled: true, packages: {} });
        expect(await listPackageHealth({})).toEqual({ enabled: true, packages: {} });
    });

    test('failed requests reject', async () => {
        serve(() => ({ status: 500, body: {} }));
        await expect(listPackageHealth({ projectId: 'p1' }, 'lib@1')).rejects.toThrow('Unable to load maintenance data');
        expect(requests[0].url.searchParams.get('package_id')).toBe('lib@1');
    });

    test('scores, activity and sort keys', () => {
        expect([scoreTone(7), scoreTone(4), scoreTone(3.9)]).toEqual(['good', 'fair', 'poor']);
        expect(maintenanceActivity(null)).toBeNull();
        const scorecard = (score: number | null, reason: string | null = null) => ({
            status: 'scored' as const, score: 5, date: null, fetchedAt: null, maintained: { score, reason },
        });
        expect(maintenanceActivity(scorecard(null))).toBeNull();
        expect(maintenanceActivity(scorecard(-1))).toBeNull();
        expect(maintenanceActivity(scorecard(0))).toEqual({ label: 'Inactive', tone: 'poor' });
        expect(maintenanceActivity({ ...scorecard(5), maintained: null })).toBeNull();
        expect(healthSortValue(undefined)).toBe(-1);
        expect(healthSortValue(asPackageHealth(raw['curl@1.0'])!)).toBe(9.1);
        expect(healthSortValue(asPackageHealth(raw['glibc@1.0'])!)).toBe(-1);
        expect(asPackageHealth(null)).toBeNull();
    });
});
