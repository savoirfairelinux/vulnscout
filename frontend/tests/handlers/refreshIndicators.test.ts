import RefreshIndicators, {
    activeIndicators, addedEntries, asRefreshIndicators, cvssIndicators, indicatorsFor, refreshRunPath,
} from '../../src/handlers/refreshIndicators';
import type { CVSS } from '../../src/handlers/vulnerabilities';

const run = { run_id: 'run-1', refresh_type: 'full', status: 'complete', source_status: { nvd: 'complete' },
    started_at: '2026-11-01T10:00:00+00:00', finished_at: '2026-11-01T10:01:00+00:00' };
const change = (field: string, overrides: Record<string, unknown> = {}) => ({
    field, before: null, after: 1, changed_at: '2026-11-01T10:00:30+00:00', kind: 'first_enrichment',
    indicator: 'new', current: true, cvss: null, ...overrides,
});
const cvss = (author: string, score: number, metric: string) => change(`cvss:3.1:${author}:${metric}`, {
    before: { score: 5, vector: 'V' }, after: { score, vector: `V${score}` }, kind: 'changed', indicator: 'updated',
    cvss: { version: '3.1', author, metric_id: metric },
});
const gauge = (author: string, score: number, variant_id?: string): CVSS => ({
    author, version: '3.1', severity: 'high', vector_string: `V${score}`, base_score: score,
    exploitability_score: 1, impact_score: 1, variant_id,
});

describe('refresh indicators API client', () => {
    afterEach(() => jest.restoreAllMocks());

    test('requests one vulnerability in the selected scope with GET only', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true, status: 200, json: async () => ({ vuln_id: 'CVE-1', sources: [] }),
        });
        const controller = new AbortController();
        expect(await RefreshIndicators.forVulnerability('CVE 1/x', { projectId: 'p', variantId: 'v' }, controller.signal))
            .toEqual({ vuln_id: 'CVE-1', sources: [] });
        const [url, options] = (fetch as jest.Mock).mock.calls[0];
        const parsed = new URL(url, 'http://localhost');
        expect(parsed.pathname).toBe('/api/vulnerabilities/CVE%201%2Fx/refresh-indicators');
        expect(Object.fromEntries(parsed.searchParams)).toEqual({ project_id: 'p', variant_id: 'v' });
        expect(options).toEqual({ mode: 'cors', signal: controller.signal });

        await RefreshIndicators.forVulnerability('CVE-1', {});
        expect((fetch as jest.Mock).mock.calls[1][0]).toMatch(/\/refresh-indicators$/);
    });

    test('returns null for unknown vulnerabilities and throws on failures', async () => {
        global.fetch = jest.fn().mockResolvedValueOnce({ ok: false, status: 404 })
            .mockResolvedValueOnce({ ok: false, status: 503 });
        expect(await RefreshIndicators.forVulnerability('CVE-1', {})).toBeNull();
        await expect(RefreshIndicators.forVulnerability('CVE-1', {})).rejects.toThrow('HTTP 503');
    });

    test('ignores malformed payloads and entries', () => {
        expect(asRefreshIndicators([])).toBeNull();
        expect(asRefreshIndicators({ sources: [] })).toBeNull();
        expect(asRefreshIndicators({ vuln_id: 'CVE-1', sources: [
            { source: 'nvd', state: 'bogus' },
            { source: 'epss', state: 'changed', run, changes: [{ field: 'x' }, change('epss_score')] },
        ] })?.sources).toEqual([{
            source: 'epss', state: 'changed', run, later_attempt: null,
            changes: [{ ...change('epss_score') }],
        }]);
    });
});

describe('refresh indicator selection', () => {
    const data = asRefreshIndicators({ vuln_id: 'CVE-1', sources: [
        { source: 'nvd', state: 'changed', run, later_attempt: null, changes: [
            cvss('nvd@nist.gov', 9.8, 'm1'),
            cvss('nvd@nist.gov', 6.1, 'm2'),
            cvss('other', 4.2, 'm3'),
            change('links', { before: ['a'], after: ['a', 'b'], added: ['b'], removed: [], indicator: 'new' }),
            change('description', { current: false }),
            change('status', { before: 'high', after: null, indicator: 'removed' }),
        ] },
        { source: 'epss', state: 'no_change', run, later_attempt: null, changes: [] },
        { source: 'ghsa', state: 'no_baseline', run: null, later_attempt: null, changes: [change('links')] },
    ] });

    test('keeps only current indicators of checked sources', () => {
        const live = activeIndicators(data);
        expect(live.map(item => `${item.source}:${item.field}`)).toEqual([
            'nvd:cvss:3.1:nvd@nist.gov:m1', 'nvd:cvss:3.1:nvd@nist.gov:m2', 'nvd:cvss:3.1:other:m3',
            'nvd:links', 'nvd:status',
        ]);
        expect(live[0].run.run_id).toBe('run-1');
        expect(indicatorsFor(live, 'status')).toEqual([]);
        expect(indicatorsFor(live, 'links').map(item => item.field)).toEqual(['links']);
        expect([...addedEntries(live, 'links').keys()]).toEqual(['b']);
        expect(activeIndicators(null)).toEqual([]);
    });

    test('matches CVSS by version and author, then by value when the author has several scores', () => {
        const live = activeIndicators(data);
        expect(cvssIndicators(live, gauge('other', 4.2)).map(item => item.field)).toEqual(['cvss:3.1:other:m3']);
        expect(cvssIndicators(live, gauge('nvd@nist.gov', 6.1)).map(item => item.field)).toEqual(['cvss:3.1:nvd@nist.gov:m2']);
        expect(cvssIndicators(live, gauge('nobody', 9.8))).toEqual([]);
        expect(cvssIndicators(live, gauge('other', 4.2, 'variant'))).toEqual([]);
    });

    test('links to the Refresh tab for one run', () => {
        expect(refreshRunPath('q 1')).toBe('/refresh?run=q%201');
    });
});
