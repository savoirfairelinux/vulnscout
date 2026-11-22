import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import { MemoryRouter } from 'react-router-dom';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import Iso8601Duration from '../../src/handlers/iso8601duration';
import VulnModal from '../../src/components/VulnModal';

const METRIC = '0f8fad5b-d9cb-469f-a165-70867728950e';
const CVSS_FIELD = `cvss:3.1:nvd@nist.gov:${METRIC}`;
const NEW_LINK = 'https://example.org/patches/CVE-2010-1234.patch';
const OLD_LINK = 'https://old.example.org/advisory';
const LONG_DESCRIPTION = `Previous description ${'with a very long sentence '.repeat(40)}end`;

const vulnerability: Vulnerability = {
    id: 'CVE-2010-1234',
    aliases: [],
    related_vulnerabilities: [],
    namespace: 'nvd:cve',
    found_by: ['grype'],
    datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2010-1234',
    packages: ['openssl@1.0.0'],
    packages_current: [],
    urls: ['https://security-tracker.debian.org/tracker/CVE-2010-1234', NEW_LINK],
    cpes: [],
    texts: [{ title: 'description', content: 'Refreshed description' }],
    severity: {
        severity: 'critical',
        min_score: 7.5,
        max_score: 9.8,
        cvss: [
            {
                author: 'nvd@nist.gov', version: '3.1', severity: 'critical', vector_string: 'CVSS:3.1/AV:N/AC:L',
                base_score: 9.8, exploitability_score: 3.9, impact_score: 5.9,
            },
            {
                author: 'security-advisories@github.com', version: '3.1', severity: 'high',
                vector_string: 'CVSS:3.1/AV:L/AC:L', base_score: 7.5, exploitability_score: 1.8, impact_score: 5.9,
            },
        ],
    },
    epss: { score: 0.25, percentile: 0.5 },
    effort: {
        optimistic: new Iso8601Duration('PT4H'),
        likely: new Iso8601Duration('P1D'),
        pessimistic: new Iso8601Duration('P1W'),
    },
    fix: { state: 'unknown' },
    simplified_status: 'Pending Assessment',
    variants: [],
    assessments: [],
};

const run = (runId: string, status = 'complete', started = '2026-11-01T10:00:00+00:00') => ({
    run_id: runId, refresh_type: 'full', status, source_status: {},
    started_at: started, finished_at: '2026-11-01T10:05:00+00:00',
});

const cvssChange = {
    field: CVSS_FIELD, before: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L' }, after: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L' },
    changed_at: '2026-11-01T10:01:00+00:00', kind: 'changed', indicator: 'updated', current: true,
    cvss: { version: '3.1', author: 'nvd@nist.gov', metric_id: METRIC },
};
const linksChange = {
    field: 'links', before: ['https://security-tracker.debian.org/tracker/CVE-2010-1234', OLD_LINK],
    after: ['https://security-tracker.debian.org/tracker/CVE-2010-1234', NEW_LINK],
    changed_at: '2026-11-01T10:01:00+00:00', kind: 'changed', indicator: 'updated', current: true, cvss: null,
    added: [NEW_LINK], removed: [OLD_LINK],
};
const descriptionChange = {
    field: 'description', before: LONG_DESCRIPTION, after: 'Refreshed description',
    changed_at: '2026-11-01T10:01:00+00:00', kind: 'changed', indicator: 'updated', current: true, cvss: null,
};
const weaknessesChange = {
    field: 'weaknesses', before: null, after: ['CWE-787'], changed_at: '2026-11-01T10:01:00+00:00',
    kind: 'first_enrichment', indicator: 'new', current: true, cvss: null, added: ['CWE-787'], removed: [],
};

const indicators = (...sources: unknown[]) => ({ vuln_id: vulnerability.id, scope: {}, sources });
const nvdChanged = (overrides: Record<string, unknown> = {}) => ({
    source: 'nvd', state: 'changed', run: run('run-nvd'), later_attempt: null,
    changes: [cvssChange, linksChange, descriptionChange, weaknessesChange], ...overrides,
});
const epssUnchanged = { source: 'epss', state: 'no_change', run: run('run-epss'), changes: [], later_attempt: null };

const indicatorRequests = () => fetchMock.mock.calls
    .map(([request]) => new URL(typeof request === 'string' ? request : (request as Request).url, 'http://localhost'))
    .filter(url => url.pathname.endsWith('/refresh-indicators'));

function serve(byScope: (url: URL) => unknown) {
    fetchMock.resetMocks();
    fetchMock.mockResponse(request => {
        const url = new URL(request.url, 'http://localhost');
        if (url.pathname.endsWith('/refresh-indicators')) return Promise.resolve(JSON.stringify(byScope(url)));
        if (url.pathname.endsWith('/history')) {
            return Promise.resolve(JSON.stringify({ history: [{
                field: CVSS_FIELD, old_value: cvssChange.before, value: cvssChange.after, source: 'nvd',
                changed_at: '2026-11-01T10:01:00Z',
            }, {
                field: 'epss_score', old_value: 0.2, value: 0.25, source: 'epss', changed_at: '2026-10-01T10:01:00Z',
            }] }));
        }
        return Promise.resolve(JSON.stringify([]));
    });
}

const renderModal = (props: { projectId?: string; variantId?: string } = {}) => render(
    <MemoryRouter>
        <VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null}
            patchVuln={() => {}} {...props} />
    </MemoryRouter>,
);

const expandHistory = async () => {
    await userEvent.click(screen.getByRole('button', { name: 'Expand data history' }));
    return screen.findByRole('region', { name: 'Latest refresh per source' });
};

describe('VulnModal refresh indicators', () => {
    test('marks updated CVSS and new list entries with the previous value, source, time and refresh link', async () => {
        serve(() => indicators(nvdChanged(), epssUnchanged));
        renderModal();

        const cvss = await screen.findByTestId(`refresh-indicator-${CVSS_FIELD}`);
        expect(within(cvss).getByText('Updated')).toBeInTheDocument();
        expect(cvss).toHaveTextContent('Updated by the NVD refresh of');
        expect(cvss).toHaveTextContent('Previous value7.5 (CVSS:3.1/AV:N/AC:L)');
        expect(cvss).toHaveTextContent('Refreshed value9.8 (CVSS:3.1/AV:N/AC:L)');
        expect(within(cvss).getByRole('link', { name: 'View this refresh in the Refresh tab' }))
            .toHaveAttribute('href', '/refresh?run=run-nvd');
        // The CVSS score of another author is untouched.
        expect(screen.getAllByTestId(/^refresh-indicator-cvss:/)).toHaveLength(1);

        const links = screen.getByTestId('refresh-indicator-links');
        expect(within(links).getByText('Updated')).toBeInTheDocument();
        expect(links).toHaveTextContent('A new reference or patch link does not mean the installed package is patched.');
        const newLink = screen.getByRole('link', { name: NEW_LINK }).closest('li') as HTMLElement;
        expect(within(newLink).getByText('New')).toBeInTheDocument();
        const unchangedLink = screen.getByRole('link', { name: 'https://security-tracker.debian.org/tracker/CVE-2010-1234' })
            .closest('li') as HTMLElement;
        expect(within(unchangedLink).queryByText('New')).not.toBeInTheDocument();

        // Unchanged EPSS data gets no badge.
        expect(screen.queryByTestId('refresh-indicator-epss_score')).not.toBeInTheDocument();
        expect(screen.getByTestId('refresh-indicator-summary')).toHaveTextContent('Latest refresh: 1 new · 3 updated');
    });

    test('keeps removed entries and long previous values inspectable in Data history', async () => {
        serve(() => indicators(nvdChanged(), epssUnchanged));
        renderModal();
        const latest = await expandHistory();

        const links = within(latest).getByTestId('refresh-change-links');
        expect(links).toHaveTextContent('Added entries');
        expect(links).toHaveTextContent(NEW_LINK);
        expect(links).toHaveTextContent('Removed entries');
        expect(within(links).getByText(OLD_LINK)).toBeInTheDocument();
        expect(within(links).getByText('Removed')).toBeInTheDocument();

        const description = within(latest).getByTestId('refresh-change-description');
        const previous = within(description).getByText(LONG_DESCRIPTION);
        expect(previous.tagName).toBe('PRE');
        expect(previous).toHaveClass('whitespace-pre-wrap', 'overflow-auto');

        const weaknesses = within(latest).getByTestId('refresh-change-weaknesses');
        expect(within(weaknesses).getAllByText('New').length).toBeGreaterThan(0);
        expect(weaknesses).toHaveTextContent('not a newly discovered vulnerability');

        expect(latest).toHaveTextContent('Checked: no data changed in the latest EPSS refresh.');
        expect(within(latest).getAllByRole('link', { name: 'View refresh run' }).map(link => link.getAttribute('href')))
            .toEqual(['/refresh?run=run-nvd', '/refresh?run=run-epss']);

        // Only the timeline row produced by the latest refresh is marked.
        const cvssHistory = await screen.findByTestId(`history-${CVSS_FIELD}`);
        expect(within(cvssHistory).getByText('Updated')).toBeInTheDocument();
        expect(within(screen.getByTestId('history-epss_score')).queryByText('Updated')).not.toBeInTheDocument();
    });

    test('shows no badge for unchanged data or values superseded after the refresh', async () => {
        serve(() => indicators(
            { ...nvdChanged(), changes: [{ ...cvssChange, current: false }] },
            epssUnchanged,
        ));
        renderModal();
        const latest = await expandHistory();

        expect(screen.queryByTestId(/^refresh-indicator-/)).not.toBeInTheDocument();
        expect(screen.queryByText('New')).not.toBeInTheDocument();
        const cvss = within(latest).getByTestId(`refresh-change-${CVSS_FIELD}`);
        expect(within(cvss).getByText('Superseded')).toBeInTheDocument();
        expect(cvss).toHaveTextContent('no longer describes the current data');
    });

    test('reloads indicators from the server for the selected scope after reopening', async () => {
        serve(() => indicators(nvdChanged()));
        const first = renderModal({ projectId: 'project-1', variantId: 'variant-1' });
        expect(await screen.findByTestId(`refresh-indicator-${CVSS_FIELD}`)).toBeInTheDocument();
        first.unmount();

        renderModal({ projectId: 'project-1', variantId: 'variant-1' });
        expect(await screen.findByTestId(`refresh-indicator-${CVSS_FIELD}`)).toBeInTheDocument();
        const requests = indicatorRequests();
        expect(requests).toHaveLength(2);
        requests.forEach(url => {
            expect(url.pathname).toBe('/api/vulnerabilities/CVE-2010-1234/refresh-indicators');
            expect(url.searchParams.get('project_id')).toBe('project-1');
            expect(url.searchParams.get('variant_id')).toBe('variant-1');
        });
    });

    test('isolates indicators by source and scope and keeps them when a later check failed', async () => {
        serve(url => url.searchParams.get('variant_id') === 'other-variant'
            ? indicators(epssUnchanged)
            : indicators(
                nvdChanged({ changes: [cvssChange], later_attempt: { status: 'failed', error: 'HTTP 503', run: run('run-failed', 'incomplete', '2026-11-02T10:00:00+00:00') } }),
                { source: 'epss', state: 'changed', run: run('run-epss'), later_attempt: null, changes: [{
                    field: 'epss_score', before: 0.2, after: 0.25, changed_at: '2026-11-01T11:00:00+00:00',
                    kind: 'changed', indicator: 'updated', current: true, cvss: null,
                }] },
            ));
        const view = renderModal({ variantId: 'variant-1' });

        expect(await screen.findByTestId(`refresh-indicator-${CVSS_FIELD}`)).toBeInTheDocument();
        const epss = screen.getByTestId('refresh-indicator-epss_score');
        expect(epss).toHaveTextContent('Updated by the EPSS refresh of');
        expect(epss).toHaveTextContent('Previous value20.00%');
        const latest = await expandHistory();
        expect(latest).toHaveTextContent('A later NVD check did not complete: failed (HTTP 503)');
        expect(latest).toHaveTextContent('HTTP 503');
        expect(latest).toHaveTextContent('Indicators from the last successful check are kept.');
        expect(within(latest).getByRole('link', { name: 'View that run' })).toHaveAttribute('href', '/refresh?run=run-failed');

        view.rerender(
            <MemoryRouter>
                <VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null}
                    patchVuln={() => {}} variantId="other-variant" />
            </MemoryRouter>,
        );
        await waitFor(() => expect(screen.queryByTestId(/^refresh-indicator-/)).not.toBeInTheDocument());
        expect(await screen.findByText('Checked: no data changed in the latest EPSS refresh.')).toBeInTheDocument();
    });

    test('states partial runs, missing baselines and first enrichment explicitly', async () => {
        serve(() => indicators(
            nvdChanged({ run: run('run-partial', 'incomplete'), changes: [weaknessesChange] }),
            { source: 'ghsa', state: 'no_baseline', run: null, changes: [], later_attempt: {
                status: 'skipped', error: 'Not returned by provider', run: run('run-skipped', 'incomplete'),
            } },
        ));
        renderModal();
        const latest = await expandHistory();

        expect(latest).toHaveTextContent('Partial refresh run (incomplete or cancelled): this vulnerability\'s NVD check completed, but the run did not cover every source or target.');
        expect(latest).toHaveTextContent('No completed GitHub Advisory Database refresh is recorded for this vulnerability in this scope: there is no baseline');
        expect(latest).toHaveTextContent('A later GitHub Advisory Database check did not complete: skipped (Not returned by provider)');
        expect(latest).not.toHaveTextContent('Indicators from the last successful check are kept.');
        const weaknesses = within(latest).getByTestId('refresh-change-weaknesses');
        expect(weaknesses).toHaveTextContent('First enrichment: no previous value was recorded.');
        expect(weaknesses).toHaveTextContent('No previous value');
    });

    test('replaces indicators with the server result after the modal refresh', async () => {
        let refreshed = false;
        fetchMock.resetMocks();
        fetchMock.mockResponse(request => {
            const url = new URL(request.url, 'http://localhost');
            if (url.pathname.endsWith('/refresh-indicators')) {
                return Promise.resolve(JSON.stringify(refreshed
                    ? indicators({ ...epssUnchanged, source: 'nvd', run: run('run-new') })
                    : indicators(nvdChanged())));
            }
            if (url.pathname.endsWith('/refresh') && request.method === 'POST') {
                refreshed = true;
                return Promise.resolve(JSON.stringify({ results: {} }));
            }
            if (url.pathname === `/api/vulnerabilities/${vulnerability.id}`) return Promise.resolve(JSON.stringify(vulnerability));
            return Promise.resolve(JSON.stringify([]));
        });
        renderModal();
        expect(await screen.findByTestId(`refresh-indicator-${CVSS_FIELD}`)).toBeInTheDocument();

        await userEvent.click(screen.getByTitle('Refresh from NVD, EPSS & ENISA EUVD'));

        await waitFor(() => expect(screen.queryByTestId(/^refresh-indicator-/)).not.toBeInTheDocument());
        expect(indicatorRequests()).toHaveLength(2);
        const latest = await expandHistory();
        expect(latest).toHaveTextContent('Checked: no data changed in the latest NVD refresh.');
    });

    test('explains an empty refresh history and a failed indicator request without badges', async () => {
        serve(() => indicators());
        const view = renderModal();
        const latest = await expandHistory();
        expect(latest).toHaveTextContent('No refresh of this vulnerability is recorded in this scope: there is no baseline');
        view.unmount();

        fetchMock.resetMocks();
        fetchMock.mockResponse(request => Promise.resolve(
            new URL(request.url, 'http://localhost').pathname.endsWith('/refresh-indicators')
                ? { status: 500, body: '' } : { body: JSON.stringify([]) },
        ));
        renderModal();
        await userEvent.click(screen.getByRole('button', { name: 'Expand data history' }));
        expect(await screen.findByText(/Failed to load refresh indicators/)).toBeInTheDocument();
        expect(screen.queryByTestId(/^refresh-indicator-/)).not.toBeInTheDocument();
    });
});
