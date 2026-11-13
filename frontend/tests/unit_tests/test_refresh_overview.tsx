import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import RefreshOverview from '../../src/pages/RefreshOverview';
import RefreshRuns from '../../src/handlers/refreshRuns';
import type { RefreshRun } from '../../src/handlers/refreshRuns';
import Projects from '../../src/handlers/project';
import Variants from '../../src/handlers/variant';
import * as vulnerabilityHistory from '../../src/handlers/vulnerabilityHistory';
import Vulnerabilities, { type Vulnerability } from '../../src/handlers/vulnerabilities';
import Operations from '../../src/handlers/operations';
import { getSnapshot, refreshProgressOf, waitForQueue } from '../../src/handlers/operationStore';
import type { Operation } from '../../src/types/operation';

jest.mock('../../src/handlers/operationStore', () => {
    const operations: never[] = [];
    return {
        subscribe: () => () => {},
        getSnapshot: jest.fn(() => operations),
        refreshProgressOf: jest.fn(),
        waitForQueue: jest.fn(async () => []),
    };
});

const run: RefreshRun = {
    run_id: 'persisted-run', scope: { project_id: 'project-a', variant_id: null },
    sources: ['nvd', 'epss'], started_at: '2026-10-30T12:00:00Z', finished_at: '2026-10-30T12:01:00Z',
    source_status: { nvd: 'complete', epss: 'complete' },
    status: 'complete',
    coverage: [
        { vuln_id: 'CVE-1', source: 'nvd', status: 'complete', error: null },
        { vuln_id: 'CVE-1', source: 'epss', status: 'complete', error: null },
        { vuln_id: 'CVE-2', source: 'nvd', status: 'skipped', error: 'Not supported' },
    ],
    summary: { total_changes: 2, changed_vulnerabilities: 1, first_enrichments: 0 },
    changes: [{
        vuln_id: 'CVE-1', source: 'nvd', field: 'description', before: 'Old description',
        after: 'New description', kind: 'changed', change_type: 'modification', changed_at: '2026-10-30T12:00:30Z',
        packages: [{ package_id: 'package-1', package: 'openssl@3', name: 'openssl', version: '3', variant_id: 'variant-a', project_id: 'project-a' }],
    }], total: 1, limit: 25, offset: 0,
};

function show(initial = '/refresh', props: { projectId?: string; variantId?: string } = { projectId: 'project-a', variantId: 'variant-a' }) {
    return render(<MemoryRouter initialEntries={[initial]}><RefreshOverview {...props} /></MemoryRouter>);
}

async function openResult() {
    await userEvent.click(await screen.findByRole('button', { name: 'View Refresh Result' }));
    return screen.findByRole('dialog', { name: 'Refresh Result' });
}

async function selectSection(name: string) {
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: new RegExp(`^${name}`) }));
}

describe('Refresh overview', () => {
    let detail: jest.SpyInstance;
    let latest: jest.SpyInstance;
    let list: jest.SpyInstance;
    beforeEach(() => {
        (getSnapshot as jest.Mock).mockReturnValue([]);
        (waitForQueue as jest.Mock).mockReset().mockResolvedValue([]);
        (refreshProgressOf as jest.Mock).mockReset();
        latest = jest.spyOn(RefreshRuns, 'latest').mockResolvedValue(run);
        detail = jest.spyOn(RefreshRuns, 'detail').mockResolvedValue(run);
        list = jest.spyOn(RefreshRuns, 'list').mockResolvedValue({ runs: [run], total: 1, limit: 20, offset: 0 });
    });
    afterEach(() => jest.restoreAllMocks());

    test('opens persisted metadata, coverage and before/after tables in the Scan-style result popup', async () => {
        show();
        await screen.findByRole('button', { name: 'View Refresh Result' });
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.queryByText('Old description')).not.toBeInTheDocument();
        expect(detail).not.toHaveBeenCalled();
        for (const id of ['persisted-run', 'project-a', 'variant-a', 'package-1']) {
            expect(screen.queryByText(new RegExp(id))).not.toBeInTheDocument();
        }
        expect(screen.queryByText('Update vulnerability data and review what changed.')).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: 'View refresh changes' })).not.toBeInTheDocument();
        expect(screen.getByRole('heading', { name: 'Refresh History' })).toBeInTheDocument();
        const toolbar = screen.getByRole('heading', { name: 'Refresh History' }).closest('header');
        expect(toolbar).toContainElement(screen.getByTestId('refresh-dropdown-toggle'));
        expect(toolbar).toContainElement(screen.getByRole('button', { name: 'Reload results' }));
        expect(toolbar).toContainElement(screen.getByRole('button', { name: 'Export vulnerability history' }));
        const entries = screen.getByRole('list', { name: 'Refresh runs' });
        const entry = within(entries).getByRole('article');
        expect(within(entry).queryByText('Vulnerability Data Refresh')).not.toBeInTheDocument();
        expect(within(entry).getByRole('button', { name: 'View Refresh Result' })).toHaveAttribute('aria-pressed', 'false');
        expect(entry).toHaveTextContent('NVD');
        expect(entry).toHaveTextContent('EPSS');
        expect(entry).toHaveTextContent('complete');
        expect(entry).toHaveTextContent('1 vulnerabilities changed');
        expect(entry.querySelector('time')).toHaveAttribute('dateTime', run.started_at);
        expect(latest).toHaveBeenCalledWith({ project_id: 'project-a', variant_id: 'variant-a' }, expect.any(AbortSignal));
        expect(list).toHaveBeenCalledWith(expect.objectContaining({ project_id: 'project-a', variant_id: 'variant-a' }), expect.any(AbortSignal));
        const popup = await openResult();
        expect(popup).toHaveAttribute('aria-modal', 'true');
        expect(within(entry).getByRole('button', { name: 'View Refresh Result' })).toHaveAttribute('aria-pressed', 'true');
        const changes = await within(popup).findByRole('table', { name: 'Refresh changes' });
        for (const column of ['Vulnerability', 'Field', 'Source', 'Change', 'Before', 'After', 'Changed', 'Packages']) {
            expect(within(changes).getByRole('columnheader', { name: column })).toBeInTheDocument();
        }
        expect(screen.getByText('Old description')).toBeInTheDocument();
        expect(screen.getByText('New description')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Open CVE-1 vulnerability' })).toHaveAttribute('href', '/vulnerabilities');
        expect(screen.getByRole('link', { name: /openssl@3/ })).toHaveAttribute('href', '/vulnerabilities');
        await selectSection('Overview');
        const counts = screen.getByRole('table', { name: 'Distinct vulnerability counts' });
        for (const row of ['Targeted 2', 'Checked 1', 'Changed 1', 'Skipped 1']) {
            expect(within(counts).getByRole('row', { name: row })).toBeInTheDocument();
        }
        expect(screen.getByRole('table', { name: 'Refresh metadata' })).toHaveTextContent('Finished');
        await selectSection('Coverage');
        const coverage = screen.getByRole('table', { name: 'Vulnerability coverage' });
        expect(within(coverage).getByRole('row', { name: 'CVE-2 NVD skipped Not supported' })).toBeInTheDocument();
        expect(screen.getByRole('table', { name: 'Provider coverage' })).toHaveTextContent('NVD');
    });

    test('filters on the server before pagination and preserves scope on every request', async () => {
        detail.mockResolvedValue({ ...run, total: 26 });
        show();
        await openResult();
        await screen.findByRole('button', { name: 'Next changes' });
        await userEvent.click(screen.getByRole('button', { name: 'Next changes' }));
        await waitFor(() => expect(detail).toHaveBeenLastCalledWith('persisted-run',
            expect.objectContaining({ project_id: 'project-a', variant_id: 'variant-a', offset: 25, limit: 25 }), expect.any(AbortSignal)));
        await userEvent.selectOptions(screen.getByLabelText('Source'), 'epss');
        await waitFor(() => expect(detail).toHaveBeenLastCalledWith('persisted-run',
            expect.objectContaining({ source: 'epss', offset: 0 }), expect.any(AbortSignal)));
        await userEvent.selectOptions(screen.getByLabelText('Change type'), 'removal');
        await waitFor(() => expect(detail).toHaveBeenLastCalledWith('persisted-run',
            expect.objectContaining({ source: 'epss', change_type: 'removal', offset: 0 }), expect.any(AbortSignal)));
        await selectSection('Overview');
        expect(within(screen.getByRole('table', { name: 'Distinct vulnerability counts' }))
            .getByRole('row', { name: 'Changed 1' })).toBeInTheDocument();
    });

    test('loads the selected project scope before offering its deliberately all-variant export', async () => {
        jest.spyOn(Projects, 'list').mockResolvedValue([{ id: 'project-a', name: 'Project A' }]);
        jest.spyOn(Variants, 'list').mockResolvedValue([
            { id: 'variant-a', name: 'alpha', project_id: 'project-a' },
            { id: 'variant-b', name: 'beta', project_id: 'project-a' },
        ]);
        show();

        await userEvent.click(screen.getByRole('button', { name: 'Export vulnerability history' }));
        expect(await screen.findByRole('heading', { name: 'Project scope' })).toBeInTheDocument();
        await waitFor(() => expect(Projects.list).toHaveBeenCalledWith());
        expect(await screen.findByText('Project A')).toBeInTheDocument();
        expect(await screen.findByRole('checkbox', { name: 'alpha' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'beta' })).toBeChecked();
        expect(screen.queryByRole('heading', { name: 'Export vulnerability history' })).not.toBeInTheDocument();
        expect(Variants.list).toHaveBeenCalledWith('project-a');
        const next = screen.getByRole('button', { name: 'Next' });
        expect(next).toBeEnabled();
        await userEvent.click(next);
        expect(await screen.findByRole('heading', { name: 'Export vulnerability history' })).toBeInTheDocument();
        expect(screen.queryByRole('radio', { name: /^Reports/i })).not.toBeInTheDocument();
    });

    test('keeps export disabled until the selected project and variants finish loading', async () => {
        let resolveProjects: (projects: { id: string; name: string }[]) => void = () => undefined;
        let resolveVariants: (variants: { id: string; name: string; project_id: string }[]) => void = () => undefined;
        jest.spyOn(Projects, 'list').mockImplementation(() => new Promise(resolve => { resolveProjects = resolve; }));
        jest.spyOn(Variants, 'list').mockImplementation(() => new Promise(resolve => { resolveVariants = resolve; }));
        const download = jest.spyOn(vulnerabilityHistory, 'downloadVulnerabilityHistory').mockResolvedValue();
        show();

        await userEvent.click(screen.getByRole('button', { name: 'Export vulnerability history' }));
        expect(await screen.findByText('Loading project and variant scope…')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
        expect(screen.queryByRole('button', { name: 'Download history' })).not.toBeInTheDocument();

        resolveProjects([{ id: 'project-a', name: 'Project A' }]);
        resolveVariants([{ id: 'variant-a', name: 'alpha', project_id: 'project-a' }]);
        expect(await screen.findByRole('checkbox', { name: 'alpha' })).toBeChecked();
        expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
        expect(download).not.toHaveBeenCalled();
    });

    test('does not request a global history export when no project is selected', async () => {
        const projects = jest.spyOn(Projects, 'list');
        const variants = jest.spyOn(Variants, 'list');
        const download = jest.spyOn(vulnerabilityHistory, 'downloadVulnerabilityHistory').mockResolvedValue();
        show('/refresh', {});

        await userEvent.click(screen.getByRole('button', { name: 'Export vulnerability history' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('No project is selected');
        expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
        expect(projects).not.toHaveBeenCalled();
        expect(variants).not.toHaveBeenCalled();
        expect(download).not.toHaveBeenCalled();
    });

    test.each([
        ['project', () => jest.spyOn(Projects, 'list').mockRejectedValueOnce(new Error('Project list unavailable'))],
        ['variant', () => jest.spyOn(Variants, 'list').mockRejectedValueOnce(new Error('Variant list unavailable'))],
    ])('fails closed and offers retry when the %s scope request fails', async (_label, failRequest) => {
        jest.spyOn(Projects, 'list').mockResolvedValue([{ id: 'project-a', name: 'Project A' }]);
        jest.spyOn(Variants, 'list').mockResolvedValue([
            { id: 'variant-a', name: 'alpha', project_id: 'project-a' },
        ]);
        failRequest();
        const download = jest.spyOn(vulnerabilityHistory, 'downloadVulnerabilityHistory').mockResolvedValue();
        show();

        await userEvent.click(screen.getByRole('button', { name: 'Export vulnerability history' }));
        expect(await screen.findByRole('alert')).toHaveTextContent(/unavailable/);
        expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
        expect(screen.queryByRole('button', { name: 'Download history' })).not.toBeInTheDocument();
        expect(download).not.toHaveBeenCalled();

        await userEvent.click(screen.getByRole('button', { name: 'Retry loading scope' }));
        expect(await screen.findByRole('checkbox', { name: 'alpha' })).toBeChecked();
        expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
    });

    test('distinguishes no refresh/no baseline from a successful zero-change run', async () => {
        latest.mockResolvedValue(null);
        list.mockResolvedValue({ runs: [], total: 0, limit: 20, offset: 0 });
        const view = show();
        expect(await screen.findByText('No refresh has been recorded in this scope. Run Refresh Vulnerability Data to begin.')).toBeInTheDocument();
        expect(screen.queryByText('No refresh runs in this scope.')).not.toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(detail).not.toHaveBeenCalled();
        view.unmount();
        latest.mockResolvedValue({ ...run, changes: [], total: 0, summary: { total_changes: 0, changed_vulnerabilities: 0, first_enrichments: 0 } });
        detail.mockResolvedValue({ ...run, changes: [], total: 0 });
        list.mockResolvedValue({ runs: [run], total: 1, limit: 20, offset: 0 });
        show();
        await openResult();
        expect(await screen.findByText('Refresh complete: zero changes. Checked data is unchanged.')).toBeInTheDocument();
    });

    test('shows first enrichment separately from modifications and renders long values', async () => {
        const enrichment = { ...run, summary: { ...run.summary, first_enrichments: 1 }, changes: [{
            ...run.changes[0], before: null, after: 'Long value '.repeat(1000), kind: 'first_enrichment', change_type: 'addition',
        }] };
        latest.mockResolvedValue(enrichment);
        detail.mockResolvedValue(enrichment);
        show();
        await openResult();
        expect(await screen.findByText(/No baseline exists for those fields/)).toBeInTheDocument();
        expect(await screen.findByText(/First enrichment \(addition\)/)).toBeInTheDocument();
        expect(screen.getByText('No value')).toBeInTheDocument();
        expect(screen.getByText(/Long value Long value/)).toHaveClass('max-h-48');
    });

    test('retains committed changes in partial/cancelled/failed runs and exposes gaps', async () => {
        const partial: RefreshRun = { ...run, status: 'incomplete', coverage: [
            ...run.coverage,
            { source: 'epss', vuln_id: 'CVE-2', status: 'cancelled', error: null },
            { source: 'nvd', vuln_id: 'CVE-3', status: 'failed', error: 'Provider unavailable' },
        ] };
        latest.mockResolvedValue(partial);
        detail.mockResolvedValue(partial);
        show();
        await openResult();
        expect(await screen.findByRole('alert')).toHaveTextContent('Incomplete refresh — cancelled coverage — source failures');
        expect(await screen.findByText('New description')).toBeInTheDocument();
        await selectSection('Coverage');
        expect(within(screen.getByRole('table', { name: 'Vulnerability coverage' }))
            .getByRole('row', { name: 'CVE-3 NVD failed Provider unavailable' })).toBeInTheDocument();
        expect(screen.queryByText(/Refresh complete: zero changes/)).not.toBeInTheDocument();
    });

    test('missing exact run never silently substitutes latest, and errors are explicit', async () => {
        detail.mockResolvedValue(null);
        const view = show('/refresh?run=expired');
        expect(await screen.findByText(/Requested refresh run is unavailable/)).toBeInTheDocument();
        expect(latest).not.toHaveBeenCalled();
        view.unmount();
        detail.mockRejectedValue(new Error('HTTP 500'));
        show('/refresh?run=failed');
        expect(await screen.findByRole('alert')).toHaveTextContent('HTTP 500');
    });

    test('opens a shared run link in a dismissible loading popup', async () => {
        detail.mockImplementation(() => new Promise(() => {}));
        show('/refresh?run=persisted-run');
        const popup = screen.getByRole('dialog', { name: 'Refresh Result' });
        expect(within(popup).getByRole('status')).toHaveTextContent('Loading refresh results');
        expect(screen.queryByText('Old description')).not.toBeInTheDocument();
        await userEvent.click(within(popup).getByRole('button', { name: 'Close' }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(detail.mock.calls[0][2].aborted).toBe(true);
    });

    test('keeps the coverage section selected when reloading popup results', async () => {
        show();
        await openResult();
        await selectSection('Coverage');
        await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Reload results' }));
        expect(await screen.findByRole('table', { name: 'Provider coverage' })).toBeInTheDocument();
        expect(within(screen.getByRole('navigation', { name: 'Refresh result sections' }))
            .getByRole('button', { name: /^Coverage/ })).toHaveAttribute('aria-pressed', 'true');
    });

    test('server-scoped shared CVE is shown in another visible variant and reload is read-only', async () => {
        show('/refresh?run=persisted-run', { projectId: 'project-a', variantId: 'variant-b' });
        expect(await screen.findByText('New description')).toBeInTheDocument();
        expect(detail).toHaveBeenCalledWith('persisted-run',
            { project_id: 'project-a', variant_id: 'variant-b' }, expect.any(AbortSignal));
        await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Reload results' }));
        await waitFor(() => expect(detail.mock.calls.filter(call => call[1].limit === undefined)).toHaveLength(2));
        expect(await screen.findByText('New description')).toBeInTheDocument();
    });

    test('paginates persisted runs without opening results or loading hidden changes', async () => {
        list.mockResolvedValue({ runs: [run], total: 21, limit: 20, offset: 0 });
        show();
        await userEvent.click(await screen.findByRole('button', { name: 'Next runs' }));
        await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20 }), expect.any(AbortSignal)));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(detail).not.toHaveBeenCalled();
    });

    test('run cards select the exact run without showing its internal ID', async () => {
        const older = { ...run, run_id: 'older-internal-id', sources: ['euvd'] };
        list.mockResolvedValue({ runs: [run, older], total: 2, limit: 20, offset: 0 });
        detail.mockImplementation(async (id: string) => id === older.run_id ? older : run);
        show();
        const entries = await screen.findByRole('list', { name: 'Refresh runs' });
        const olderCard = within(entries).getByRole('article', { name: /EUVD/ });
        await userEvent.click(within(olderCard).getByRole('button', { name: 'View Refresh Result' }));
        await waitFor(() => expect(detail).toHaveBeenCalledWith('older-internal-id',
            { project_id: 'project-a', variant_id: 'variant-a' }, expect.any(AbortSignal)));
        expect(await screen.findByRole('dialog', { name: 'Refresh Result' })).toBeInTheDocument();
        expect(screen.queryByText(/older-internal-id/)).not.toBeInTheDocument();
    });

    test('changing project resets timeline pagination instead of showing an empty later page', async () => {
        list.mockResolvedValue({ runs: [run], total: 21, limit: 20, offset: 0 });
        const view = show();
        await userEvent.click(await screen.findByRole('button', { name: 'Next runs' }));
        await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20 }), expect.any(AbortSignal)));
        view.rerender(<MemoryRouter><RefreshOverview projectId="fresh-project" /></MemoryRouter>);
        await waitFor(() => expect(list).toHaveBeenLastCalledWith(
            expect.objectContaining({ project_id: 'fresh-project', offset: 0 }), expect.any(AbortSignal)));
    });

    test.each([
        ['running', /Refresh in progress.*only committed changes/],
        ['incomplete', /Incomplete coverage.*inspect provider outcomes/],
    ] as const)('timeline cards make %s coverage explicit without opening details', async (status, message) => {
        list.mockResolvedValue({ runs: [{ ...run, status }], total: 1, limit: 20, offset: 0 });
        show();
        const card = await screen.findByRole('article');
        expect(within(card).getByText(message)).toBeInTheDocument();
    });

    test.each([
        ['variant', { projectId: 'project-a', variantId: 'variant-a' }, 'variant-a'],
        ['project', { projectId: 'project-a' }, undefined],
        ['comparison', { projectId: 'project-a', variantId: 'variant-a', baseVariantId: 'variant-b', compareOperation: 'union', comparisonScope: true }, undefined],
        ['variant subset', { projectId: 'project-a', variantId: 'variant-a', variantIds: ['variant-a', 'variant-b'], multiOperation: 'intersection', comparisonScope: true }, undefined],
    ])('starts refresh from the new tab with fresh %s scope data and completion updates', async (_label, scope, refreshVariant) => {
        const vulnerabilities = [{ id: 'CVE-old' }] as Vulnerability[];
        const fresh = [{ id: 'CVE-new' }, { id: 'GHSA-new' }] as Vulnerability[];
        const load = jest.spyOn(Vulnerabilities, 'list').mockResolvedValue(fresh);
        const enqueue = jest.spyOn(Operations, 'enqueue').mockResolvedValue({ ok: true, queueId: 'new-run', operations: [] });
        const complete = jest.fn();
        render(<MemoryRouter><RefreshOverview {...scope} vulnerabilities={vulnerabilities} onRefreshComplete={complete} /></MemoryRouter>);
        expect(screen.getByRole('heading', { name: 'Refresh History' }).closest('header'))
            .toContainElement(screen.getByTestId('refresh-dropdown-toggle'));
        await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        await userEvent.click(screen.getByRole('button', { name: 'Start' }));
        await waitFor(() => expect(enqueue).toHaveBeenCalled());
        expect(load).toHaveBeenCalledWith('variantId' in scope ? scope.variantId : undefined, 'project-a',
            'baseVariantId' in scope ? scope.baseVariantId : undefined,
            'compareOperation' in scope ? scope.compareOperation : undefined,
            'variantIds' in scope ? scope.variantIds : undefined,
            'multiOperation' in scope ? scope.multiOperation : undefined);
        expect(enqueue).toHaveBeenCalledWith(['nvd', 'epss', 'euvd'].map(source => ({
            kind: 'refresh', source, ids: ['CVE-new'],
            options: { mode: 'local', project_id: 'project-a', ...(refreshVariant ? { variant_id: refreshVariant } : {}) },
        })));
        await waitFor(() => expect(complete).toHaveBeenCalled());
        expect(screen.queryByRole('link', { name: 'View refresh changes' })).not.toBeInTheDocument();
    });

    test.each(['success', 'error'] as const)('places %s operation banners above Refresh History', async outcome => {
        const vulnerabilities = [{ id: 'CVE-1' }] as Vulnerability[];
        jest.spyOn(Vulnerabilities, 'list').mockResolvedValue(vulnerabilities);
        const message = outcome === 'success'
            ? 'Vulnerability data refresh added to the operation queue' : 'Unable to enqueue refresh';
        jest.spyOn(Operations, 'enqueue').mockResolvedValue(outcome === 'success'
            ? { ok: true, queueId: 'new-run', operations: [] } : { ok: false, error: message });
        (waitForQueue as jest.Mock).mockReturnValueOnce(new Promise(() => {}));
        render(<MemoryRouter><RefreshOverview projectId="project-a" vulnerabilities={vulnerabilities} /></MemoryRouter>);
        await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        await userEvent.click(screen.getByRole('button', { name: 'Start' }));
        const banner = await screen.findByRole('alert');
        expect(banner).toHaveTextContent(message);
        const header = screen.getByRole('heading', { name: 'Refresh History' }).closest('header');
        expect(header?.previousElementSibling).toBe(banner);
    });

    test('omits operation progress counters while preserving active-provider cancellation', async () => {
        const epss: Operation = {
            op_id: 'refresh:epss', kind: 'refresh', source: 'epss', label: 'EPSS',
            lane: 'pipeline', scope: null, status: 'running',
            progress: { current: 3300, total: 16145, message: 'Updating EPSS' },
            logs: [], error: null, queue_id: 'active-run', position: null, options: {}, cancellable: true,
            created_at: run.started_at, started_at: run.started_at, finished_at: null, result: null,
        };
        (getSnapshot as jest.Mock).mockReturnValue([
            epss,
            { ...epss, op_id: 'refresh:euvd', source: 'euvd', label: 'ENISA EUVD',
                status: 'queued', progress: { current: 0, total: 0, message: 'Queued' } },
        ]);
        (refreshProgressOf as jest.Mock).mockImplementation((source: string) => ({
            in_progress: true, phase: 'running', message: '',
            current: source === 'epss' ? 3300 : 0, total: source === 'epss' ? 16145 : 0,
        }));
        render(<MemoryRouter><RefreshOverview projectId="project-a"
            vulnerabilities={[{ id: 'CVE-1' }] as Vulnerability[]} /></MemoryRouter>);
        await screen.findByRole('list', { name: 'Refresh runs' });
        expect(screen.queryByText(/EPSS 3300\/16145|ENISA EUVD 0\/0/)).not.toBeInTheDocument();
        await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        expect(screen.getByTestId('cancel-epss-refresh')).toBeInTheDocument();
        expect(screen.getByTestId('cancel-euvd-refresh')).toBeInTheDocument();
    });

    test('has explicit run-list loading, empty and error states', async () => {
        list.mockImplementation(() => new Promise(() => {}));
        const view = show();
        expect(screen.getByText('Loading refresh runs…')).toBeInTheDocument();
        view.unmount();
        list.mockResolvedValue({ runs: [], total: 0, limit: 20, offset: 0 });
        latest.mockResolvedValue(null);
        const empty = show();
        expect(await screen.findByText(/No refresh has been recorded/)).toBeInTheDocument();
        empty.unmount();
        list.mockRejectedValue(new Error('Unable to load run list'));
        show();
        expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load run list');
        expect(screen.queryByText('Loading refresh runs…')).not.toBeInTheDocument();
    });

    test('never broadens unsupported comparison scopes into project requests', () => {
        render(<MemoryRouter><RefreshOverview projectId="project-a" comparisonScope /></MemoryRouter>);
        expect(screen.getByRole('alert')).toHaveTextContent('No broader scope has been loaded');
        expect(screen.queryByRole('button', { name: 'Export vulnerability history' })).not.toBeInTheDocument();
        expect(latest).not.toHaveBeenCalled();
        expect(list).not.toHaveBeenCalled();
        expect(detail).not.toHaveBeenCalled();
    });

    test('exposes source-level failures even with no CVE coverage or committed changes', async () => {
        const empty: RefreshRun = {
            ...run, status: 'incomplete', source_status: { nvd: 'incomplete', epss: 'complete' },
            coverage: [], changes: [], total: 0,
            summary: { total_changes: 0, changed_vulnerabilities: 0, first_enrichments: 0 },
        };
        latest.mockResolvedValue(empty);
        detail.mockResolvedValue(empty);
        show();
        await openResult();
        expect(await screen.findByText(/Coverage is incomplete\. Unchanged data cannot be concluded/)).toBeInTheDocument();
        await selectSection('Coverage');
        expect(await screen.findByText(/This source has incomplete coverage/)).toBeInTheDocument();
        expect(screen.queryByText(/Refresh complete: zero changes/)).not.toBeInTheDocument();
    });

    test.each(['button', 'Escape', 'backdrop'])('closes the result popup with %s and can reopen the same run', async method => {
        show();
        const popup = await openResult();
        expect(await within(popup).findByText('New description')).toBeInTheDocument();
        if (method === 'button') await userEvent.click(within(popup).getByRole('button', { name: 'Close' }));
        else if (method === 'Escape') await userEvent.keyboard('{Escape}');
        else await userEvent.click(screen.getByTestId('refresh-result-modal-backdrop'));
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
        expect(screen.queryByText('New description')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'View Refresh Result' })).toHaveFocus();
        await openResult();
        expect(await screen.findByText('New description')).toBeInTheDocument();
    });
});
