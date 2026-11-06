import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import RefreshOverview from '../../src/pages/RefreshOverview';
import RefreshRuns from '../../src/handlers/refreshRuns';
import type { RefreshRun } from '../../src/handlers/refreshRuns';
import Vulnerabilities, { type Vulnerability } from '../../src/handlers/vulnerabilities';
import Operations from '../../src/handlers/operations';

jest.mock('../../src/handlers/operationStore', () => {
    const operations: never[] = [];
    return { subscribe: () => () => {}, getSnapshot: () => operations, waitForQueue: jest.fn(async () => []) };
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

describe('Refresh overview', () => {
    let detail: jest.SpyInstance;
    let latest: jest.SpyInstance;
    let list: jest.SpyInstance;
    beforeEach(() => {
        latest = jest.spyOn(RefreshRuns, 'latest').mockResolvedValue(run);
        detail = jest.spyOn(RefreshRuns, 'detail').mockResolvedValue(run);
        list = jest.spyOn(RefreshRuns, 'list').mockResolvedValue({ runs: [run], total: 1, limit: 20, offset: 0 });
    });
    afterEach(() => jest.restoreAllMocks());

    test('shows persisted metadata, distinct counts, scoped coverage and expandable before/after with links', async () => {
        show();
        await screen.findByText('Selected refresh');
        for (const id of ['persisted-run', 'project-a', 'variant-a', 'package-1']) {
            expect(screen.queryByText(new RegExp(id))).not.toBeInTheDocument();
        }
        expect(screen.getByText('Update vulnerability data and review what changed.')).toBeInTheDocument();
        const entries = screen.getByRole('list', { name: 'Refresh runs' });
        const entry = within(entries).getByRole('button');
        expect(entry).toHaveAttribute('aria-pressed', 'true');
        expect(entry).toHaveTextContent('NVD');
        expect(entry).toHaveTextContent('EPSS');
        expect(entry).toHaveTextContent('complete');
        expect(entry).toHaveTextContent('1 vulnerabilities changed');
        expect(entry.querySelector('time')).toHaveAttribute('dateTime', run.started_at);
        expect(latest).toHaveBeenCalledWith({ project_id: 'project-a', variant_id: 'variant-a' }, expect.any(AbortSignal));
        expect(list).toHaveBeenCalledWith(expect.objectContaining({ project_id: 'project-a', variant_id: 'variant-a' }), expect.any(AbortSignal));
        const counts = screen.getByLabelText('Distinct vulnerability counts');
        expect(counts).toHaveTextContent('Targeted: 2');
        expect(counts).toHaveTextContent('Checked: 1');
        expect(counts).toHaveTextContent('Changed: 1');
        expect(counts).toHaveTextContent('Skipped: 1');
        await userEvent.click(screen.getByText('Per-source coverage and gaps'));
        expect(screen.getByText('CVE-2: skipped — Not supported')).toBeInTheDocument();
        await userEvent.click(await screen.findByText('CVE-1 — 1 field changes on this page'));
        expect(screen.getByText('Old description')).toBeInTheDocument();
        expect(screen.getByText('New description')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Open CVE-1 vulnerability' })).toHaveAttribute('href', '/vulnerabilities');
        expect(screen.getByRole('link', { name: /openssl@3/ })).toHaveAttribute('href', '/vulnerabilities');
    });

    test('filters on the server before pagination and preserves scope on every request', async () => {
        detail.mockResolvedValue({ ...run, total: 26 });
        show();
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
        expect(screen.getByLabelText('Distinct vulnerability counts')).toHaveTextContent('Changed: 1');
    });

    test('distinguishes no refresh/no baseline from a successful zero-change run', async () => {
        latest.mockResolvedValue(null);
        const view = show();
        expect(await screen.findByText(/No refresh has been recorded.*No baseline/)).toBeInTheDocument();
        view.unmount();
        latest.mockResolvedValue({ ...run, changes: [], total: 0, summary: { total_changes: 0, changed_vulnerabilities: 0, first_enrichments: 0 } });
        detail.mockResolvedValue({ ...run, changes: [], total: 0 });
        show();
        expect(await screen.findByText('Refresh complete: zero changes. Checked data is unchanged.')).toBeInTheDocument();
    });

    test('shows first enrichment separately from modifications and renders long values', async () => {
        const enrichment = { ...run, summary: { ...run.summary, first_enrichments: 1 }, changes: [{
            ...run.changes[0], before: null, after: 'Long value '.repeat(1000), kind: 'first_enrichment', change_type: 'addition',
        }] };
        latest.mockResolvedValue(enrichment);
        detail.mockResolvedValue(enrichment);
        show();
        expect(await screen.findByText(/No baseline exists for those fields/)).toBeInTheDocument();
        expect(await screen.findByText(/First enrichment \(addition\)/)).toBeInTheDocument();
        expect(screen.getByText('No value')).toBeInTheDocument();
        expect(screen.getByText(/Long value Long value/)).toHaveClass('max-h-96');
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
        expect(await screen.findByRole('alert')).toHaveTextContent('Incomplete refresh — cancelled coverage — source failures');
        expect(await screen.findByText('New description')).toBeInTheDocument();
        expect(screen.getByText('CVE-3: failed — Provider unavailable')).toBeInTheDocument();
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

    test('server-scoped shared CVE is shown in another visible variant and reload is read-only', async () => {
        show('/refresh?run=persisted-run', { projectId: 'project-a', variantId: 'variant-b' });
        expect(await screen.findByText('New description')).toBeInTheDocument();
        expect(detail).toHaveBeenCalledWith('persisted-run',
            { project_id: 'project-a', variant_id: 'variant-b' }, expect.any(AbortSignal));
        await userEvent.click(screen.getByRole('button', { name: 'Reload results' }));
        await waitFor(() => expect(detail.mock.calls.filter(call => call[1].limit === undefined)).toHaveLength(2));
        expect(await screen.findByText('New description')).toBeInTheDocument();
    });

    test('paginates persisted runs without changing selected run', async () => {
        list.mockResolvedValue({ runs: [run], total: 21, limit: 20, offset: 0 });
        show();
        await userEvent.click(await screen.findByRole('button', { name: 'Next runs' }));
        await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20 }), expect.any(AbortSignal)));
        expect(within(screen.getByLabelText('Distinct vulnerability counts')).getByText('Changed:')).toBeInTheDocument();
    });

    test('run cards select the exact run without showing its internal ID', async () => {
        const older = { ...run, run_id: 'older-internal-id', sources: ['euvd'] };
        list.mockResolvedValue({ runs: [run, older], total: 2, limit: 20, offset: 0 });
        show();
        const entries = await screen.findByRole('list', { name: 'Refresh runs' });
        await userEvent.click(within(entries).getByRole('button', { name: /EUVD/ }));
        await waitFor(() => expect(detail).toHaveBeenCalledWith('older-internal-id',
            { project_id: 'project-a', variant_id: 'variant-a' }, expect.any(AbortSignal)));
        expect(screen.queryByText(/older-internal-id/)).not.toBeInTheDocument();
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
        expect(screen.getByRole('link', { name: 'View refresh changes' })).toHaveAttribute('href', '/refresh?run=new-run');
    });

    test('has explicit run-list loading, empty and error states', async () => {
        list.mockImplementation(() => new Promise(() => {}));
        const view = show();
        expect(screen.getByText('Loading refresh runs…')).toBeInTheDocument();
        view.unmount();
        list.mockResolvedValue({ runs: [], total: 0, limit: 20, offset: 0 });
        const empty = show();
        expect(await screen.findByText('No refresh runs in this scope.')).toBeInTheDocument();
        empty.unmount();
        list.mockRejectedValue(new Error('Unable to load run list'));
        show();
        expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load run list');
        expect(screen.queryByText('Loading refresh runs…')).not.toBeInTheDocument();
    });

    test('never broadens unsupported comparison scopes into project requests', () => {
        render(<MemoryRouter><RefreshOverview projectId="project-a" comparisonScope /></MemoryRouter>);
        expect(screen.getByRole('alert')).toHaveTextContent('No broader scope has been loaded');
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
        expect(await screen.findByText(/This source did not complete successfully/)).toBeInTheDocument();
        expect(await screen.findByText(/Coverage is incomplete; unchanged data cannot be concluded/)).toBeInTheDocument();
        expect(screen.queryByText(/Refresh complete: zero changes/)).not.toBeInTheDocument();
    });
});
