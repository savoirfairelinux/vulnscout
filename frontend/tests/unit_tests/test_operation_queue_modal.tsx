import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import OperationQueueModal from '../../src/components/OperationQueueModal';
import Operations from '../../src/handlers/operations';
import * as exportsClient from '../../src/handlers/exportQueue';
import { __reset, __setEventSourceFactory } from '../../src/handlers/operationStore';
import type { Operation } from '../../src/types/operation';

/** Stand-in for the browser EventSource so frames arrive deterministically. */
class FakeEventSource {
    static instances: FakeEventSource[] = [];

    readonly url: string;
    closed = false;
    onerror: (() => void) | null = null;
    private readonly handlers = new Map<string, Array<(event: MessageEvent) => void>>();

    constructor(url: string) {
        this.url = url;
        FakeEventSource.instances.push(this);
    }

    addEventListener(type: string, handler: (event: MessageEvent) => void) {
        const existing = this.handlers.get(type) ?? [];
        existing.push(handler);
        this.handlers.set(type, existing);
    }

    close() {
        this.closed = true;
    }

    send(type: string, data: unknown) {
        const event = { data: JSON.stringify(data) } as MessageEvent;
        act(() => {
            (this.handlers.get(type) ?? []).forEach(handler => handler(event));
        });
    }

    fail() {
        act(() => {
            this.onerror?.();
        });
    }

    static latest(): FakeEventSource {
        return FakeEventSource.instances[FakeEventSource.instances.length - 1];
    }
}

const operation = (overrides: Partial<Operation> & { op_id: string }): Operation => ({
    kind: 'scan',
    source: 'grype',
    label: 'Grype Scan',
    lane: 'pipeline',
    scope: null,
    status: 'queued',
    progress: { current: 0, total: 0, message: 'Queued' },
    logs: [],
    error: null,
    queue_id: null,
    position: null,
    options: {},
    cancellable: true,
    created_at: '2026-08-19T10:00:00+00:00',
    started_at: null,
    finished_at: null,
    result: null,
    ...overrides,
});

const completed = (opId: string, label: string, overrides: Partial<Operation> = {}): Operation => operation({
    op_id: opId,
    label,
    status: 'done',
    progress: { current: 1, total: 1, message: 'Complete' },
    ...overrides,
});

describe('OperationQueueModal', () => {
    let restoreFactory: () => void;

    beforeEach(() => {
        FakeEventSource.instances = [];
        restoreFactory = __setEventSourceFactory(url => new FakeEventSource(url) as unknown as EventSource);
    });

    afterEach(() => {
        __reset();
        restoreFactory();
        jest.restoreAllMocks();
    });

    /** Renders the modal and returns the stream it opened. */
    const renderModal = (onClose = jest.fn()) => {
        const view = render(<OperationQueueModal isOpen={true} onClose={onClose} />);
        return { ...view, stream: FakeEventSource.latest(), onClose };
    };

    it('closes from its close button, backdrop, and Escape key', () => {
        const onClose = jest.fn();
        const { rerender } = renderModal(onClose);

        expect(screen.getByRole('dialog', { name: 'Operation queue' })).toBeInTheDocument();
        expect(screen.getByText('This window can be safely closed. Track the operation queue in the navigation bar.')).toBeInTheDocument();
        expect(screen.getByText('No operations to display.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close operation queue' }));
        fireEvent.mouseDown(screen.getByTestId('modal-backdrop'));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(3);

        rerender(<OperationQueueModal isOpen={false} onClose={onClose} />);
        expect(screen.queryByRole('dialog', { name: 'Operation queue' })).not.toBeInTheDocument();
    });

    it('keeps legacy refresh operations without a batch ID independent', () => {
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [
                operation({
                    op_id: 'refresh:nvd', kind: 'refresh', source: 'nvd', label: 'NVD refresh',
                    logs: ['Waiting'], created_at: '2026-08-19T10:00:00+00:00',
                }),
                operation({
                    op_id: 'refresh:epss', kind: 'refresh', source: 'epss', label: 'EPSS refresh',
                    logs: ['Waiting'], created_at: '2026-08-19T10:00:01+00:00',
                }),
            ],
        });

        const nvdCollapse = screen.getByRole('button', { name: /nvd refresh.*queued/i });
        const epssCollapse = screen.getByRole('button', { name: /epss refresh.*queued/i });
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'false');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');

        fireEvent.click(nvdCollapse);
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'true');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');
    });

    it('shows an accepted refresh batch immediately and keeps its provider steps together', async () => {
        const epss = operation({
            op_id: 'refresh:epss', kind: 'refresh', source: 'epss', label: 'EPSS refresh',
            queue_id: 'q-refresh', position: 1,
        });
        const euvd = operation({
            op_id: 'refresh:euvd', kind: 'refresh', source: 'euvd', label: 'ENISA EUVD refresh',
            queue_id: 'q-refresh', position: 2,
        });
        jest.spyOn(global, 'fetch').mockResolvedValue({
            status: 202,
            json: async () => ({ queue_id: 'q-refresh', operations: [epss, euvd] }),
        } as Response);
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: [] });

        await act(async () => {
            await Operations.enqueue([
                Operations.refreshJob('epss', ['CVE-2024-1111']),
                Operations.refreshJob('euvd', ['CVE-2024-1111']),
            ]);
        });

        expect(screen.queryByText('No operations to display.')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /^Vulnerability data refresh queued \(0 of 2 steps\)/ }));
        expect(screen.getByRole('button', { name: /^EPSS refresh.*queued/ })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^ENISA EUVD refresh.*queued/ })).toBeInTheDocument();
        stream.send('operation', { ...epss, status: 'done' });
        stream.send('operation', { ...euvd, status: 'running' });
        expect(screen.getByRole('button', { name: /^Vulnerability data refresh in progress \(1 of 2 steps\)/ }))
            .toHaveAttribute('aria-expanded', 'true');
        stream.send('operation', { ...euvd, status: 'done' });
        expect(screen.getAllByRole('button', { name: /^Vulnerability data refresh / })).toHaveLength(1);
        expect(screen.getByRole('button', { name: /^Vulnerability data refresh complete \(2 of 2 steps\)/ }))
            .toBeInTheDocument();
    });

    it('dismisses finished operations through the operation API', () => {
        const dismiss = jest.spyOn(Operations, 'dismiss').mockResolvedValue(true);
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [
                completed('scan:grype:variant-1', 'Grype Scan', { created_at: '2026-08-19T10:00:00+00:00' }),
                completed('scan:nvd:variant-1', 'NVD Scan', { source: 'nvd', created_at: '2026-08-19T10:00:01+00:00' }),
                completed('scan:osv:variant-1', 'OSV Scan', { source: 'osv', created_at: '2026-08-19T10:00:02+00:00' }),
                completed('scan:scc:variant-1', 'SCC Scan', { source: 'scc', created_at: '2026-08-19T10:00:03+00:00' }),
                completed('refresh:epss', 'EPSS refresh', { kind: 'refresh', source: 'epss', created_at: '2026-08-19T10:00:04+00:00' }),
                completed('export:doc-1', 'Project export', { kind: 'export', source: 'documents', lane: 'export', created_at: '2026-08-19T10:00:05+00:00' }),
                completed('upload:sbom-1', 'SBOM import', { kind: 'upload', source: 'sbom', lane: 'upload', created_at: '2026-08-19T10:00:06+00:00' }),
            ],
        });

        screen.getAllByTitle('Close').forEach(button => fireEvent.click(button));

        expect(dismiss.mock.calls.map(([opId]) => opId)).toEqual([
            'scan:grype:variant-1',
            'scan:nvd:variant-1',
            'scan:osv:variant-1',
            'scan:scc:variant-1',
            'refresh:epss',
            'export:doc-1',
            'upload:sbom-1',
        ]);
    });

    it('cancels an operation that is still running', () => {
        const cancel = jest.spyOn(Operations, 'cancel').mockResolvedValue(true);
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [operation({
                op_id: 'scan:grype:variant-1',
                status: 'running',
                scope: { variant_id: 'variant-1', variant_name: 'Variant 1', project_id: 'project-1' },
                logs: ['Scanning'],
            })],
        });

        fireEvent.click(screen.getByRole('button', { name: 'Cancel Grype Scan – Variant 1' }));

        expect(cancel).toHaveBeenCalledWith('scan:grype:variant-1');
    });

    it('does not offer cancellation for unsupported running operations', () => {
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [
                operation({
                    op_id: 'upload:sbom-1', kind: 'upload', source: 'sbom', label: 'SBOM import',
                    lane: 'upload', status: 'running', cancellable: false,
                }),
                operation({
                    op_id: 'export:doc-1', kind: 'export', source: 'documents', label: 'Export docs',
                    lane: 'export', status: 'running', cancellable: false,
                }),
            ],
        });

        expect(screen.queryByRole('button', { name: /cancel sbom import/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /cancel export docs/i })).not.toBeInTheDocument();
    });

    const batch = (status: Operation['status'] = 'running') => [
        operation({
            op_id: 'scan:grype:variant-1', status: 'done', queue_id: 'q-1', position: 1,
            scope: { variant_id: 'variant-1', variant_name: 'alpha', project_id: 'project-1' },
            progress: { current: 4, total: 4, message: 'Scan complete' },
            logs: ['Scanned'], created_at: '2026-08-19T10:00:00+00:00',
        }),
        operation({
            op_id: 'scan:grype:variant-2', status, queue_id: 'q-1', position: 2,
            scope: { variant_id: 'variant-2', variant_name: 'hyper-v', project_id: 'project-1' },
            progress: { current: 1, total: 4, message: '1/4 Exporting CycloneDX' },
            logs: ['Scanning'], created_at: '2026-08-19T10:00:01+00:00',
        }),
        operation({
            op_id: 'refresh:epss', kind: 'refresh', source: 'epss', label: 'EPSS', queue_id: 'q-1', position: 3,
            status: status === 'running' ? 'queued' : status, created_at: '2026-08-19T10:00:02+00:00',
        }),
    ];

    const refreshBatch = (scope: Operation['scope'] = { project_id: 'project-1', variant_id: null }) => [
        operation({
            op_id: 'refresh:epss', kind: 'refresh', source: 'epss', label: 'EPSS refresh',
            queue_id: 'q-refresh', position: 1, scope, status: 'running',
            progress: { current: 1, total: 4, message: 'Updating scores' },
        }),
        operation({
            op_id: 'refresh:euvd', kind: 'refresh', source: 'euvd', label: 'ENISA EUVD refresh',
            queue_id: 'q-refresh', position: 2, scope,
        }),
    ];

    it('keeps one expandable refresh task as its EPSS and EUVD steps arrive', () => {
        const { stream } = renderModal();
        const [epss, euvd] = refreshBatch();
        stream.send('operation', epss);
        const parent = screen.getByRole('button', { name: /vulnerability data refresh in progress \(0 of 1 steps\)/i });
        expect(parent).toHaveAttribute('aria-expanded', 'false');
        expect(screen.queryByRole('button', { name: /^EPSS refresh/ })).not.toBeInTheDocument();

        fireEvent.click(parent);
        stream.send('operation', euvd);
        const expanded = screen.getByRole('button', { name: /vulnerability data refresh in progress \(0 of 2 steps\)/i });
        expect(expanded).toHaveAttribute('aria-expanded', 'true');
        expect(screen.getByRole('button', { name: /^EPSS refresh/ })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^ENISA EUVD refresh/ })).toBeInTheDocument();
    });

    it.each([
        ['global', { project_id: null, variant_id: null }],
        ['project', { project_id: 'project-1', variant_id: null }],
        ['variant', { project_id: 'project-1', variant_id: 'variant-1' }],
    ])('labels a %s refresh batch without requiring scan-specific variant names', (_name, scope) => {
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: refreshBatch(scope) });
        expect(screen.getByRole('button', { name: /vulnerability data refresh in progress \(0 of 2 steps\)/i }))
            .toBeInTheDocument();
        expect(screen.getByText(/EPSS refresh: Updating scores/)).toBeInTheDocument();
        expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
    });

    it('cancels a refresh batch or an individual provider and dismisses settled steps together', () => {
        const cancelQueue = jest.spyOn(Operations, 'cancelQueue').mockResolvedValue(true);
        const cancel = jest.spyOn(Operations, 'cancel').mockResolvedValue(true);
        const dismiss = jest.spyOn(Operations, 'dismiss').mockResolvedValue(true);
        const { stream } = renderModal();
        const steps = refreshBatch();
        stream.send('snapshot', { seq: 1, operations: steps });
        fireEvent.click(screen.getByRole('button', { name: /vulnerability data refresh in progress/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel EPSS refresh – EPSS refresh' }));
        expect(cancel).toHaveBeenCalledWith('refresh:epss');
        fireEvent.click(screen.getByRole('button', { name: 'Cancel Vulnerability data refresh' }));
        expect(cancelQueue).toHaveBeenCalledTimes(1);
        expect(cancelQueue).toHaveBeenCalledWith('q-refresh');
        expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument();

        steps.forEach(step => stream.send('operation', { ...step, status: 'cancelled' }));
        fireEvent.click(screen.getByRole('button', { name: 'Close Vulnerability data refresh' }));
        expect(dismiss.mock.calls.map(([opId]) => opId)).toEqual(['refresh:epss', 'refresh:euvd']);
    });

    it('collapses a multi-step batch into one run entry', () => {
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: batch() });

        const run = screen.getByRole('button', { name: /scan run – 2 variants in progress \(1 of 3 steps\)/i });
        expect(run).toHaveAttribute('aria-expanded', 'false');
        expect(screen.getByText(/grype scan – hyper-v: 1\/4 exporting cyclonedx \(42%\)/i)).toBeInTheDocument();
        expect(screen.queryByText('Scanning')).not.toBeInTheDocument();

        fireEvent.click(run);

        expect(screen.getByText(/grype scan – alpha complete/i)).toBeInTheDocument();
        expect(screen.getByText(/grype scan – hyper-v in progress/i)).toBeInTheDocument();
        expect(screen.getByText('Scanning')).toBeInTheDocument();
        expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
    });

    it('cancels a whole run once, and a single step on its own', () => {
        const cancelQueue = jest.spyOn(Operations, 'cancelQueue').mockResolvedValue(true);
        const cancel = jest.spyOn(Operations, 'cancel').mockResolvedValue(true);
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: batch() });
        fireEvent.click(screen.getByRole('button', { name: /scan run – 2 variants in progress/i }));

        fireEvent.click(screen.getByRole('button', { name: 'Cancel Grype Scan – hyper-v' }));
        expect(cancel).toHaveBeenCalledWith('scan:grype:variant-2');

        fireEvent.click(screen.getByRole('button', { name: 'Cancel Scan run – 2 variants' }));
        expect(cancelQueue).toHaveBeenCalledWith('q-1');
        expect(screen.queryByRole('button', { name: 'Cancel Scan run – 2 variants' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /cancel epss/i })).not.toBeInTheDocument();
    });

    it('offers the run cancellation again when the request is refused', async () => {
        jest.spyOn(Operations, 'cancelQueue').mockResolvedValue(false);
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: batch() });

        fireEvent.click(screen.getByRole('button', { name: 'Cancel Scan run – 2 variants' }));

        expect(await screen.findByRole('button', { name: 'Cancel Scan run – 2 variants' })).toBeInTheDocument();
    });

    it('reports the worst outcome of a finished run and dismisses every step', () => {
        const dismiss = jest.spyOn(Operations, 'dismiss').mockResolvedValue(true);
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: batch('error') });

        expect(screen.getByText(/scan run – 2 variants failed \(3 of 3 steps\)/i)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close Scan run – 2 variants' }));

        expect(dismiss.mock.calls.map(([opId]) => opId)).toEqual([
            'scan:grype:variant-1', 'scan:grype:variant-2', 'refresh:epss',
        ]);
    });

    it('names a refresh-only batch after its data refresh', () => {
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [
                completed('refresh:nvd', 'NVD', { kind: 'refresh', source: 'nvd', queue_id: 'q-2', position: 1 }),
                completed('refresh:epss', 'EPSS', { kind: 'refresh', source: 'epss', queue_id: 'q-2', position: 2 }),
            ],
        });

        expect(screen.getByText(/vulnerability data refresh complete \(2 of 2 steps\)/i)).toBeInTheDocument();
        expect(screen.getByLabelText('Complete')).toBeInTheDocument();
    });

    it('warns that it is reconnecting when the stream drops', () => {
        jest.useFakeTimers();
        try {
            const { stream } = renderModal();
            stream.send('snapshot', { seq: 1, operations: [] });
            expect(screen.queryByText(/reconnecting to the operation stream/i)).not.toBeInTheDocument();

            stream.fail();

            expect(screen.getByRole('status')).toHaveTextContent(/reconnecting to the operation stream/i);
        } finally {
            jest.useRealTimers();
        }
    });

    it('offers retained export downloads from a restored snapshot and reports expiry', async () => {
        const download = jest.spyOn(exportsClient, 'downloadExport').mockRejectedValue(new Error('Export archive is no longer available'));
        const { stream } = renderModal();
        stream.send('snapshot', { seq: 1, operations: [completed('export:1', 'Project export', {
            kind: 'export', source: 'documents', lane: 'export', result: { download_ready: true },
        })] });

        fireEvent.click(screen.getByRole('button', { name: 'Download Project export' }));
        expect(download).toHaveBeenCalledWith('export:1');
        expect(await screen.findByRole('alert')).toHaveTextContent('Export archive is no longer available');
    });
});
