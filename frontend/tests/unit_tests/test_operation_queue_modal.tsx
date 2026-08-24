import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import OperationQueueModal from '../../src/components/OperationQueueModal';
import Operations from '../../src/handlers/operations';
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
        fireEvent.mouseDown(screen.getByRole('dialog', { name: 'Operation queue' }));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(3);

        rerender(<OperationQueueModal isOpen={false} onClose={onClose} />);
        expect(screen.queryByRole('dialog', { name: 'Operation queue' })).not.toBeInTheDocument();
    });

    it('renders each vulnerability refresh source as an independent collapse', () => {
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

    it('numbers the variants of a multi-variant scan batch', () => {
        const { stream } = renderModal();
        stream.send('snapshot', {
            seq: 1,
            operations: [
                operation({
                    op_id: 'scan:grype:variant-1', status: 'running', queue_id: 'q-1',
                    scope: { variant_id: 'variant-1', variant_name: 'alpha', project_id: 'project-1' },
                    logs: ['Scanning'], created_at: '2026-08-19T10:00:00+00:00',
                }),
                operation({
                    op_id: 'scan:grype:variant-2', status: 'running', queue_id: 'q-1',
                    scope: { variant_id: 'variant-2', variant_name: 'hyper-v', project_id: 'project-1' },
                    logs: ['Scanning'], created_at: '2026-08-19T10:00:01+00:00',
                }),
                operation({
                    op_id: 'scan:nvd:variant-1', source: 'nvd', label: 'NVD Scan', status: 'running', queue_id: 'q-1',
                    scope: { variant_id: 'variant-1', variant_name: 'alpha', project_id: 'project-1' },
                    logs: ['Scanning'], created_at: '2026-08-19T10:00:02+00:00',
                }),
            ],
        });

        expect(screen.getByText(/grype scan – hyper-v in progress \(variant 2 of 2\)/i)).toBeInTheDocument();
        expect(screen.getByText(/nvd scan – alpha in progress/i)).toBeInTheDocument();
        expect(screen.queryByText(/nvd scan – alpha in progress \(variant/i)).not.toBeInTheDocument();
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
});
