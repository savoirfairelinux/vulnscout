import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';

import RefreshControls from '../../src/components/RefreshControls';
import Iso8601Duration from '../../src/handlers/iso8601duration';
import Operations from '../../src/handlers/operations';
import { __reset, __setEventSourceFactory } from '../../src/handlers/operationStore';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import VulnerabilityHistory from '../../src/handlers/vulnerabilityHistory';
import type { Operation } from '../../src/types/operation';

class RefreshEventSource {
    static current: RefreshEventSource;
    private handlers = new Map<string, EventListenerOrEventListenerObject>();

    constructor() { RefreshEventSource.current = this; }
    addEventListener(type: string, handler: EventListenerOrEventListenerObject) {
        this.handlers.set(type, handler);
    }
    close() {}
    send(type: string, data: unknown) {
        const event = new MessageEvent(type, { data: JSON.stringify(data) });
        const handler = this.handlers.get(type);
        act(() => {
            if (typeof handler === 'function') handler(event);
            else handler?.handleEvent(event);
        });
    }
}

const vulnerabilities: Vulnerability[] = [{
    id: 'CVE-2024-0001', aliases: [], related_vulnerabilities: [], namespace: 'nvd:cve',
    found_by: [], datasource: '', packages: [], packages_current: [], variants: [], urls: [], texts: [],
    severity: { severity: 'unknown', min_score: 0, max_score: 0, cvss: [] },
    epss: { score: undefined, percentile: undefined },
    effort: {
        optimistic: new Iso8601Duration(undefined),
        likely: new Iso8601Duration(undefined),
        pessimistic: new Iso8601Duration(undefined),
    },
    fix: { state: 'unknown' }, simplified_status: 'Pending Assessment', assessments: [],
}];

const operation = (source: string, overrides: Partial<Operation> = {}): Operation => ({
    op_id: `refresh:${source}`, kind: 'refresh', source, label: source.toUpperCase(),
    lane: 'pipeline', scope: null, status: 'queued',
    progress: { current: 0, total: 10, message: 'Queued' }, logs: [], error: null,
    queue_id: 'current-batch', position: null, options: {}, cancellable: true,
    created_at: '2026-06-10T10:00:00Z', started_at: '2026-06-10T10:00:00Z',
    finished_at: null, result: null, ...overrides,
});

describe('Refresh controls batch lifecycle', () => {
    let restoreStream: () => void;

    beforeEach(() => {
        restoreStream = __setEventSourceFactory(() => new RefreshEventSource() as unknown as EventSource);
    });
    afterEach(() => {
        __reset();
        restoreStream();
        jest.restoreAllMocks();
    });

    test.each(['done', 'error', 'cancelled'] as const)('reloads once after every provider settles, including %s outcomes', async status => {
        const complete = jest.fn();
        const accepted = ['nvd', 'epss', 'euvd'].map(source => operation(source));
        jest.spyOn(Operations, 'enqueue').mockResolvedValue({
            ok: true, queueId: 'current-batch', operations: accepted,
        });
        const cancel = jest.spyOn(Operations, 'cancel').mockResolvedValue(true);
        const summary = jest.spyOn(VulnerabilityHistory, 'changesSince').mockResolvedValue({
            since: accepted[0].started_at!, total: 1, vulnerabilities: 1, fields: { epss_score: 1 },
        });
        const fetch = jest.spyOn(globalThis, 'fetch');
        render(<MemoryRouter><RefreshControls vulnerabilities={vulnerabilities}
            getRefreshVulnerabilities={async () => vulnerabilities} onRefreshComplete={complete} /></MemoryRouter>);
        await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        await userEvent.click(screen.getByRole('button', { name: 'Start' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('added to the operation queue');
        const stream = RefreshEventSource.current;
        stream.send('snapshot', { seq: 1, operations: accepted });
        stream.send('operation', operation('nvd', {
            status: 'running', progress: { current: 5, total: 10, message: 'Updating NVD' },
        }));
        expect(screen.queryByRole('status')).not.toBeInTheDocument();
        expect(screen.queryByText(/NVD 5\/10/)).not.toBeInTheDocument();
        await userEvent.click(screen.getByTestId('refresh-dropdown-toggle'));
        expect(screen.getByTestId('cancel-nvd-refresh')).toBeInTheDocument();
        if (status === 'cancelled') {
            await userEvent.click(screen.getByTestId('cancel-nvd-refresh'));
            expect(cancel).toHaveBeenCalledWith('refresh:nvd');
            expect(await screen.findByRole('alert')).toHaveTextContent('cancellation requested');
        }
        const nvd = operation('nvd', { status, error: status === 'error' ? 'Provider unavailable' : null });
        const epss = operation('epss', { status: 'done' });
        const euvd = operation('euvd', { status: 'done' });
        stream.send('operation', nvd);
        stream.send('operation', epss);
        expect(complete).not.toHaveBeenCalled();
        expect(summary).not.toHaveBeenCalled();
        stream.send('operation', euvd);
        await waitFor(() => expect(complete).toHaveBeenCalledTimes(1));
        if (status === 'done') {
            expect(summary).toHaveBeenCalledWith(accepted[0].started_at, ['nvd', 'epss', 'euvd'],
                'current-batch', accepted.map(item => item.op_id));
            expect(await screen.findByRole('alert')).toHaveTextContent('Refresh complete: 1 value changed');
        } else {
            expect(summary).not.toHaveBeenCalled();
            expect(await screen.findByRole('alert')).toHaveTextContent(`partially completed: nvd ${status}`);
            if (status === 'error') expect(screen.getByRole('alert')).toHaveTextContent('Provider unavailable');
        }
        await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        stream.send('snapshot', { seq: 2, operations: [nvd, epss, euvd] });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(complete).toHaveBeenCalledTimes(1);
        expect(fetch).not.toHaveBeenCalled();
    });

    test('does not announce or reload previously settled providers without a new launch', () => {
        const complete = jest.fn();
        render(<MemoryRouter><RefreshControls vulnerabilities={vulnerabilities}
            getRefreshVulnerabilities={async () => vulnerabilities} onRefreshComplete={complete} /></MemoryRouter>);
        RefreshEventSource.current.send('snapshot', {
            seq: 1,
            operations: [
                operation('nvd', { status: 'done' }),
                operation('epss', { status: 'cancelled' }),
                operation('euvd', { status: 'error' }),
            ],
        });
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(complete).not.toHaveBeenCalled();
    });
});
