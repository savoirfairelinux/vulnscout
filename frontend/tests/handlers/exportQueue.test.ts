import { waitFor } from '@testing-library/react';
import { downloadExport, queueExport } from '../../src/handlers/exportQueue';
import { __reset, __setEventSourceFactory } from '../../src/handlers/operationStore';
import type { ExportRequest } from '../../src/handlers/exportQueue';

const request: ExportRequest = {
    project_id: 'project-1', variant_ids: ['variant-1'], mode: 'per_variant',
    documents: [{ name: 'summary.adoc', extension: 'pdf' }],
};

class TestEventSource {
    static current: TestEventSource;
    private handlers = new Map<string, (event: MessageEvent) => void>();
    constructor() { TestEventSource.current = this; }
    addEventListener(type: string, handler: EventListenerOrEventListenerObject) {
        this.handlers.set(type, handler as (event: MessageEvent) => void);
    }
    close() {}
    send(type: string, data: unknown) {
        this.handlers.get(type)?.({ data: JSON.stringify(data), lastEventId: 'epoch:1' } as MessageEvent);
    }
}

function response(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
    return {
        ok: status < 400, status, headers: new Headers(headers),
        json: async () => body, blob: async () => new Blob(['archive']),
    } as Response;
}

describe('SSE export downloads', () => {
    let restoreStream: () => void;
    let fetchCall: jest.Mock;

    beforeEach(() => {
        restoreStream = __setEventSourceFactory(() => new TestEventSource() as unknown as EventSource);
        fetchCall = jest.fn();
        global.fetch = fetchCall as typeof fetch;
    });

    afterEach(() => {
        __reset();
        restoreStream();
        jest.restoreAllMocks();
        delete (URL as Partial<typeof URL>).createObjectURL;
        delete (URL as Partial<typeof URL>).revokeObjectURL;
    });

    it('downloads a completed operation once without requesting a removed status route', async () => {
        fetchCall.mockResolvedValueOnce(response({ op_id: 'export:job-1' }, 202))
            .mockResolvedValueOnce(response({}, 200, { 'Content-Disposition': 'attachment; filename="project-files.zip"' }));
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: jest.fn(() => 'blob:export') });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: jest.fn() });
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        await queueExport(request, 'Demo Project');
        TestEventSource.current.send('operation', { op_id: 'export:job-1', status: 'done' });
        TestEventSource.current.send('operation', { op_id: 'export:job-1', status: 'done' });

        await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
        expect(fetchCall.mock.calls.map(([url]) => url)).toEqual([
            'http://localhost/api/documents/export',
            'http://localhost/api/documents/export/export%3Ajob-1/download',
        ]);
        expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:export');
    });

    it('rejects a failed submission with the server error', async () => {
        fetchCall.mockResolvedValueOnce(response({ error: 'Invalid export' }, 400));
        await expect(queueExport(request, 'Demo Project')).rejects.toThrow('Invalid export');
        expect(fetchCall).toHaveBeenCalledTimes(1);
    });

    it('reports an expired retained archive to the caller', async () => {
        fetchCall.mockResolvedValueOnce(response({ error: 'Export archive is no longer available' }, 410));
        await expect(downloadExport('export:job-1')).rejects.toThrow('Export archive is no longer available');
    });
});