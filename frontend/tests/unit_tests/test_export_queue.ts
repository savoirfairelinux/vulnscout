import { waitFor } from '@testing-library/react';

import { queueExport } from '../../src/handlers/exportQueue';
import type { ExportRequest } from '../../src/handlers/exportQueue';
import {
    __reset,
    __setEventSourceFactory,
    getOperation,
    getSnapshot,
} from '../../src/handlers/operationStore';
import type { Operation } from '../../src/types/operation';

/** Stand-in for the browser EventSource so export progress can be driven directly. */
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
        (this.handlers.get(type) ?? []).forEach(handler => handler(event));
    }

    static latest(): FakeEventSource {
        return FakeEventSource.instances[FakeEventSource.instances.length - 1];
    }
}

const request: ExportRequest = {
    project_id: 'project-1',
    variant_ids: ['variant-1', 'variant-2'],
    mode: 'per_variant',
    documents: [
        { name: 'summary.adoc', extension: 'pdf' },
        { name: 'SPDX 2.3', extension: 'json' },
    ],
};

const exportOperation = (overrides: Partial<Operation> = {}): Operation => ({
    op_id: 'export-1',
    kind: 'export',
    source: 'documents',
    label: 'Demo Project export',
    lane: 'export',
    scope: null,
    status: 'running',
    progress: { current: 2, total: 4, message: 'Generating 2 of 4' },
    logs: ['second file'],
    error: null,
    queue_id: null,
    position: null,
    options: {},
    cancellable: false,
    created_at: '2026-08-19T10:00:00+00:00',
    started_at: '2026-08-19T10:00:00+00:00',
    finished_at: null,
    result: null,
    ...overrides,
});

function response({
    body = {},
    ok = true,
    status = 200,
    headers = {},
    blob = new Blob(['zip-content']),
}: {
    body?: unknown;
    ok?: boolean;
    status?: number;
    headers?: Record<string, string>;
    blob?: Blob;
} = {}): Response {
    return {
        ok,
        status,
        headers: new Headers(headers),
        json: jest.fn().mockResolvedValue(body),
        blob: jest.fn().mockResolvedValue(blob),
    } as unknown as Response;
}

describe('export queue', () => {
    let restoreFactory: () => void;
    let fetchSpy: jest.MockedFunction<typeof global.fetch>;

    beforeEach(() => {
        FakeEventSource.instances = [];
        restoreFactory = __setEventSourceFactory(url => new FakeEventSource(url) as unknown as EventSource);
        fetchSpy = jest.fn() as jest.MockedFunction<typeof global.fetch>;
        global.fetch = fetchSpy;
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: jest.fn(() => 'blob:export') });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: jest.fn() });
    });

    afterEach(() => {
        __reset();
        restoreFactory();
        jest.restoreAllMocks();
        delete (URL as Partial<typeof URL>).createObjectURL;
        delete (URL as Partial<typeof URL>).revokeObjectURL;
    });

    test('asks the backend to build the archive and waits for the operation it returns', async () => {
        fetchSpy.mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }));

        await queueExport(request, 'Demo Project');

        expect(fetchSpy).toHaveBeenCalledWith('http://localhost/api/documents/export', expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ ...request, async: true }),
        }));
        expect(FakeEventSource.instances).toHaveLength(1);
    });

    test('publishes export progress on the shared stream', async () => {
        fetchSpy.mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }));
        await queueExport(request, 'Demo Project');

        FakeEventSource.latest().send('snapshot', { seq: 1, operations: [exportOperation()] });

        expect(getSnapshot()).toHaveLength(1);
        expect(getOperation('export-1')).toMatchObject({
            status: 'running',
            progress: { current: 2, total: 4, message: 'Generating 2 of 4' },
            logs: ['second file'],
        });
    });

    test('downloads the archive under its server-provided name once the export completes', async () => {
        fetchSpy
            .mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }))
            .mockResolvedValueOnce(response({
                headers: { 'Content-Disposition': 'attachment; filename="project-files.zip"' },
            }));
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        const downloaded: string[] = [];
        click.mockImplementation(function (this: HTMLAnchorElement) { downloaded.push(this.download); });

        await queueExport(request, 'Demo Project');
        const stream = FakeEventSource.latest();
        stream.send('snapshot', { seq: 1, operations: [exportOperation()] });
        expect(click).not.toHaveBeenCalled();

        stream.send('operation', exportOperation({
            status: 'done',
            progress: { current: 4, total: 4, message: 'Export ready' },
            result: { download_ready: true },
        }));

        await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
        expect(fetchSpy).toHaveBeenLastCalledWith(
            'http://localhost/api/documents/export/export-1/download',
            { mode: 'cors' },
        );
        expect(downloaded).toEqual(['project-files.zip']);
        expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
        expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:export');
        expect(document.querySelector('a')).toBeNull();
    });

    test('names the archive after the project when the server does not', async () => {
        fetchSpy
            .mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }))
            .mockResolvedValueOnce(response());
        const downloaded: string[] = [];
        jest.spyOn(HTMLAnchorElement.prototype, 'click')
            .mockImplementation(function (this: HTMLAnchorElement) { downloaded.push(this.download); });

        await queueExport({ ...request, mode: 'consolidated' }, 'Demo Project');
        FakeEventSource.latest().send('snapshot', {
            seq: 1,
            operations: [exportOperation({ status: 'done' })],
        });

        await waitFor(() => expect(downloaded).toEqual(['Demo Project_consolidated_export.zip']));
    });

    test('rethrows the reason the backend refused to queue the export', async () => {
        fetchSpy.mockResolvedValueOnce(response({ body: { error: 'No export documents selected' }, ok: false, status: 400 }));

        await expect(queueExport(request, 'Demo Project')).rejects.toThrow('No export documents selected');
        expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    test('refuses an accepted response that carries no operation to follow', async () => {
        fetchSpy.mockResolvedValueOnce(response({ body: {}, status: 202 }));

        await expect(queueExport(request, 'Demo Project')).rejects.toThrow('Export failed (202)');
    });

    test('reports a failed download without breaking the caller', async () => {
        fetchSpy
            .mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }))
            .mockResolvedValueOnce(response({ ok: false, status: 503 }));
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});

        await expect(queueExport(request, 'Demo Project')).resolves.toBeUndefined();
        FakeEventSource.latest().send('snapshot', {
            seq: 1,
            operations: [exportOperation({ status: 'done' })],
        });

        await waitFor(() => expect(consoleError).toHaveBeenCalledWith(
            'Export download failed:',
            expect.objectContaining({ message: 'Failed to download export (503)' }),
        ));
        expect(click).not.toHaveBeenCalled();
    });

    test('downloads nothing when the export ends in failure', async () => {
        fetchSpy.mockResolvedValueOnce(response({ body: { op_id: 'export-1' }, status: 202 }));
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        await queueExport(request, 'Demo Project');
        FakeEventSource.latest().send('snapshot', {
            seq: 1,
            operations: [exportOperation({ status: 'error', error: 'renderer crashed' })],
        });

        await new Promise(resolve => setTimeout(resolve, 0));
        expect(click).not.toHaveBeenCalled();
        expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
});
