import type { ExportRequest } from '../../src/handlers/exportQueue';

const request: ExportRequest = {
    project_id: 'project-1',
    variant_ids: ['variant-1', 'variant-2'],
    mode: 'per_variant',
    documents: [
        { name: 'summary.adoc', extension: 'pdf' },
        { name: 'SPDX 2.3', extension: 'json' },
    ],
};

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
    beforeEach(() => {
        jest.resetModules();
        jest.useFakeTimers();
        global.fetch = jest.fn();
    });

    afterEach(() => {
        jest.useRealTimers();
        jest.restoreAllMocks();
        delete (URL as Partial<typeof URL>).createObjectURL;
        delete (URL as Partial<typeof URL>).revokeObjectURL;
    });

    test('publishes progress, downloads the completed archive, and dismisses it', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(response({ body: { job_id: 'job-1' }, status: 202 }))
            .mockResolvedValueOnce(response({ body: {
                status: 'running', current: 2, total: 4, progress: 'Generating 2 of 4', logs: ['second file'], error: null,
            } }))
            .mockResolvedValueOnce(response({ body: {
                status: 'done', current: 4, total: 4, progress: 'Export ready', logs: ['complete'], error: null,
            } }))
            .mockResolvedValueOnce(response({
                headers: { 'Content-Disposition': 'attachment; filename="project-files.zip"' },
            }));
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: jest.fn(() => 'blob:export') });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: jest.fn() });
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        const queue = await import('../../src/handlers/exportQueue');
        const listener = jest.fn();
        const unsubscribe = queue.subscribe(listener);

        await queue.queueExport(request, 'Demo Project');
        await jest.advanceTimersByTimeAsync(0);

        expect(queue.getSnapshot()).toEqual([expect.objectContaining({
            status: 'running',
            progress: 'Generating 2 of 4',
            total: 4,
            doneCount: 1,
        })]);
        queue.dismiss('export-1');
        expect(queue.getSnapshot()).toHaveLength(1);

        await jest.advanceTimersByTimeAsync(1000);

        expect(queue.getSnapshot()).toEqual([expect.objectContaining({
            status: 'done',
            progress: 'Export ready',
            doneCount: 4,
        })]);
        expect(click).toHaveBeenCalledTimes(1);
        expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
        expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:export');
        expect(document.querySelector('a')).toBeNull();

        queue.dismiss('export-1');
        expect(queue.getSnapshot()).toEqual([]);
        expect(listener).toHaveBeenCalled();
        unsubscribe();
    });

    test('records and rethrows an error when the export cannot be queued', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch.mockResolvedValueOnce(response({ body: { error: 'No export documents selected' }, ok: false, status: 400 }));
        const queue = await import('../../src/handlers/exportQueue');

        await expect(queue.queueExport(request, 'Demo Project')).rejects.toThrow('No export documents selected');

        expect(queue.getSnapshot()).toEqual([expect.objectContaining({
            status: 'error',
            error: 'No export documents selected',
            progress: 'Export failed',
            logs: ['No export documents selected'],
        })]);
        expect(fetch).toHaveBeenCalledWith('http://localhost/api/documents/export', expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ ...request, async: true }),
        }));
    });

    test('records polling and download failures without rejecting queue creation', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(response({ body: { job_id: 'job-2' }, status: 202 }))
            .mockResolvedValueOnce(response({ body: {
                status: 'done', current: 4, total: 4, progress: 'Export ready', logs: [], error: null,
            } }))
            .mockResolvedValueOnce(response({ ok: false, status: 503 }));
        for (let attempt = 0; attempt < 3; attempt += 1) {
            fetch
                .mockResolvedValueOnce(response({ body: {
                    status: 'done', current: 4, total: 4, progress: 'Export ready', logs: [], error: null,
                } }))
                .mockResolvedValueOnce(response({ ok: false, status: 503 }));
        }
        const queue = await import('../../src/handlers/exportQueue');

        await expect(queue.queueExport(request, 'Demo Project')).resolves.toBeUndefined();
        await jest.advanceTimersByTimeAsync(0);
        await jest.advanceTimersByTimeAsync(3000);

        expect(queue.getSnapshot()).toEqual([expect.objectContaining({
            status: 'error',
            error: 'Failed to download export (503)',
            logs: ['Failed to download export (503)'],
        })]);
        queue.dismiss('missing-operation');
        expect(queue.getSnapshot()).toHaveLength(1);
    });

    test('recovers after a transient polling failure', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(response({ body: { job_id: 'job-3' }, status: 202 }))
            .mockResolvedValueOnce(response({ ok: false, status: 503 }))
            .mockResolvedValueOnce(response({ body: {
                status: 'done', current: 4, total: 4, progress: 'Export ready', logs: [], error: null,
            } }))
            .mockResolvedValueOnce(response());
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: jest.fn(() => 'blob:export') });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: jest.fn() });
        jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        const queue = await import('../../src/handlers/exportQueue');

        await queue.queueExport(request, 'Demo Project');
        await jest.advanceTimersByTimeAsync(0);
        expect(queue.getSnapshot()).toEqual([expect.objectContaining({
            status: 'running', progress: 'Reconnecting to export',
        })]);

        await jest.advanceTimersByTimeAsync(1000);
        expect(queue.getSnapshot()).toEqual([expect.objectContaining({ status: 'done' })]);
    });
});