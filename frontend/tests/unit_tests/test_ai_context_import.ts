import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Context from '../../src/handlers/context';

beforeEach(() => fetchMock.resetMocks());

describe('AI draft handlers', () => {
    test('getAiDraft returns null on 404 and throws the server error otherwise', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'No draft.' }), { status: 404 });
        await expect(Context.getAiDraft('v1')).resolves.toBeNull();
        expect(fetchMock.mock.calls[0][0]).toContain('/api/variants/v1/context/draft');

        fetchMock.mockResponseOnce(JSON.stringify({ source: 'a.pdf', status: 'current' }));
        await expect(Context.getAiDraft('v1')).resolves.toMatchObject({ source: 'a.pdf' });

        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Boom' }), { status: 500 });
        await expect(Context.getAiDraft('v1')).rejects.toThrow('Boom');
    });

    test('deleteAiDraft ignores a missing draft and reports other failures', async () => {
        fetchMock.mockResponseOnce('', { status: 204 });
        await expect(Context.deleteAiDraft('v1')).resolves.toBeUndefined();
        expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: 'DELETE' });
        fetchMock.mockResponseOnce('', { status: 404 });
        await expect(Context.deleteAiDraft('v1')).resolves.toBeUndefined();
        fetchMock.mockResponseOnce('', { status: 500 });
        await expect(Context.deleteAiDraft('v1')).rejects.toThrow('Failed to discard the AI draft (500)');
    });

    test('uploadImportSource posts the file and explains a 413', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ name: 'report.pdf', size: 4 }), { status: 201 });
        const file = new File(['%PDF'], 'report.pdf');
        await expect(Context.uploadImportSource('v1', file)).resolves.toEqual({ name: 'report.pdf', size: 4 });
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toContain('/api/variants/v1/context/import-source');
        expect((init?.body as FormData).get('file')).toBeInstanceOf(File);

        fetchMock.mockResponseOnce('', { status: 413 });
        await expect(Context.uploadImportSource('v1', file)).rejects.toThrow('HTTP 413');
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Unsupported file.' }), { status: 400 });
        await expect(Context.uploadImportSource('v1', file)).rejects.toThrow('Unsupported file.');
    });
});
