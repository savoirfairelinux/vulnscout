/**
 * Tests for Projects and Variants handler methods added for the Settings feature:
 * - Projects.rename, create, delete
 * - Variants.rename, create, delete, uploadSBOM, getUploadStatus
 */
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Projects from '../../src/handlers/project';
import Variants from '../../src/handlers/variant';


// ---------------------------------------------------------------------------
// Projects.rename
// ---------------------------------------------------------------------------

describe('Projects.rename', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends PATCH with new name and returns updated project', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'p1', name: 'NewName' }));

        const result = await Projects.rename('p1', 'NewName');

        expect(result).toEqual({ id: 'p1', name: 'NewName' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects/p1/rename'),
            expect.objectContaining({
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: 'NewName' }),
            })
        );
    });

    test('encodes project id in URL', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'a b', name: 'X' }));

        await Projects.rename('a b', 'X');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('a%20b'),
            expect.anything()
        );
    });

    test('throws on error response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Conflict' }), { status: 409 });

        await expect(Projects.rename('p1', 'Dup')).rejects.toThrow('Conflict');
    });

    test('throws generic message when body has no error field', async () => {
        fetchMock.mockResponseOnce('', { status: 500 });

        await expect(Projects.rename('p1', 'X')).rejects.toThrow('Rename failed (500)');
    });
});


// ---------------------------------------------------------------------------
// Projects.create
// ---------------------------------------------------------------------------

describe('Projects.create', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends POST and returns created project', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'p2', name: 'Created' }));

        const result = await Projects.create('Created');

        expect(result).toEqual({ id: 'p2', name: 'Created' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects'),
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ name: 'Created' }),
            })
        );
    });

    test('throws on duplicate name', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'already exists' }), { status: 409 });

        await expect(Projects.create('Dup')).rejects.toThrow('already exists');
    });
});


// ---------------------------------------------------------------------------
// Projects.delete
// ---------------------------------------------------------------------------

describe('Projects.delete', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends DELETE request', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ message: 'deleted' }));

        await Projects.delete('p1');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects/p1'),
            expect.objectContaining({ method: 'DELETE' })
        );
    });

    test('encodes project id in URL', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ message: 'ok' }));

        await Projects.delete('a b');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('a%20b'),
            expect.anything()
        );
    });

    test('throws on 404', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Not found' }), { status: 404 });

        await expect(Projects.delete('missing')).rejects.toThrow('Not found');
    });
});


// ---------------------------------------------------------------------------
// Variants.rename
// ---------------------------------------------------------------------------

describe('Variants.rename', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends PATCH with new name and returns updated variant', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'v1', name: 'NewVar', project_id: 'p1' }));

        const result = await Variants.rename('v1', 'NewVar');

        expect(result).toEqual({ id: 'v1', name: 'NewVar', project_id: 'p1' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/rename'),
            expect.objectContaining({
                method: 'PATCH',
                body: JSON.stringify({ name: 'NewVar' }),
            })
        );
    });

    test('throws on error response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Duplicate' }), { status: 409 });

        await expect(Variants.rename('v1', 'Dup')).rejects.toThrow('Duplicate');
    });
});


// ---------------------------------------------------------------------------
// Variants.create
// ---------------------------------------------------------------------------

describe('Variants.create', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends POST to project variants endpoint', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'v2', name: 'release', project_id: 'p1' }));

        const result = await Variants.create('p1', 'release');

        expect(result).toEqual({ id: 'v2', name: 'release', project_id: 'p1' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects/p1/variants'),
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ name: 'release' }),
            })
        );
    });

    test('encodes project id in URL', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'v1', name: 'x', project_id: 'a b' }));

        await Variants.create('a b', 'x');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('a%20b'),
            expect.anything()
        );
    });

    test('throws on error response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'exists' }), { status: 409 });

        await expect(Variants.create('p1', 'Dup')).rejects.toThrow('exists');
    });
});


// ---------------------------------------------------------------------------
// Variants.delete
// ---------------------------------------------------------------------------

describe('Variants.delete', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends DELETE request for the variant', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ message: 'ok' }));

        await Variants.delete('v1');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1'),
            expect.objectContaining({ method: 'DELETE' })
        );
    });

    test('throws on 404', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Not found' }), { status: 404 });

        await expect(Variants.delete('missing')).rejects.toThrow('Not found');
    });
});


// ---------------------------------------------------------------------------
// Variants.uploadSBOM (multi-file)
// ---------------------------------------------------------------------------

describe('Variants.uploadSBOM', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('sends POST with files array in FormData', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            upload_id: 'uid-1',
            scan_id: 'sid-1',
            message: 'accepted',
        }));

        const file1 = new File(['{"spdxVersion":"SPDX-2.3"}'], 'sbom1.spdx.json', { type: 'application/json' });
        const file2 = new File(['{"spdxVersion":"SPDX-2.3"}'], 'sbom2.spdx.json', { type: 'application/json' });

        const result = await Variants.uploadSBOM('p1', 'v1', [file1, file2]);

        expect(result.upload_id).toBe('uid-1');
        expect(result.scan_id).toBe('sid-1');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/sbom/upload'),
            expect.objectContaining({ method: 'POST' })
        );

        // Verify FormData contents
        const calledBody = (fetchMock.mock.calls[0] as any[])[1].body as FormData;
        expect(calledBody.get('project_id')).toBe('p1');
        expect(calledBody.get('variant_id')).toBe('v1');
        const files = calledBody.getAll('files');
        expect(files).toHaveLength(2);
    });

    test('sends single file correctly', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            upload_id: 'uid-2',
            scan_id: 'sid-2',
            message: 'accepted',
        }));

        const file = new File(['{}'], 'sbom.json', { type: 'application/json' });
        const result = await Variants.uploadSBOM('p1', 'v1', [file]);

        expect(result.upload_id).toBe('uid-2');
        const calledBody = (fetchMock.mock.calls[0] as any[])[1].body as FormData;
        const files = calledBody.getAll('files');
        expect(files).toHaveLength(1);
    });

    test('throws on error response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'No file' }), { status: 400 });

        const file = new File(['{}'], 'test.json');
        await expect(Variants.uploadSBOM('p1', 'v1', [file])).rejects.toThrow('No file');
    });

    test('throws generic message on unexpected error', async () => {
        fetchMock.mockResponseOnce('', { status: 500 });

        const file = new File(['{}'], 'test.json');
        await expect(Variants.uploadSBOM('p1', 'v1', [file])).rejects.toThrow('Upload failed (500)');
    });
});


// ---------------------------------------------------------------------------
// Variants.getUploadStatus
// ---------------------------------------------------------------------------

describe('Variants.getUploadStatus', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('returns status from server', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'done', message: 'SBOM imported.' }));

        const result = await Variants.getUploadStatus('uid-1');

        expect(result).toEqual({ status: 'done', message: 'SBOM imported.' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/sbom/upload/uid-1/status'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns processing status', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'processing', message: 'Parsing...' }));

        const result = await Variants.getUploadStatus('uid-2');

        expect(result.status).toBe('processing');
        expect(result.message).toBe('Parsing...');
    });

    test('returns error on failed fetch', async () => {
        fetchMock.mockResponseOnce('', { status: 404 });

        const result = await Variants.getUploadStatus('bad-id');

        expect(result.status).toBe('error');
        expect(result.message).toContain('Failed to check');
    });

    test('encodes upload id in URL', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'done', message: 'ok' }));

        await Variants.getUploadStatus('id with spaces');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('id%20with%20spaces'),
            expect.anything()
        );
    });
});
