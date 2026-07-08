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

    test('throws generic message when rename error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 502,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Projects.rename('p1', 'Broken')).rejects.toThrow('Rename failed (502)');
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

    test('throws generic message when error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 500,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Projects.create('Broken')).rejects.toThrow('Create failed (500)');
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

    test('throws generic message when delete error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 502,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Projects.delete('broken')).rejects.toThrow('Delete failed (502)');
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

    test('throws generic message when create error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 503,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Variants.create('p1', 'release')).rejects.toThrow('Create failed (503)');
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

    test('throws generic message when delete error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 500,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Variants.delete('broken')).rejects.toThrow('Delete failed (500)');
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

    test('throws generic message when upload error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 503,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        const file = new File(['{}'], 'test.json');
        await expect(Variants.uploadSBOM('p1', 'v1', [file])).rejects.toThrow('Upload failed (503)');
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


// ---------------------------------------------------------------------------
// Variants.copyAssessments
// ---------------------------------------------------------------------------

describe('Variants.copyAssessments', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('copies assessments from source to target variant', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            copied: 5,
            skipped: 2,
            message: 'Copied 5 assessments.',
        }));

        const result = await Variants.copyAssessments('source-v1', 'target-v2');

        expect(result.copied).toBe(5);
        expect(result.skipped).toBe(2);
        expect(result.message).toBe('Copied 5 assessments.');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/copy-assessments'),
            expect.objectContaining({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_variant_id: 'source-v1',
                    target_variant_id: 'target-v2',
                    match_mode: 'exact',
                    version_precision: 1,
                }),
            })
        );
    });

    test('sends version_precision for ignore_minor_version mode', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ copied: 1, skipped: 0, message: 'ok' }));

        await Variants.copyAssessments('src', 'tgt', 'ignore_minor_version', 2);

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect(body.match_mode).toBe('ignore_minor_version');
        expect(body.version_precision).toBe(2);
    });

    test('omits selections when not provided', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ copied: 0, skipped: 0, message: 'ok' }));

        await Variants.copyAssessments('src', 'tgt', 'ignore_version', 1);

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect('selections' in body).toBe(false);
    });

    test('includes selections array when provided', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ copied: 2, skipped: 0, message: 'ok' }));

        const selections = [
            { source_assessment_id: 'a1', target_finding_id: 'tf1' },
            { source_assessment_id: 'a2', target_finding_id: 'tf2' },
        ];
        await Variants.copyAssessments('src', 'tgt', 'ignore_version', 1, selections);

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect(body.selections).toEqual(selections);
        expect(body.match_mode).toBe('ignore_version');
    });

    test('includes an empty selections array when explicitly passed', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ copied: 0, skipped: 0, message: 'ok' }));

        await Variants.copyAssessments('src', 'tgt', 'ignore_version', 1, []);

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect(body.selections).toEqual([]);
    });

    test('throws on error response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Not found' }), { status: 404 });

        await expect(Variants.copyAssessments('src', 'tgt')).rejects.toThrow('Not found');
    });

    test('throws generic message when error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 500,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Variants.copyAssessments('src', 'tgt')).rejects.toThrow('Copy failed (500)');
    });
});


// ---------------------------------------------------------------------------
// Variants.previewCopyAssessments
// ---------------------------------------------------------------------------

describe('Variants.previewCopyAssessments', () => {
    beforeEach(() => { fetchMock.resetMocks(); });

    test('returns preview data on success', async () => {
        const previewData = {
            count: 3,
            skipped: 1,
            message: 'Preview ready.',
            entries: [
                {
                    source_assessment_id: 'a1',
                    source_finding_id: 'f1',
                    target_finding_id: 'f2',
                    vulnerability_id: 'CVE-2023-1234',
                    source_package: 'pkg@1.0.0',
                    target_package: 'pkg@2.0.0',
                }
            ],
        };
        fetchMock.mockResponseOnce(JSON.stringify(previewData));

        const result = await Variants.previewCopyAssessments('src', 'tgt');

        expect('unsupported' in result).toBe(false);
        if (!('unsupported' in result)) {
            expect(result.count).toBe(3);
            expect(result.entries).toHaveLength(1);
            expect(result.entries![0].vulnerability_id).toBe('CVE-2023-1234');
        }
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/copy-assessments/preview'),
            expect.objectContaining({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            })
        );
    });

    test('returns unsupported result on 404', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) } as Response)
        );

        const result = await Variants.previewCopyAssessments('src', 'tgt');

        expect('unsupported' in result && result.unsupported).toBe(true);
        if ('unsupported' in result) {
            expect(result.status).toBe(404);
            expect(result.message).toContain('Preview is unavailable');
        }
    });

    test('returns unsupported result on 405', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: false, status: 405, json: () => Promise.resolve({}) } as Response)
        );

        const result = await Variants.previewCopyAssessments('src', 'tgt');

        expect('unsupported' in result && result.unsupported).toBe(true);
        if ('unsupported' in result) {
            expect(result.status).toBe(405);
        }
    });

    test('throws on other error responses', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Server error' }), { status: 500 });

        await expect(Variants.previewCopyAssessments('src', 'tgt')).rejects.toThrow('Server error');
    });

    test('throws generic message when error body cannot be parsed', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                status: 503,
                json: () => Promise.reject(new Error('invalid json')),
            } as Response)
        );

        await expect(Variants.previewCopyAssessments('src', 'tgt')).rejects.toThrow('Preview failed (503)');
    });

    test('passes match_mode for ignore_version mode', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ count: 0, skipped: 0, message: '', mode: 'ignore_version', groups: [] }));

        await Variants.previewCopyAssessments('src', 'tgt', 'ignore_version');

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect(body.match_mode).toBe('ignore_version');
        expect('ignore_package_version' in body).toBe(false);
    });

    test('sends match_mode and version_precision for ignore_minor_version', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ count: 0, skipped: 0, message: '', mode: 'ignore_minor_version', groups: [] }));

        await Variants.previewCopyAssessments('src', 'tgt', 'ignore_minor_version', 2);

        const body = JSON.parse((fetchMock.mock.calls[0] as any[])[1].body as string);
        expect(body.match_mode).toBe('ignore_minor_version');
        expect(body.version_precision).toBe(2);
        expect('ignore_package_version' in body).toBe(false);
    });

    test('returns grouped candidates for alternative modes', async () => {
        const grouped = {
            count: 2,
            skipped: 1,
            skipped_count: 1,
            message: '2 assessments would be copied. 1 already present would be skipped.',
            mode: 'ignore_version',
            groups: [
                {
                    source_assessment_id: 'a1',
                    source_finding_id: 'sf1',
                    vulnerability_id: 'CVE-2024-0001',
                    source_package: 'openssl@1.1.1',
                    candidates: [
                        {
                            target_finding_id: 'tf1',
                            target_package: 'openssl@1.4.2',
                            already_has_custom: false,
                            selected: true,
                        },
                    ],
                },
            ],
        };
        fetchMock.mockResponseOnce(JSON.stringify(grouped));

        const result = await Variants.previewCopyAssessments('src', 'tgt', 'ignore_version');

        expect('unsupported' in result).toBe(false);
        if (!('unsupported' in result)) {
            expect(result.mode).toBe('ignore_version');
            expect(result.groups).toHaveLength(1);
            expect(result.groups![0].candidates[0].target_finding_id).toBe('tf1');
            expect(result.entries).toBeUndefined();
        }
    });
});
