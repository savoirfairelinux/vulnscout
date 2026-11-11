import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Context from '../../src/handlers/context';
import { applyAiDraft, contextImportKey, contextImportMessage, draftChangeSummary } from '../../src/helpers/aiContextImport';
import { emptyDraft, emptyStrideModel } from '../../src/helpers/strideModel';
import type { AiContextDraftValues } from '../../src/handlers/context';

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

const NO_SYSTEM = { scope: null, actors: null, entry_points: null, trust_boundaries: null };
const values = (overrides: Partial<AiContextDraftValues> = {}): AiContextDraftValues => ({
    variant_description: null, environment: null, other_info: null, system: NO_SYSTEM, stride: emptyStrideModel(), ...overrides,
});
const comp = (id: string, name: string) => ({ id, name, description: '', trust_zone: '' });

describe('aiContextImport helpers', () => {
    test('applyAiDraft keeps null texts, clears "" and never touches the codebase settings', () => {
        const baseline = { ...emptyDraft(), variant_description: 'Gateway', environment: 'Lab', codebase_paths: ['/src'],
            system: { scope: 'Old', actors: 'Admin', entry_points: '', trust_boundaries: '' } };
        const applied = applyAiDraft(baseline, values({
            environment: '', other_info: 'Notes', system: { ...NO_SYSTEM, scope: 'New' },
            stride: { ...emptyStrideModel(), components: [comp('C1', 'UI')] },
        }));
        expect(applied.variant_description).toBe('Gateway');
        expect(applied.environment).toBe('');
        expect(applied.other_info).toBe('Notes');
        expect(applied.system).toEqual({ scope: 'New', actors: '', entry_points: '', trust_boundaries: '' });
        expect(applied.codebase_paths).toEqual(['/src']);
        expect(applied.codebase_source).toBe(baseline.codebase_source);
        expect(applied.stride.components).toEqual([comp('C1', 'UI')]);
    });

    test('draftChangeSummary counts rows by id and names changed fields', () => {
        const baseline = { ...emptyDraft(), stride: { ...emptyStrideModel(), components: [comp('C1', 'UI'), comp('C2', 'DB')] } };
        const draft = { ...baseline, environment: 'Prod', system: { ...baseline.system, actors: 'Ops' },
            stride: { ...emptyStrideModel(), components: [comp('C1', 'Web UI'), comp('C3', 'API'), comp('C4', 'Queue')] } };
        expect(draftChangeSummary(baseline, draft)).toBe('+2 components, ~1 component, -1 component (changes to Environment, System actors)');
        expect(draftChangeSummary(baseline, { ...baseline, other_info: 'x' })).toBe('changes to Other information');
        expect(draftChangeSummary(baseline, baseline)).toBe('no changes');
    });

    test('the queued message names the variant, the document and the embedded tools', () => {
        expect(contextImportKey('v1')).toBe('context-import:v1');
        const text = contextImportMessage({ projectId: 'p1', projectName: 'Project A', variantId: 'v1', variantName: 'Variant 1', fileName: 'report.pdf' });
        for (const part of ['Variant 1', 'v1', 'Project A', 'p1', 'report.pdf', 'embedded mode', 'read_import_source', 'propose_variant_threat_model', 'Never save']) {
            expect(text).toContain(part);
        }
    });
});
