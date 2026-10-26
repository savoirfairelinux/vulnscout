import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Context, { ContextSaveError } from '../../src/handlers/context';
import type { MergedContext, StrideModel } from '../../src/handlers/context';
import {
    STRIDE_CATEGORIES, RATING_OPTIONS, emptyStrideModel, emptyDraft, draftFromContext,
    draftsEqual, nextId, isReferenced, hasThreatModel,
} from '../../src/helpers/strideModel';

beforeEach(() => fetchMock.resetMocks());

function ctxWithEditor(editor: Partial<MergedContext['editor']> = {}): MergedContext {
    return {
        project_id: 'p1', description: null, variant_id: 'v1', variant_description: 'VD',
        codebase_path: null, environment: null, threat_model: null, risks: null, other_info: null,
        editor: {
            codebase_source: 'paths', codebase_path: null,
            system: { scope: null, actors: null, entry_points: null, trust_boundaries: null },
            stride: emptyStrideModel(), files: [], updated_at: null,
            ...editor,
        },
    };
}

const populated: StrideModel = {
    components: [{ id: 'C1', name: 'API', description: '', trust_zone: '' }],
    interactions: [{ id: 'I1', name: 'call', source_id: 'C1', destination_id: 'C2', interface: '', data: '', trust_boundary: '' }],
    threats: [{ id: 'T1', category: 'spoofing', description: 'x', target_ids: ['I1'] }],
    risks: [{ threat_id: 'T1', likelihood: 'low', impact: null, mitigation: '', residual: '' }],
};

describe('constants', () => {
    test('STRIDE categories are in spec order with labels and letters', () => {
        expect(STRIDE_CATEGORIES.map(c => c.key)).toEqual([
            'spoofing', 'tampering', 'repudiation', 'information_disclosure',
            'denial_of_service', 'elevation_of_privilege',
        ]);
        expect(STRIDE_CATEGORIES.map(c => c.letter).join('')).toBe('STRIDE');
        expect(STRIDE_CATEGORIES[3].label).toBe('Information disclosure');
    });

    test('rating options start with not rated', () => {
        expect(RATING_OPTIONS.map(r => r.label)).toEqual(['Not rated', 'Low', 'Medium', 'High']);
        expect(RATING_OPTIONS[0].value).toBeNull();
    });
});

describe('drafts', () => {
    test('emptyDraft defaults to the references source and an empty STRIDE model', () => {
        const d = emptyDraft();
        expect(d.codebase_source).toBe('references');
        expect(d.codebase_paths).toEqual([]);
        expect(d.stride).toEqual(emptyStrideModel());
    });

    test('draftFromContext maps nulls to empty strings and reads the editor block', () => {
        const d = draftFromContext(ctxWithEditor({
            codebase_source: 'references', codebase_path: ' /src/a;;/src/b ;',
            system: { scope: 'S', actors: null, entry_points: null, trust_boundaries: null },
        }));
        expect(d.variant_description).toBe('VD');
        expect(d.environment).toBe('');
        expect(d.other_info).toBe('');
        expect(d.codebase_source).toBe('references');
        expect(d.codebase_paths).toEqual(['/src/a', '/src/b']);
        expect(d.system).toEqual({ scope: 'S', actors: '', entry_points: '', trust_boundaries: '' });
    });

    test('draftFromContext does not share references with the context', () => {
        const ctx = ctxWithEditor({ stride: populated });
        const d = draftFromContext(ctx);
        expect(d.stride).toEqual(populated);
        expect(d.stride.threats[0]).not.toBe(populated.threats[0]);
        expect(d.stride.threats[0].target_ids).not.toBe(populated.threats[0].target_ids);
    });

    test('draftsEqual ignores object identity but detects changes', () => {
        const a = draftFromContext(ctxWithEditor({ stride: populated }));
        const b = draftFromContext(ctxWithEditor({ stride: populated }));
        expect(draftsEqual(a, b)).toBe(true);
        expect(draftsEqual(a, { ...b, environment: 'x' })).toBe(false);
        const c = { ...b, stride: { ...b.stride, threats: [{ ...b.stride.threats[0], target_ids: ['I1', 'C1'] }] } };
        expect(draftsEqual(a, c)).toBe(false);
    });
});

describe('ids and references', () => {
    test('nextId starts at 1 and takes max+1', () => {
        expect(nextId([], 'C')).toBe('C1');
        expect(nextId([{ id: 'C1' }, { id: 'C4' }], 'C')).toBe('C5');
    });

    test('nextId never reuses a removed id', () => {
        expect(nextId([{ id: 'C1' }], 'C', ['C2'])).toBe('C3');
    });

    test('nextId ignores other prefixes and malformed ids', () => {
        expect(nextId([{ id: 'I9' }, { id: 'Cx' }], 'C')).toBe('C1');
    });

    test('isReferenced covers interaction endpoints, threat targets and risk threat ids', () => {
        expect(isReferenced(populated, 'C1')).toBe(true);
        expect(isReferenced(populated, 'C2')).toBe(true);
        expect(isReferenced(populated, 'I1')).toBe(true);
        expect(isReferenced(populated, 'T1')).toBe(true);
        expect(isReferenced(populated, 'C9')).toBe(false);
    });
});

describe('hasThreatModel', () => {
    test('counts system fields and rows but not risks', () => {
        const base = emptyDraft();
        expect(hasThreatModel(base)).toBe(false);
        expect(hasThreatModel({ ...base, system: { ...base.system, scope: 'x' } })).toBe(true);
        expect(hasThreatModel({ ...base, system: { ...base.system, scope: '  ' } })).toBe(false);
        expect(hasThreatModel({ ...base, stride: { ...emptyStrideModel(), components: populated.components } })).toBe(true);
        expect(hasThreatModel({ ...base, stride: { ...emptyStrideModel(), interactions: populated.interactions } })).toBe(true);
        expect(hasThreatModel({ ...base, stride: { ...emptyStrideModel(), threats: populated.threats } })).toBe(true);
        expect(hasThreatModel({ ...base, stride: { ...emptyStrideModel(), risks: populated.risks } })).toBe(false);
    });
});

describe('Context.saveVariantEditor', () => {
    test('sends null for blank optional text and the editor shape', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(ctxWithEditor()));
        const draft = {
            ...emptyDraft(), variant_description: ' ', environment: '', other_info: 'info',
            codebase_paths: ['', ' '],
        };
        await Context.saveVariantEditor('v 1', draft);
        const [url, init] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/api/variants/v%201/context');
        expect(init?.method).toBe('PUT');
        const body = JSON.parse(String(init?.body));
        expect(body.variant_description).toBeNull();
        expect(body.environment).toBeNull();
        expect(body.other_info).toBe('info');
        expect(body.codebase_path).toBeNull();
        expect(body.system).toEqual({ scope: null, actors: null, entry_points: null, trust_boundaries: null });
        expect(body).not.toHaveProperty('editor_mode');
        expect(body).not.toHaveProperty('free');
        expect(body.codebase_source).toBe('references');
        expect(body.stride).toEqual(emptyStrideModel());
    });

    test('joins the trimmed non-blank codebase paths with ";"', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(ctxWithEditor()));
        await Context.saveVariantEditor('v1', { ...emptyDraft(), codebase_paths: [' /src/a ', '', '/src/b'] });
        expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body)).codebase_path).toBe('/src/a;/src/b');
    });

    test('returns the saved variant context on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(ctxWithEditor({ updated_at: 'now' })));
        const res = await Context.saveVariantEditor('v1', emptyDraft());
        expect(res.editor.updated_at).toBe('now');
    });

    test('throws ContextSaveError with fields on 400', async () => {
        fetchMock.mockResponseOnce(
            JSON.stringify({ error: 'invalid', fields: { 'threats[0].target_ids': 'unknown id' } }),
            { status: 400 },
        );
        const err = await Context.saveVariantEditor('v1', emptyDraft()).catch(e => e);
        expect(err).toBeInstanceOf(ContextSaveError);
        expect(err.status).toBe(400);
        expect(err.message).toBe('invalid');
        expect(err.fields).toEqual({ 'threats[0].target_ids': 'unknown id' });
    });

    test('uses empty fields when the error body has none', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'nope' }), { status: 404 });
        const err = await Context.saveVariantEditor('v1', emptyDraft()).catch(e => e);
        expect(err).toBeInstanceOf(ContextSaveError);
        expect(err.fields).toEqual({});
        expect(err.status).toBe(404);
    });

    test('a non-JSON error body gives the HTTP status, not a parse error', async () => {
        fetchMock.mockResponseOnce('<html>Bad Gateway</html>', { status: 502 });
        const err = await Context.saveVariantEditor('v1', emptyDraft()).catch(e => e);
        expect(err).toBeInstanceOf(ContextSaveError);
        expect(err.message).toBe('Failed to save variant context (502)');
        expect(err.status).toBe(502);
        expect(err.fields).toEqual({});
    });
});

describe('Context error replies', () => {
    const file = new File(['x'], 'a.zip');
    test.each([
        ['get', () => Context.get('p1', 'v1'), 'Failed to load context (502)'],
        ['getProject', () => Context.getProject('p1'), 'Failed to load project context (502)'],
        ['saveProject', () => Context.saveProject('p1', 'd'), 'Failed to save project context (502)'],
        ['uploadFile', () => Context.uploadFile('v1', file, ''), 'Failed to upload reference (502)'],
        ['deleteFile', () => Context.deleteFile('v1', 'f1'), 'Failed to delete reference (502)'],
        ['exportAll', () => Context.exportAll(), 'Failed to export context (502)'],
        ['exportSelected', () => Context.exportSelected(['v1']), 'Failed to export context (502)'],
        ['importContext', () => Context.importContext([]), 'Failed to import context (502)'],
    ])('%s reports a non-JSON error body by its HTTP status', async (_name, call, message) => {
        fetchMock.mockResponseOnce('<html>Bad Gateway</html>', { status: 502 });
        await expect(call()).rejects.toThrow(message);
    });

    test('a JSON error message is still used', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Variant does not belong to project' }), { status: 400 });
        await expect(Context.get('p1', 'v1')).rejects.toThrow('Variant does not belong to project');
    });
});
