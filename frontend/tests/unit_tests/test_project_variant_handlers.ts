import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Config from '../../src/handlers/config';
import Projects from '../../src/handlers/project';
import Variants from '../../src/handlers/variant';
import Packages from '../../src/handlers/packages';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Assessments from '../../src/handlers/assessments';


// ---------------------------------------------------------------------------
// Config handler
// ---------------------------------------------------------------------------

describe('Config', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('returns project and variant when server provides valid data', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 'proj-1', name: 'MyProject' },
            variant: { id: 'var-1', name: 'default' },
        }));

        const config = await Config.get();

        expect(config.project).toEqual({ id: 'proj-1', name: 'MyProject' });
        expect(config.variant).toEqual({ id: 'var-1', name: 'default' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/config'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns null project and variant when server returns null values', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ project: null, variant: null }));

        const config = await Config.get();

        expect(config.project).toBeNull();
        expect(config.variant).toBeNull();
    });

    test('returns null project when id field is missing', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { name: 'NoId' },
            variant: null,
        }));

        const config = await Config.get();

        expect(config.project).toBeNull();
    });

    test('returns null variant when name field is not a string', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 'p1', name: 'P1' },
            variant: { id: 'v1', name: 42 },
        }));

        const config = await Config.get();

        expect(config.variant).toBeNull();
    });

    test('returns null when server returns empty object', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({}));

        const config = await Config.get();

        expect(config.project).toBeNull();
        expect(config.variant).toBeNull();
    });
});


// ---------------------------------------------------------------------------
// Projects handler
// ---------------------------------------------------------------------------

describe('Projects', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('returns list of valid projects', async () => {
        const mockData = [
            { id: 'p1', name: 'ProjectA' },
            { id: 'p2', name: 'ProjectB' },
        ];
        fetchMock.mockResponseOnce(JSON.stringify(mockData));

        const projects = await Projects.list();

        expect(projects).toHaveLength(2);
        expect(projects[0]).toEqual({ id: 'p1', name: 'ProjectA' });
        expect(projects[1]).toEqual({ id: 'p2', name: 'ProjectB' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns empty array when server returns empty list', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const projects = await Projects.list();

        expect(projects).toEqual([]);
    });

    test('filters out items missing id or name', async () => {
        const mockData = [
            { id: 'p1', name: 'Valid' },
            { name: 'NoId' },
            { id: 'p2' },
            { id: 'p3', name: 'AlsoValid' },
        ];
        fetchMock.mockResponseOnce(JSON.stringify(mockData));

        const projects = await Projects.list();

        expect(projects).toHaveLength(2);
        expect(projects.map(p => p.id)).toEqual(['p1', 'p3']);
    });

    test('returns empty array when server returns non-array', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'fail' }));

        const projects = await Projects.list();

        expect(projects).toEqual([]);
    });
});


// ---------------------------------------------------------------------------
// Variants handler
// ---------------------------------------------------------------------------

describe('Variants', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('returns variants for a project', async () => {
        const mockData = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p1' },
        ];
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockData),
            } as Response)
        );

        const variants = await Variants.list('p1');

        expect(variants).toHaveLength(2);
        expect(variants[0]).toEqual({ id: 'v1', name: 'default', project_id: 'p1' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects/p1/variants'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('encodes project id in URL', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve([]),
            } as Response)
        );

        await Variants.list('project with spaces');

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('project%20with%20spaces'),
            expect.anything()
        );
    });

    test('returns empty array when response is not ok', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: false,
                json: () => Promise.resolve([]),
            } as Response)
        );

        const variants = await Variants.list('p1');

        expect(variants).toEqual([]);
    });

    test('returns empty array when server returns non-array', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve({ error: 'not found' }),
            } as Response)
        );

        const variants = await Variants.list('p1');

        expect(variants).toEqual([]);
    });

    test('filters out items missing required fields', async () => {
        const mockData = [
            { id: 'v1', name: 'valid', project_id: 'p1' },
            { name: 'no-id', project_id: 'p1' },
            { id: 'v2', project_id: 'p1' },
            { id: 'v3', name: 'no-project' },
        ];
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockData),
            } as Response)
        );

        const variants = await Variants.list('p1');

        expect(variants).toHaveLength(1);
        expect(variants[0].id).toBe('v1');
    });

    test('Variants.listAll returns all variants', async () => {
        const mockData = [
            { id: 'v1', name: 'default', project_id: 'p1' },
            { id: 'v2', name: 'release', project_id: 'p2' },
        ];
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockData),
            } as Response)
        );

        const variants = await Variants.listAll();

        expect(variants).toHaveLength(2);
        expect(variants[0]).toEqual({ id: 'v1', name: 'default', project_id: 'p1' });
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('Variants.listAll returns empty array when response is not ok', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: false, json: () => Promise.resolve([]) } as Response)
        );
        expect(await Variants.listAll()).toEqual([]);
    });

    test('Variants.listAll returns empty array when server returns non-array', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: true, json: () => Promise.resolve({ error: 'not found' }) } as Response)
        );
        expect(await Variants.listAll()).toEqual([]);
    });

    test('Variants.listAll filters out items missing required fields', async () => {
        const mockData = [
            { id: 'v1', name: 'valid', project_id: 'p1' },
            { name: 'no-id', project_id: 'p1' },
        ];
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: true, json: () => Promise.resolve(mockData) } as Response)
        );
        const result = await Variants.listAll();
        expect(result).toHaveLength(1);
        expect(result[0].id).toBe('v1');
    });

    test('Variants.listByVuln returns variants for a vulnerability', async () => {
        const mockData = [{ id: 'v1', name: 'default', project_id: 'p1' }];
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: true, json: () => Promise.resolve(mockData) } as Response)
        );
        const variants = await Variants.listByVuln('CVE-2023-1234');
        expect(variants).toHaveLength(1);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/vulnerabilities/CVE-2023-1234/variants'),
            expect.anything()
        );
    });

    test('Variants.listByVuln returns empty array when response is not ok', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: false, json: () => Promise.resolve([]) } as Response)
        );
        expect(await Variants.listByVuln('CVE-2023-1234')).toEqual([]);
    });

    test('Variants.listByVuln encodes vuln id in URL', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: true, json: () => Promise.resolve([]) } as Response)
        );
        await Variants.listByVuln('CVE 2023 1234');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('CVE%202023%201234'),
            expect.anything()
        );
    });

    test('Variants.listByVuln returns empty array when server returns non-array', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ ok: true, json: () => Promise.resolve(null) } as Response)
        );
        expect(await Variants.listByVuln('CVE-2023-1234')).toEqual([]);
    });
});


// ---------------------------------------------------------------------------
// Packages.list — variantId and projectId query params
// ---------------------------------------------------------------------------

describe('Packages.list with filtering params', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('list() without params uses base URL', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Packages.list();

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('/api/packages');
        expect(calledUrl).toContain('format=list');
        expect(calledUrl).not.toContain('variant_id');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(variantId) appends variant_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Packages.list('var-abc');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-abc');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(undefined, projectId) appends project_id param when no variantId', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Packages.list(undefined, 'proj-xyz');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('project_id=proj-xyz');
        expect(calledUrl).not.toContain('variant_id');
    });

    test('list(variantId, projectId) uses only variant_id', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Packages.list('var-1', 'proj-1');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-1');
        expect(calledUrl).not.toContain('project_id');
    });
});


// ---------------------------------------------------------------------------
// Vulnerabilities.list — variantId and projectId query params
// ---------------------------------------------------------------------------

describe('Vulnerabilities.list with filtering params', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('list() without params uses base URL', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Vulnerabilities.list();

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('/api/vulnerabilities');
        expect(calledUrl).toContain('format=list');
        expect(calledUrl).not.toContain('variant_id');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(variantId) appends variant_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Vulnerabilities.list('var-abc');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-abc');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(undefined, projectId) appends project_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Vulnerabilities.list(undefined, 'proj-xyz');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('project_id=proj-xyz');
        expect(calledUrl).not.toContain('variant_id');
    });

    test('list(variantId, projectId) prioritises variant_id', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Vulnerabilities.list('var-1', 'proj-1');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-1');
        expect(calledUrl).not.toContain('project_id');
    });
});


// ---------------------------------------------------------------------------
// Assessments.list — variantId and projectId query params
// ---------------------------------------------------------------------------

describe('Assessments.list with filtering params', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('list() without params uses base URL', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Assessments.list();

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('/api/assessments');
        expect(calledUrl).toContain('format=list');
        expect(calledUrl).not.toContain('variant_id');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(variantId) appends variant_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Assessments.list('var-abc');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-abc');
        expect(calledUrl).not.toContain('project_id');
    });

    test('list(undefined, projectId) appends project_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Assessments.list(undefined, 'proj-xyz');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('project_id=proj-xyz');
        expect(calledUrl).not.toContain('variant_id');
    });

    test('list(variantId, projectId) prioritises variant_id', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );

        await Assessments.list('var-1', 'proj-1');

        const calledUrl: string = (fetchMock.mock.calls[0] as any[])[0];
        expect(calledUrl).toContain('variant_id=var-1');
        expect(calledUrl).not.toContain('project_id');
    });
});
