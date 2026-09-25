import Operations from '../../src/handlers/operations';

describe('operation job builders', () => {
    it('builds scan jobs with default and explicit options', () => {
        expect(Operations.scanJob('grype', ['variant-1'])).toEqual({
            kind: 'scan',
            source: 'grype',
            variant_ids: ['variant-1'],
            options: { exclude_kernel: true, exclude_native: false, mode: 'local' },
        });
        expect(Operations.scanJob('nvd', ['variant-2'], { excludeKernel: false, mode: 'api' })).toEqual({
            kind: 'scan',
            source: 'nvd',
            variant_ids: ['variant-2'],
            options: { exclude_kernel: false, exclude_native: false, mode: 'api' },
        });
    });

    it('builds immediate and deferred refresh jobs', () => {
        expect(Operations.refreshJob('nvd', ['CVE-2024-1234'])).toEqual({
            kind: 'refresh',
            source: 'nvd',
            ids: ['CVE-2024-1234'],
            options: { mode: 'local' },
        });
        expect(Operations.deferredRefreshJob('epss', ['variant-1'], ['CVE-2024-1234'], { mode: 'api' })).toEqual({
            kind: 'refresh',
            source: 'epss',
            variant_ids: ['variant-1'],
            exclude_ids: ['CVE-2024-1234'],
            options: { mode: 'api' },
        });
    });
});

describe('operation queue requests', () => {
    const fetchSpy = jest.fn();
    let restoreFetch: typeof fetch;

    beforeEach(() => {
        restoreFetch = global.fetch;
        global.fetch = fetchSpy as typeof fetch;
        fetchSpy.mockReset();
    });

    afterEach(() => {
        global.fetch = restoreFetch;
    });

    it('cancels every step of a batch through the queue endpoint', async () => {
        fetchSpy.mockResolvedValueOnce({ ok: true } as Response);
        fetchSpy.mockResolvedValueOnce({ ok: false } as Response);

        expect(await Operations.cancelQueue('q-1/2')).toBe(true);
        expect(await Operations.cancelQueue('q-1/2')).toBe(false);
        expect(fetchSpy.mock.calls[0]).toEqual([
            expect.stringMatching(/\/api\/operations\/queue\/q-1%2F2\/cancel$/),
            { method: 'POST', mode: 'cors' },
        ]);
    });
});
