import RefreshRuns from '../../src/handlers/refreshRuns';

describe('persisted refresh API client', () => {
    beforeEach(() => {
        global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ run_id: 'run' }) });
    });
    afterEach(() => jest.restoreAllMocks());

    test('encodes exact run and consistently sends selected scope, filters and pagination as GET', async () => {
        const controller = new AbortController();
        await RefreshRuns.detail('run/with spaces', {
            project_id: 'project A', variant_id: 'variant B', source: 'nvd',
            change_type: 'removal', limit: 25, offset: 25,
        }, controller.signal);
        const [url, options] = (fetch as jest.Mock).mock.calls[0];
        expect(url).toContain('/api/refresh-runs/run%2Fwith%20spaces?');
        const params = new URL(url, 'http://localhost').searchParams;
        expect(Object.fromEntries(params)).toEqual({
            project_id: 'project A', variant_id: 'variant B', source: 'nvd', change_type: 'removal', limit: '25', offset: '25',
        });
        expect(options).toEqual({ mode: 'cors', signal: controller.signal });
    });

    test('distinguishes missing exact result from failures, without latest fallback or writes', async () => {
        (fetch as jest.Mock).mockResolvedValueOnce({ status: 404, ok: false });
        expect(await RefreshRuns.detail('missing', {})).toBeNull();
        expect(fetch).toHaveBeenCalledTimes(1);
        (fetch as jest.Mock).mockResolvedValueOnce({ status: 503, ok: false });
        await expect(RefreshRuns.latest({})).rejects.toThrow('HTTP 503');
    });
});
