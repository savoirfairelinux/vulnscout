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
