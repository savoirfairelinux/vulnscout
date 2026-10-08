import { ROUTES, normalizeRoutePath, parseSettingsPath, settingsProjectPath, settingsVariantPath, tabForPath } from '../../src/routes';

describe('route path resolution', () => {
    test('maps every known route path back to its tab key', () => {
        (Object.entries(ROUTES) as [keyof typeof ROUTES, string][]).forEach(([tab, path]) => {
            expect(tabForPath(path)).toBe(tab);
        });
    });

    test('ignores a trailing slash like the router does', () => {
        // Arrange
        const pathname = '/sbom/';

        // Act
        const tab = tabForPath(pathname);

        // Assert
        expect(tab).toBe('packages');
    });

    test('returns unknown for a path no route matches', () => {
        expect(tabForPath('/does-not-exist')).toBe('unknown');
        expect(tabForPath('/sbom/nested')).toBe('unknown');
    });

    test('normalizeRoutePath keeps the root path intact', () => {
        expect(normalizeRoutePath('/')).toBe('/');
        expect(normalizeRoutePath('/settings//')).toBe('/settings');
    });
});

describe('settings sub-routes', () => {
    test('tabForPath resolves nested settings paths to settings', () => {
        expect(tabForPath('/settings/transfer')).toBe('settings');
        expect(tabForPath('/settings/p1')).toBe('settings');
        expect(tabForPath('/settings/p1/v1/')).toBe('settings');
        expect(tabForPath('/settingsx')).toBe('unknown');
        expect(tabForPath('/sbom/nested')).toBe('unknown');
    });

    test('parseSettingsPath maps every settings URL', () => {
        expect(parseSettingsPath('/settings')).toEqual({ kind: 'general' });
        expect(parseSettingsPath('/settings/')).toEqual({ kind: 'general' });
        expect(parseSettingsPath('/settings/transfer')).toEqual({ kind: 'transfer' });
        expect(parseSettingsPath('/settings/custom-export')).toEqual({ kind: 'custom-export' });
        expect(parseSettingsPath('/settings/p1')).toEqual({ kind: 'project', projectId: 'p1' });
        expect(parseSettingsPath('/settings/p1/')).toEqual({ kind: 'project', projectId: 'p1' });
        expect(parseSettingsPath('/settings/p1/v1/')).toEqual({ kind: 'variant', projectId: 'p1', variantId: 'v1' });
        expect(parseSettingsPath('/settings/p1/v1/x')).toEqual({ kind: 'unknown' });
        expect(parseSettingsPath('/settings/%E0%A4%A')).toEqual({ kind: 'unknown' });
        expect(parseSettingsPath('/sbom')).toEqual({ kind: 'unknown' });
    });

    test('builds project and variant paths that round-trip', () => {
        expect(settingsProjectPath('p 1')).toBe('/settings/p%201');
        expect(settingsVariantPath('p1', 'v1')).toBe('/settings/p1/v1');
        expect(parseSettingsPath(settingsProjectPath('p 1'))).toEqual({ kind: 'project', projectId: 'p 1' });
    });
});
