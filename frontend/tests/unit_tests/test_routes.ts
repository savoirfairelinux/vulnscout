import { ROUTES, normalizeRoutePath, tabForPath } from '../../src/routes';

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
