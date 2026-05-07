import { splitPkgId, extractSupplierName, formatPkgId } from '../../src/helpers/pkgId';

describe('splitPkgId', () => {
    test('splits name@version::supplier correctly', () => {
        const result = splitPkgId('mylib@1.2.3::Organization: Acme Corp');
        expect(result.nameVersion).toBe('mylib@1.2.3');
        expect(result.supplier).toBe('Organization: Acme Corp');
    });

    test('returns empty supplier when no :: separator', () => {
        const result = splitPkgId('mylib@1.2.3');
        expect(result.nameVersion).toBe('mylib@1.2.3');
        expect(result.supplier).toBe('');
    });
});

describe('extractSupplierName', () => {
    test('strips "Organization: " prefix', () => {
        expect(extractSupplierName('Organization: Acme Corp')).toBe('Acme Corp');
    });

    test('strips "Person: " prefix', () => {
        expect(extractSupplierName('Person: Jane Doe')).toBe('Jane Doe');
    });

    test('strips trailing parenthetical (e.g. email)', () => {
        expect(extractSupplierName('Organization: Acme Corp (acme@example.com)')).toBe('Acme Corp');
    });

    test('strips prefix and trailing parenthetical together', () => {
        expect(extractSupplierName('Person: Jane Doe (jane@example.com)')).toBe('Jane Doe');
    });

    test('returns string unchanged when no prefix', () => {
        expect(extractSupplierName('Acme Corp')).toBe('Acme Corp');
    });

    test('returns empty string for empty input', () => {
        expect(extractSupplierName('')).toBe('');
    });
});

describe('formatPkgId', () => {
    test('formats with extracted supplier name', () => {
        expect(formatPkgId('mylib@1.2.3::Organization: Acme Corp')).toBe('mylib@1.2.3 (Acme Corp)');
    });

    test('falls back to "unknown supplier" when no supplier', () => {
        expect(formatPkgId('mylib@1.2.3')).toBe('mylib@1.2.3 (unknown supplier)');
    });

    test('uses raw supplier name when no prefix', () => {
        expect(formatPkgId('mylib@1.2.3::Acme Corp')).toBe('mylib@1.2.3 (Acme Corp)');
    });
});
