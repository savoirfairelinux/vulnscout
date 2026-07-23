import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Config from '../../src/handlers/config';


describe('Config.get', () => {
    beforeEach(() => {
        fetchMock.resetMocks();
        window.localStorage.clear();
    });

    test('maps report metadata fields', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 'p1', name: 'Project 1' },
            variant: { id: 'v1', name: 'Variant 1' },
            author_name: 'Alice',
            product_name: 'Product X',
            client_name: 'Client Y',
            contact_email: 'alice@example.com',
        }));

        const result = await Config.get();

        expect(result.project).toEqual({ id: 'p1', name: 'Project 1' });
        expect(result.variant).toEqual({ id: 'v1', name: 'Variant 1' });
        expect(result.product_name).toBe('Product X');
        expect(result.author_name).toBe('Alice');
        expect(result.client_name).toBe('Client Y');
        expect(result.contact_email).toBe('alice@example.com');
    });

    test('applies defaults for invalid/missing values', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 7, name: 'bad' },
            variant: null,
            product_name: null,
            author_name: 5,
            client_name: null,
            contact_email: null,
        }));

        const result = await Config.get();

        expect(result.project).toBeNull();
        expect(result.variant).toBeNull();
        expect(result.product_name).toBe('');
        expect(result.author_name).toBe('vulnscout');
        expect(result.client_name).toBe('');
        expect(result.contact_email).toBe('');
    });
});


describe('Config frontend scope storage', () => {
    beforeEach(() => {
        window.localStorage.clear();
    });

    test('stores and restores a valid frontend scope locally', () => {
        const scope = {
            project_id: 'p1',
            mode: 'select' as const,
            variant_ids: ['v1'],
            compare_base_id: '',
            compare_operation: 'difference' as const,
            compare_variant_id: '',
        };

        Config.setFrontendScope(scope);

        expect(Config.getFrontendScope()).toEqual(scope);
    });

    test('ignores malformed stored scope data', () => {
        window.localStorage.setItem('vulnscout.frontendScope', '{"mode":"select"}');

        expect(Config.getFrontendScope()).toBeNull();
    });

    test('clears a saved frontend scope', () => {
        Config.setFrontendScope({
            project_id: 'p1',
            mode: 'select',
            variant_ids: [],
            compare_base_id: '',
            compare_operation: 'difference',
            compare_variant_id: '',
        });

        Config.clearFrontendScope();

        expect(Config.getFrontendScope()).toBeNull();
    });

    test('detects unavailable projects and variants in saved scopes', () => {
        const scope = {
            project_id: 'p1',
            mode: 'select' as const,
            variant_ids: ['v1'],
            compare_base_id: '',
            compare_operation: 'difference' as const,
            compare_variant_id: '',
        };

        expect(Config.isFrontendScopeAvailable(scope, ['p2'], ['v1'])).toBe(false);
        expect(Config.isFrontendScopeAvailable(scope, ['p1'], ['v2'])).toBe(false);
        expect(Config.isFrontendScopeAvailable(scope, ['p1'], ['v1'])).toBe(true);
    });
});


describe('Config.patch', () => {
    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('sends PATCH body and returns normalized response', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: null,
            variant: null,
            product_name: 'Product X',
            author_name: 'Alice',
            client_name: 'Client Y',
            contact_email: 'alice@example.com',
        }));

        const payload = {
            product_name: 'Product X',
            author_name: 'Alice',
            client_name: 'Client Y',
            contact_email: 'alice@example.com',
        };

        const result = await Config.patch(payload);

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/config'),
            expect.objectContaining({
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
        );
        expect(result.product_name).toBe('Product X');
        expect(result.author_name).toBe('Alice');
        expect(result.client_name).toBe('Client Y');
        expect(result.contact_email).toBe('alice@example.com');
    });

    test('throws backend error message when available', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Unsupported config key: nope' }), { status: 400 });

        await expect(Config.patch({ product_name: 'x', author_name: 'y', client_name: 'z', contact_email: 'a@b.c' }))
            .rejects
            .toThrow('Unsupported config key: nope');
    });

    test('throws generic error message when error body is not JSON', async () => {
        fetchMock.mockResponseOnce('failure', { status: 500 });

        await expect(Config.patch({ product_name: 'x' }))
            .rejects
            .toThrow('Failed to update config (500)');
    });
});