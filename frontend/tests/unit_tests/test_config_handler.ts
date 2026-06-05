import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Config from '../../src/handlers/config';


describe('Config.get', () => {
    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('maps report metadata fields and author_name fallback', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 'p1', name: 'Project 1' },
            variant: { id: 'v1', name: 'Variant 1' },
            author: 'Legacy Author',
            product_name: 'Product X',
            client_name: 'Client Y',
            contact_email: 'alice@example.com',
        }));

        const result = await Config.get();

        expect(result.project).toEqual({ id: 'p1', name: 'Project 1' });
        expect(result.variant).toEqual({ id: 'v1', name: 'Variant 1' });
        expect(result.author).toBe('Legacy Author');
        expect(result.product_name).toBe('Product X');
        expect(result.author_name).toBe('Legacy Author');
        expect(result.client_name).toBe('Client Y');
        expect(result.contact_email).toBe('alice@example.com');
    });

    test('applies defaults for invalid/missing values', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({
            project: { id: 7, name: 'bad' },
            variant: null,
            author: '   ',
            product_name: null,
            author_name: 5,
            client_name: null,
            contact_email: null,
        }));

        const result = await Config.get();

        expect(result.project).toBeNull();
        expect(result.variant).toBeNull();
        expect(result.author).toBe('vulnscout');
        expect(result.product_name).toBe('');
        expect(result.author_name).toBe('   ');
        expect(result.client_name).toBe('');
        expect(result.contact_email).toBe('');
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
            author: 'vulnscout',
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