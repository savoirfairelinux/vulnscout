import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import CustomExportContentManager from '../../src/components/CustomExportContentManager';

function jsonResponse(body: unknown, ok = true, status = 200): Response {
    return {
        ok,
        status,
        json: jest.fn().mockResolvedValue(body),
    } as unknown as Response;
}

describe('CustomExportContentManager', () => {
    beforeEach(() => {
        global.fetch = jest.fn();
    });

    test('falls back to empty lists when loading documents fails', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch.mockRejectedValueOnce(new Error('Network unavailable'));

        render(<CustomExportContentManager />);

        expect(await screen.findByText('No custom reports installed.')).toBeInTheDocument();
        expect(screen.getByText('No custom assets installed.')).toBeInTheDocument();
    });

    test('uploads an asset by drag and drop, reloads documents, and dismisses success', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(jsonResponse([]))
            .mockResolvedValueOnce(jsonResponse({ name: 'logo.png' }))
            .mockResolvedValueOnce(jsonResponse([
                { id: 'logo.png', category: ['assets'], extension: 'png' },
            ]));
        render(<CustomExportContentManager />);
        const upload = await screen.findByRole('button', { name: 'Upload a custom report or asset' });
        const file = new File(['image'], 'logo.PNG', { type: 'image/png' });

        fireEvent.dragEnter(upload);
        expect(upload.className).toContain('border-sky-400');
        fireEvent.dragLeave(upload);
        expect(upload.className).not.toContain('border-sky-400');
        fireEvent.dragOver(upload);
        fireEvent.drop(upload, { dataTransfer: { files: [file] } });

        expect(await screen.findByText('Uploaded "logo.png".')).toBeInTheDocument();
        expect(await screen.findByText('logo.png')).toBeInTheDocument();
        const uploadCall = fetch.mock.calls.find(([url, options]) =>
            String(url).endsWith('/api/documents/assets') && options?.method === 'POST');
        expect(uploadCall).toBeDefined();
        expect((uploadCall?.[1]?.body as FormData).get('file')).toBe(file);

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss message' }));
        expect(screen.queryByText('Uploaded "logo.png".')).not.toBeInTheDocument();
    });

    test('shows the server fallback error and restores the upload control', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(jsonResponse([]))
            .mockResolvedValueOnce({
                ok: false,
                status: 415,
                json: jest.fn().mockRejectedValue(new Error('Invalid JSON')),
            } as unknown as Response);
        const { container } = render(<CustomExportContentManager />);
        await screen.findByText('No custom reports installed.');
        const input = container.querySelector('input[type="file"]') as HTMLInputElement;

        fireEvent.change(input, {
            target: { files: [new File(['report'], 'report.adoc', { type: 'text/asciidoc' })] },
        });

        expect(await screen.findByRole('alert')).toHaveTextContent('Import failed (415)');
        await waitFor(() => expect(screen.getByRole('button', { name: 'Upload a custom report or asset' })).toBeEnabled());
        expect(fetch).toHaveBeenCalledWith('http://localhost/api/documents/templates', expect.objectContaining({ method: 'POST' }));
    });

    test('shows a network error from an upload', async () => {
        const fetch = global.fetch as jest.MockedFunction<typeof global.fetch>;
        fetch
            .mockResolvedValueOnce(jsonResponse([]))
            .mockRejectedValueOnce('Connection lost');
        const { container } = render(<CustomExportContentManager />);
        await screen.findByText('No custom assets installed.');

        fireEvent.change(container.querySelector('input[type="file"]')!, {
            target: { files: [new File(['image'], 'logo.webp', { type: 'image/webp' })] },
        });

        expect(await screen.findByRole('alert')).toHaveTextContent('Connection lost');
    });
});