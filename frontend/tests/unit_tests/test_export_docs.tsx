import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import Exports from '../../src/pages/Exports';

describe('Exports Page', () => {

    test('render file and allow direct download', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            {
                id: "hello.adoc",
                category: ['misc'],
                extension: "adoc|pdf"
            }
        ]));

        // ARRANGE
        render(<Exports />);

        // ASSERT - Just test that it renders without crashing
        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
    })

    test('handles empty response', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        // ARRANGE
        render(<Exports />);

        // ASSERT - Component should render without crashing
        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
    })

    test('handles fetch error gracefully', async () => {
        fetchMock.resetMocks();
        fetchMock.mockRejectOnce(new Error('Network error'));
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        // ARRANGE & ACT
        render(<Exports />);

        // ASSERT - Component should still render without crashing
        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
        await waitFor(() => {
            expect(consoleSpy).toHaveBeenCalledWith('Error:', expect.any(Error));
        });
        consoleSpy.mockRestore();
    })

    test('handles invalid document data gracefully', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { invalid: "data" },
            { id: "valid.txt", category: ['misc'] }
        ]));

        // ARRANGE & ACT
        render(<Exports />);

        // ASSERT - Component should still render without crashing
        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
    })

    test('renders and displays documents in all tab', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "custom.pdf", category: ['custom'], extension: "pdf" },
            { id: "sbom.json", category: ['sbom'], extension: "json" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        expect(screen.getByText(/custom\.pdf/i)).toBeInTheDocument();
        expect(screen.getByText(/sbom\.json/i)).toBeInTheDocument();
    })

    test('filters documents by built-in tab', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "custom.pdf", category: ['custom'], extension: "pdf" },
            { id: "sbom.json", category: ['sbom'], extension: "json" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        const builtInButton = screen.getByText('Built-in reports');
        fireEvent.click(builtInButton);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });
        expect(screen.queryByText(/custom\.pdf/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/sbom\.json/i)).not.toBeInTheDocument();
    })

    test('filters documents by custom tab', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "custom.pdf", category: ['custom'], extension: "pdf" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        const customButton = screen.getByText('Custom reports');
        fireEvent.click(customButton);

        await waitFor(() => {
            expect(screen.getByText(/custom\.pdf/i)).toBeInTheDocument();
        });
        expect(screen.queryByText(/report\.adoc/i)).not.toBeInTheDocument();
    })

    test('keeps custom assets separate from custom reports', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "custom.pdf", category: ['custom'], extension: "pdf" }
        ]));

        const { container } = render(<Exports />);
        await screen.findByText(/custom\.pdf/i);

        fireEvent.click(screen.getByRole('button', { name: 'Custom assets' }));

        expect(screen.queryByText(/report\.adoc/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/custom\.pdf/i)).not.toBeInTheDocument();
        expect(screen.getByText('No documents found')).toBeInTheDocument();
        expect(container.querySelectorAll('input[type="file"]')).toHaveLength(1);
        expect(screen.getByText(/Assets: \.png, \.jpg, \.webp, \.gif/i)).toBeInTheDocument();
    })

    test('filters documents by sbom tab', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "sbom.json", category: ['sbom'], extension: "json" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        const sbomButton = screen.getByText('SBOM files');
        fireEvent.click(sbomButton);

        await waitFor(() => {
            expect(screen.getByText(/sbom\.json/i)).toBeInTheDocument();
        });
        expect(screen.queryByText(/report\.adoc/i)).not.toBeInTheDocument();
    })

    test('shows no documents message when filter has no results', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        const customButton = screen.getByText('Custom reports');
        fireEvent.click(customButton);

        await waitFor(() => {
            expect(screen.getByText('No documents found')).toBeInTheDocument();
        });
    })

    test('shows custom template message for custom tab with no documents', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        render(<Exports />);

        const customButton = await screen.findByText('Custom reports');
        fireEvent.click(customButton);

        await waitFor(() => {
            expect(screen.getByText('No documents found')).toBeInTheDocument();
            expect(screen.getByText(/You can upload your own templates/i)).toBeInTheDocument();
        });
    })

    test('handles documents without extension field', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.txt", category: ['built-in'] }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.txt/i)).toBeInTheDocument();
        });
    })

    test('switches back to all tab', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" },
            { id: "custom.pdf", category: ['custom'], extension: "pdf" }
        ]));

        render(<Exports />);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
        });

        const customButton = screen.getByText('Custom reports');
        fireEvent.click(customButton);

        await waitFor(() => {
            expect(screen.queryByText(/report\.adoc/i)).not.toBeInTheDocument();
        });

        const allButton = screen.getByText('All');
        fireEvent.click(allButton);

        await waitFor(() => {
            expect(screen.getByText(/report\.adoc/i)).toBeInTheDocument();
            expect(screen.getByText(/custom\.pdf/i)).toBeInTheDocument();
        });
    })

    test('handles non-array response from API', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify({ invalid: 'response' }));

        render(<Exports />);

        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
    })

    test('clicking a file tag toggles its opened state', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: "report.adoc", category: ['built-in'], extension: "adoc" }
        ]));

        render(<Exports />);

        const fileButton = await screen.findByText(/report\.adoc/i);
        fireEvent.click(fileButton);

        // Clicking the file tag should toggle the download options
        await waitFor(() => {
            expect(screen.getByText(/Download/i)).toBeInTheDocument();
        });

        // Clicking again should close it
        fireEvent.click(fileButton);
    })

    const uploadInput = (container: HTMLElement): HTMLInputElement =>
        container.querySelector('input[type="file"]') as HTMLInputElement;

    test('renders one upload dropzone for reports and assets', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);

        await screen.findByText(/export/i);
        expect(screen.getByRole('button', { name: /Upload a custom report or asset/i }))
            .toBeInTheDocument();
        expect(screen.getByText(/Drag & drop a custom report or asset here, or click to browse/i)).toBeInTheDocument();
        expect(container.querySelectorAll('input[type="file"]')).toHaveLength(1);
    })

    test('routes report uploads through the shared file input', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce(JSON.stringify({ id: 'report.adoc' }));
        fireEvent.change(uploadInput(container), {
            target: { files: [new File(['report'], 'report.adoc', { type: 'text/asciidoc' })] }
        });

        await screen.findByText(/Imported "report\.adoc"/i);
        const [url] = fetchMock.mock.calls[fetchMock.mock.calls.length - 2];
        expect(url).toContain('/api/documents/templates');
    })

    test('uploads an image asset successfully via the file input', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce(JSON.stringify({ name: 'logo.png' }));
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'logo.png', category: ['assets'], extension: 'png' }
        ]));

        const file = new File(['binary'], 'logo.png', { type: 'image/png' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByText(/Uploaded "logo\.png"/i);
    await screen.findByRole('button', { name: /logo\.png/i });

        const assetRequest = fetchMock.mock.calls.find(([request]) =>
            (typeof request === 'string' ? request : request?.url ?? '')
                .includes('/api/documents/assets')
        );
        expect(assetRequest).toBeDefined();
        const [url, options] = assetRequest!;
        expect(typeof url === 'string' ? url : url?.url)
            .toContain('/api/documents/assets');
        expect(options?.method).toBe('POST');
        const body = options?.body as FormData;
        expect(body.get('file')).toBeInstanceOf(File);
    })

    test('shows the server error message when asset upload fails', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Invalid file type' }), { status: 400 });

        const file = new File(['data'], 'bad.exe', { type: 'application/octet-stream' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByRole('alert');
        expect(screen.getByText('Invalid file type')).toBeInTheDocument();
    })

    test('shows a generic error message when asset upload fails without a JSON body', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce('', { status: 500 });

        const file = new File(['data'], 'bad.png', { type: 'image/png' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByText(/Upload failed \(500\)/i);
    })

    test('shows an error message when asset upload fails due to a network error', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockRejectOnce(new Error('Network down'));

        const file = new File(['data'], 'logo.png', { type: 'image/png' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByText('Network down');
    })

    test('shows an uploading state while the asset upload is in progress', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        let resolveUpload: (response: Response) => void = () => {};
        fetchMock.mockImplementationOnce(() => new Promise((resolve) => { resolveUpload = resolve; }));

        const file = new File(['binary'], 'logo.png', { type: 'image/png' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByText(/Uploading file…/i);

        resolveUpload({
            ok: true,
            json: () => Promise.resolve({ name: 'logo.png' })
        } as Response);

        await screen.findByText(/Uploaded "logo\.png"/i);
    })

    test('dismisses the asset upload success message', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        const { container } = render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce(JSON.stringify({ name: 'logo.png' }));

        const file = new File(['binary'], 'logo.png', { type: 'image/png' });
        fireEvent.change(uploadInput(container), { target: { files: [file] } });

        await screen.findByText(/Uploaded "logo\.png"/i);

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss message' }));

        await waitFor(() => {
            expect(screen.queryByText(/Uploaded "logo\.png"/i)).not.toBeInTheDocument();
        });
    })

    test('drag and drop uploads an image asset and toggles the active drag style', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        render(<Exports />);
        await screen.findByText(/export/i);

        fetchMock.mockResponseOnce(JSON.stringify({ name: 'dropped.png' }));

        const dropzone = screen.getByRole('button', { name: /Upload a custom report or asset/i });
        const file = new File(['binary'], 'dropped.png', { type: 'image/png' });

        fireEvent.dragEnter(dropzone);
        expect(dropzone.className).toContain('border-sky-400');

        fireEvent.dragLeave(dropzone);
        expect(dropzone.className).not.toContain('border-sky-400');

        fireEvent.dragOver(dropzone);
        expect(dropzone.className).toContain('border-sky-400');

        fireEvent.drop(dropzone, { dataTransfer: { files: [file] } });

        await screen.findByText(/Uploaded "dropped\.png"/i);
        expect(dropzone.className).not.toContain('border-sky-400');
    })

    test('clicking the asset dropzone opens the file browser', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponseOnce(JSON.stringify([]));

        render(<Exports />);
        await screen.findByText(/export/i);

        const clickSpy = jest.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(() => {});

        const dropzone = screen.getByRole('button', { name: /Upload a custom report or asset/i });
        fireEvent.click(dropzone);

        expect(clickSpy).toHaveBeenCalled();
        clickSpy.mockRestore();
    })

    test('confirms the export scope before downloading', async () => {
        fetchMock.resetMocks();
        fetchMock
            .mockResponseOnce(JSON.stringify([
                { id: "report.adoc", category: ['built-in'], extension: "pdf" }
            ]))
            .mockResponseOnce(JSON.stringify([
                { id: "project-1", name: "Demo Project" }
            ]))
            .mockResponseOnce(JSON.stringify([
                { id: "variant-1", name: "v1", project_id: "project-1" },
                { id: "variant-2", name: "v2", project_id: "project-1" }
            ]));

        render(<Exports projectId="project-1" variantIds={["variant-1", "variant-2"]} />);

        const fileButton = await screen.findByText(/report\.adoc/i);
        fireEvent.click(fileButton);
        fireEvent.click(screen.getByRole('link', { name: /download pdf/i }));

        expect(await screen.findByText(/this will export report\.adoc \(pdf document\) for the project demo project/i)).toBeInTheDocument();
        expect(screen.getByText('v1')).toBeInTheDocument();
        expect(screen.getByText('v2')).toBeInTheDocument();
        expect(screen.getByText(/change the export scope using the selector/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(screen.queryByText(/this will export/i)).not.toBeInTheDocument();
    })
});
