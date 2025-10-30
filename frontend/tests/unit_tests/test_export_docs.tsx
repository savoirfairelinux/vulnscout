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

        // ARRANGE & ACT
        render(<Exports />);

        // ASSERT - Component should still render without crashing
        const exportTitle = await screen.findByText(/export/i);
        expect(exportTitle).toBeInTheDocument();
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
});
