import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import Exports from '../../src/pages/Exports';

const documents = [
    { id: 'summary.adoc', category: ['built-in'], extension: 'adoc | pdf' },
    { id: 'assets/lolcat.jpg', category: ['custom'], extension: 'jpg' },
    { id: 'SPDX 2.3', category: ['sbom'], extension: 'json | xml' },
    { id: 'CycloneDX 1.6', category: ['sbom'], extension: 'json' },
    { id: 'logo.png', category: ['assets'], extension: 'png' },
];

function loadProject() {
    fetchMock
        .mockResponseOnce(JSON.stringify(documents))
        .mockResponseOnce(JSON.stringify([{ id: 'project-1', name: 'Demo Project' }]))
        .mockResponseOnce(JSON.stringify([
            { id: 'variant-1', name: 'alpha', project_id: 'project-1' },
            { id: 'variant-2', name: 'beta', project_id: 'project-1' },
        ]));
}

describe('Exports Page', () => {
    beforeEach(() => fetchMock.resetMocks());

    test('shows the in-page wizard and Settings management reminder', async () => {
        fetchMock
            .mockResponseOnce(JSON.stringify(documents))
            .mockResponseOnce(JSON.stringify([]));

        render(<Exports />);

        expect(await screen.findByRole('heading', { name: 'Export' })).toBeInTheDocument();
        expect(screen.getByRole('region', { name: 'Create export' })).toBeInTheDocument();
        expect(screen.getByText(/Settings > Custom reports & assets/i)).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /upload a custom report or asset/i })).not.toBeInTheDocument();
    });

    test('shows report layout with export type before document selection', async () => {
        loadProject();
        render(<Exports projectId="project-1" variantId="variant-1" variantIds={['variant-1']} />);

        expect(await screen.findByText(/choose the variants to export/i)).toHaveTextContent('Demo Project');
        const alpha = screen.getByRole('checkbox', { name: 'alpha' });
        const beta = screen.getByRole('checkbox', { name: 'beta' });
        expect(alpha).toBeChecked();
        expect(beta).toBeChecked();
        fireEvent.click(beta);

        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        fireEvent.click(screen.getByRole('radio', { name: /^Reports/i }));
        expect(screen.getByRole('heading', { name: 'Output layout' })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('radio', { name: /one set per variant/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));

        expect(screen.queryByRole('checkbox', { name: /logo\.png/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('checkbox', { name: /lolcat\.jpg/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Custom assets' })).not.toBeInTheDocument();
        const summary = screen.getByRole('group', { name: 'summary.adoc' });
        const adoc = within(summary).getByRole('checkbox', { name: /^adoc$/i });
        const pdf = within(summary).getByRole('checkbox', { name: /^pdf$/i });
        expect(adoc).toBeDisabled();
        expect(pdf).toBeDisabled();
        const includeSummary = within(summary).getByRole('checkbox', { name: 'Include' });
        expect(within(summary).queryByRole('checkbox', { name: 'summary.adoc' })).not.toBeInTheDocument();
        fireEvent.click(includeSummary);
        expect(adoc).toBeEnabled();
        expect(pdf).toBeEnabled();
        fireEvent.click(adoc);
        expect(screen.queryByRole('checkbox', { name: /cyclonedx/i })).not.toBeInTheDocument();

        fetchMock
            .mockResponseOnce(JSON.stringify({ job_id: 'export-job-1' }), { status: 202 })
            .mockResponseOnce(JSON.stringify({
                status: 'done', current: 1, total: 1, progress: 'Export ready', logs: ['Generating 1 of 1 element: summary.adoc (adoc)'], error: null,
            }))
            .mockResponseOnce('zip-content', {
            headers: {
                'Content-Type': 'application/zip',
                'Content-Disposition': 'attachment; filename="Demo_Project_by_variant_export.zip"',
            },
            });
        const createObjectURL = jest.fn(() => 'blob:export');
        const revokeObjectURL = jest.fn();
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL });
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        fireEvent.click(screen.getByRole('button', { name: /download export/i }));

        await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/documents/export'),
            expect.objectContaining({ method: 'POST' }),
        ));
        const exportRequest = fetchMock.mock.calls.find(([, request]) => request?.method === 'POST');
        expect(JSON.parse(String(exportRequest?.[1]?.body))).toEqual({
            async: true,
            project_id: 'project-1',
            variant_ids: ['variant-1'],
            mode: 'per_variant',
            documents: [
                { name: 'summary.adoc', extension: 'adoc' },
            ],
        });
        await waitFor(() => expect(click).toHaveBeenCalled());

        expect(createObjectURL).toHaveBeenCalled();
        expect(revokeObjectURL).toHaveBeenCalledWith('blob:export');
        delete (URL as Partial<typeof URL>).createObjectURL;
        delete (URL as Partial<typeof URL>).revokeObjectURL;
        click.mockRestore();
    });

    test('focuses each step heading after wizard navigation', async () => {
        loadProject();
        render(<Exports projectId="project-1" />);

        await screen.findByRole('checkbox', { name: 'alpha' });
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        expect(screen.getByRole('heading', { name: 'What do you want to export?' })).toHaveFocus();

        fireEvent.click(screen.getByRole('radio', { name: /^Reports/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        expect(screen.getByRole('heading', { name: 'Select reports' })).toHaveFocus();

        fireEvent.click(screen.getByRole('button', { name: 'Back' }));
        expect(screen.getByRole('heading', { name: 'What do you want to export?' })).toHaveFocus();
    });

    test('skips layout and forces per-variant ZIP for SBOM exports', async () => {
        loadProject();
        render(<Exports projectId="project-1" />);

        await screen.findByRole('checkbox', { name: 'alpha' });
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        fireEvent.click(screen.getByRole('radio', { name: /^SBOM files/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));

        expect(screen.getByRole('heading', { name: 'Select SBOM files' })).toBeInTheDocument();
        expect(screen.queryByRole('radio', { name: /Consolidated/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('checkbox', { name: /summary\.adoc/i })).not.toBeInTheDocument();
        const spdx = screen.getByRole('group', { name: 'SPDX 2.3' });
        const spdxJson = within(spdx).getByRole('checkbox', { name: /json/i });
        const spdxXml = within(spdx).getByRole('checkbox', { name: /xml/i });
        expect(spdxJson).toBeDisabled();
        expect(spdxXml).toBeDisabled();
        fireEvent.click(within(spdx).getByRole('checkbox', { name: 'Include' }));
        expect(spdxJson).toBeEnabled();
        expect(spdxXml).toBeEnabled();
        fireEvent.click(spdxXml);
        expect(spdxXml).toBeChecked();
        fireEvent.click(within(spdx).getByRole('checkbox', { name: 'Include' }));
        expect(spdxXml).toBeDisabled();
        expect(spdxXml).not.toBeChecked();
        fireEvent.click(within(spdx).getByRole('checkbox', { name: 'Include' }));
        fireEvent.click(spdxXml);

        const cycloneDx = screen.getByRole('group', { name: 'CycloneDX 1.6' });
        fireEvent.click(within(cycloneDx).getByRole('checkbox', { name: 'Include' }));
        const cycloneDxJson = within(cycloneDx).getByRole('checkbox', { name: /json/i });
        expect(cycloneDxJson).toBeChecked();
        expect(cycloneDxJson).toBeDisabled();

        fetchMock
            .mockResponseOnce(JSON.stringify({ job_id: 'export-job-2' }), { status: 202 })
            .mockResponseOnce(JSON.stringify({
                status: 'done', current: 4, total: 4, progress: 'Export ready', logs: ['Generating 4 of 4 element: beta: CycloneDX 1.6 (json)'], error: null,
            }))
            .mockResponseOnce('zip-content', {
                headers: { 'Content-Type': 'application/zip' },
            });
        Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: jest.fn(() => 'blob:sbom') });
        Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: jest.fn() });
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        fireEvent.click(screen.getByRole('button', { name: /download export/i }));

        await waitFor(() => expect(click).toHaveBeenCalled());
        const exportRequest = fetchMock.mock.calls.find(([, request]) => request?.method === 'POST');
        expect(JSON.parse(String(exportRequest?.[1]?.body))).toEqual({
            async: true,
            project_id: 'project-1',
            variant_ids: ['variant-1', 'variant-2'],
            mode: 'per_variant',
            documents: [
                { name: 'SPDX 2.3', extension: 'xml' },
                { name: 'CycloneDX 1.6', extension: 'json' },
            ],
        });

        delete (URL as Partial<typeof URL>).createObjectURL;
        delete (URL as Partial<typeof URL>).revokeObjectURL;
        click.mockRestore();
    });

    test('requires at least one selected variant', async () => {
        loadProject();
        render(<Exports projectId="project-1" />);

        await screen.findByRole('checkbox', { name: 'alpha' });
        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

        expect(screen.getByText(/0 of 2 selected/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Select all' }));
        expect(screen.getByText(/2 of 2 selected/i)).toBeInTheDocument();
    });

    test('selects and clears all reports visible in a category', async () => {
        loadProject();
        render(<Exports projectId="project-1" />);

        await screen.findByRole('checkbox', { name: 'alpha' });
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        fireEvent.click(screen.getByRole('radio', { name: /^Reports/i }));
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));

        fireEvent.click(screen.getByRole('button', { name: 'Built-in reports' }));
        fireEvent.click(screen.getByRole('button', { name: 'Select visible' }));
        expect(screen.getByText('2 selected')).toBeInTheDocument();
        expect(within(screen.getByRole('group', { name: 'summary.adoc' })).getByRole('checkbox', { name: 'Include' })).toBeChecked();

        fireEvent.click(screen.getByRole('button', { name: 'Clear visible' }));
        expect(screen.getByText('0 selected')).toBeInTheDocument();
        expect(within(screen.getByRole('group', { name: 'summary.adoc' })).getByRole('checkbox', { name: 'Include' })).not.toBeChecked();
    });

    test('requires a navbar project selection', async () => {
        fetchMock
            .mockResponseOnce(JSON.stringify(documents))
            .mockResponseOnce(JSON.stringify([]));
        render(<Exports />);

        expect(await screen.findByText(/select a project from the navigation bar/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    });

    test('ignores variants returned for an earlier project', async () => {
        let resolveFirst: (value: Response) => void = () => undefined;
        fetchMock
            .mockResponseOnce(JSON.stringify(documents))
            .mockResponseOnce(JSON.stringify([
                { id: 'project-1', name: 'First' },
                { id: 'project-2', name: 'Second' },
            ]))
            .mockImplementationOnce(() => new Promise<Response>(resolve => { resolveFirst = resolve; }))
            .mockResponseOnce(JSON.stringify([
                { id: 'variant-2', name: 'second variant', project_id: 'project-2' },
            ]));
        const { rerender } = render(<Exports projectId="project-1" />);
        rerender(<Exports projectId="project-2" />);

        expect(await screen.findByRole('checkbox', { name: 'second variant' })).toBeInTheDocument();
        resolveFirst(new Response(JSON.stringify([
            { id: 'variant-1', name: 'first variant', project_id: 'project-1' },
        ]), { status: 200 }));

        await waitFor(() => expect(screen.queryByRole('checkbox', { name: 'first variant' })).not.toBeInTheDocument());
    });
});