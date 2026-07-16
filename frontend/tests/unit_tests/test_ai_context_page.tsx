import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import "@testing-library/jest-dom";
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();
// @ts-expect-error TS6133
import React from 'react';

import AIContext from '../../src/pages/AIContext';

beforeEach(() => fetchMock.resetMocks());

function mockProjectsAndVariants() {
    // Projects list
    fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
}

describe('AIContext page', () => {

    test('renders project and variant dropdowns', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        expect(await screen.findByLabelText("Project")).toBeInTheDocument();
    });

    test('project description textarea is disabled when no project selected', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        await screen.findByLabelText("Project");
        const descField = screen.getByLabelText("Project Description");
        expect(descField).toBeDisabled();
    });

    test('project description is enabled after project selection', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants.list('p1') called when project changes
        fetchMock.mockResponseOnce(JSON.stringify([]));
        // getProject call
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'existing desc' }));

        render(<AIContext />);
        // Wait for projects to load, then select a project
        await screen.findByRole('option', { name: 'Project A' });
        const projectSelect = screen.getByLabelText("Project");
        fireEvent.change(projectSelect, { target: { value: 'p1' } });

        await waitFor(() => {
            const descField = screen.getByLabelText("Project Description");
            expect(descField).not.toBeDisabled();
        });
    });

    test('variant-bound fields are disabled when no variant selected', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants.list('p1')
        fetchMock.mockResponseOnce(JSON.stringify([]));
        // getProject call after project selection
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        const projectSelect = screen.getByLabelText("Project");
        fireEvent.change(projectSelect, { target: { value: 'p1' } });

        await waitFor(() => {
            const threatModel = screen.getByLabelText(/threat model/i);
            expect(threatModel).toBeDisabled();
        });
    });

    test('save button is disabled when no project selected', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        await screen.findByLabelText("Project");
        const saveBtn = screen.getByRole('button', { name: /save/i });
        expect(saveBtn).toBeDisabled();
    });

    test('save button calls saveProject when project-only save', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants.list('p1')
        fetchMock.mockResponseOnce(JSON.stringify([]));
        // getProject
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        // saveProject response
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'My proj' }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        const projectSelect = screen.getByLabelText("Project");
        fireEvent.change(projectSelect, { target: { value: 'p1' } });

        const descField = await screen.findByLabelText("Project Description");
        await waitFor(() => expect(descField).not.toBeDisabled());
        fireEvent.change(descField, { target: { value: 'My proj' } });

        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            const calls = fetchMock.mock.calls;
            const putCall = calls.find(c =>
                typeof c[0] === 'string' && c[0].includes('/api/projects/p1/context') &&
                (c[1] as RequestInit)?.method === 'PUT'
            );
            expect(putCall).toBeDefined();
        });
    });

    test('shows validation error when project description is empty on save', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants.list('p1')
        fetchMock.mockResponseOnce(JSON.stringify([]));
        // getProject
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        const projectSelect = screen.getByLabelText("Project");
        fireEvent.change(projectSelect, { target: { value: 'p1' } });

        const descField = await screen.findByLabelText("Project Description");
        await waitFor(() => expect(descField).not.toBeDisabled());
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            expect(screen.getByText(/project description.*required/i)).toBeInTheDocument();
        });
    });

    test('file input is disabled when no variant selected', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants.list('p1')
        fetchMock.mockResponseOnce(JSON.stringify([]));
        // getProject
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        const projectSelect = screen.getByLabelText("Project");
        fireEvent.change(projectSelect, { target: { value: 'p1' } });

        await waitFor(() => {
            const fileInput = screen.getByLabelText(/supplemental files/i);
            expect(fileInput).toBeDisabled();
        });
    });

    test('shows error banner when project load fails', async () => {
        fetchMock.mockRejectOnce(new Error('Network error'));
        render(<AIContext />);
        await waitFor(() => {
            expect(screen.getByText(/network error/i)).toBeInTheDocument();
        });
    });

    test('saves variant context when variant is selected', async () => {
        // Projects list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // Variants list
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        // getProject after project select
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        // Context.get after variant select
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null,
            variant_id: 'v1', variant_description: null,
            environment: null, threat_model: null,
            risks: null, other_info: null, files: [],
        }));
        // saveProject response
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
        // saveVariant response
        fetchMock.mockResponseOnce(JSON.stringify({
            variant_id: 'v1', variant_description: null, environment: null,
            threat_model: 'High', risks: null, other_info: null, files: [],
        }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });

        // Wait for variant option to appear
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        // Wait for context to load (threat model enabled)
        await waitFor(() => expect(screen.getByLabelText(/threat model/i)).not.toBeDisabled());

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc' } });
        fireEvent.change(screen.getByLabelText(/threat model/i), { target: { value: 'High' } });

        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            const calls = fetchMock.mock.calls;
            const variantPut = calls.find(c =>
                typeof c[0] === 'string' && c[0].includes('/api/variants/v1/context') &&
                (c[1] as RequestInit)?.method === 'PUT'
            );
            expect(variantPut).toBeDefined();
        });
    });

    test('shows success banner after successful save', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Saved' }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });

        await waitFor(() => expect(screen.getByLabelText("Project Description")).not.toBeDisabled());
        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'My project' } });
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            expect(screen.getByText(/context saved successfully/i)).toBeInTheDocument();
        });
    });

    test('shows error banner when save fails', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        // saveProject fails
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Server error' }), { status: 500 });

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });

        await waitFor(() => expect(screen.getByLabelText("Project Description")).not.toBeDisabled());
        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc' } });
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            expect(screen.getByText(/server error/i)).toBeInTheDocument();
        });
    });

    test('file upload adds file to list', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        // Context.get after variant select
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null,
            risks: null, other_info: null, files: [],
        }));
        // upload response
        fetchMock.mockResponseOnce(JSON.stringify({ id: 'f1', original_name: 'doc.pdf' }), { status: 201 });

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        await waitFor(() => expect(screen.getByLabelText(/supplemental files/i)).not.toBeDisabled());

        const file = new File(['content'], 'doc.pdf', { type: 'application/pdf' });
        fireEvent.change(screen.getByLabelText(/supplemental files/i), { target: { files: [file] } });

        await waitFor(() => {
            expect(screen.getByText('doc.pdf')).toBeInTheDocument();
        });
    });

    test('file upload sends and displays description', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null,
            risks: null, other_info: null, files: [],
        }));
        fetchMock.mockResponseOnce(
            JSON.stringify({ id: 'f1', original_name: 'doc.pdf', description: 'design notes' }),
            { status: 201 }
        );

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        await waitFor(() => expect(screen.getByLabelText(/supplemental files/i)).not.toBeDisabled());

        fireEvent.change(screen.getByLabelText("File Description"), { target: { value: 'design notes' } });
        const file = new File(['content'], 'doc.pdf', { type: 'application/pdf' });
        fireEvent.change(screen.getByLabelText(/supplemental files/i), { target: { files: [file] } });

        await waitFor(() => {
            expect(screen.getByText('design notes')).toBeInTheDocument();
        });

        const uploadCall = fetchMock.mock.calls.find(c => String(c[0]).includes('/context/files') && c[1]?.method === 'POST');
        expect(uploadCall).toBeDefined();
        const body = uploadCall![1]!.body as FormData;
        expect(body.get('description')).toBe('design notes');

        // description input resets after successful upload
        expect(screen.getByLabelText("File Description")).toHaveValue('');
    });

    test('delete file button removes file from list', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null,
            risks: null, other_info: null,
            files: [{ id: 'f1', original_name: 'existing.txt' }],
        }));
        // delete response
        fetchMock.mockResponseOnce('', { status: 204 });

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        await screen.findByText('existing.txt');
        fireEvent.click(screen.getByRole('button', { name: /delete existing\.txt/i }));

        await waitFor(() => {
            expect(screen.queryByText('existing.txt')).not.toBeInTheDocument();
        });
    });

    test('clears variant fields when project changes', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: 'Old desc', environment: null, threat_model: 'TM',
            risks: null, other_info: null, files: [],
        }));
        // Switch project: new variants list (empty), new getProject
        fetchMock.mockResponseOnce(JSON.stringify([]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        // Wait for threat model to be populated
        await waitFor(() => {
            const tm = screen.getByLabelText(/threat model/i) as HTMLTextAreaElement;
            expect(tm.value).toBe('TM');
        });

        // Now change project — variant fields should clear
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: '' } });

        await waitFor(() => {
            const tm = screen.getByLabelText(/threat model/i) as HTMLTextAreaElement;
            expect(tm.value).toBe('');
        });
    });

    function setupWithVariant() {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null,
            risks: null, other_info: null, files: [],
        }));
    }

    async function selectProjectAndVariant() {
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
        await waitFor(() => expect(screen.getByLabelText(/supplemental files/i)).not.toBeDisabled());
    }

    test('shows error banner when variant save fails', async () => {
        setupWithVariant();
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'D' }));
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Variant save failed' }), { status: 500 });

        render(<AIContext />);
        await selectProjectAndVariant();

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc' } });
        fireEvent.change(screen.getByLabelText(/threat model/i), { target: { value: 'TM' } });
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            expect(screen.getByText(/variant context failed/i)).toBeInTheDocument();
        });
    });

    test('shows file size error when file is too large', async () => {
        setupWithVariant();
        render(<AIContext />);
        await selectProjectAndVariant();

        const largeFile = new File([new ArrayBuffer(11 * 1024 * 1024)], 'big.bin');
        Object.defineProperty(largeFile, 'size', { value: 11 * 1024 * 1024 });
        fireEvent.change(screen.getByLabelText(/supplemental files/i), { target: { files: [largeFile] } });

        await waitFor(() => {
            expect(screen.getByText(/10 MB maximum/i)).toBeInTheDocument();
        });
    });

    test('shows error when file upload fails', async () => {
        setupWithVariant();
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Upload failed on server' }), { status: 500 });

        render(<AIContext />);
        await selectProjectAndVariant();

        const file = new File(['data'], 'test.txt');
        fireEvent.change(screen.getByLabelText(/supplemental files/i), { target: { files: [file] } });

        await waitFor(() => {
            expect(screen.getByText(/upload failed on server/i)).toBeInTheDocument();
        });
    });

    test('shows error banner when delete file fails', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null,
            risks: null, other_info: null,
            files: [{ id: 'f1', original_name: 'keep.txt' }],
        }));
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Delete failed' }), { status: 500 });

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
        await screen.findByText('keep.txt');

        fireEvent.click(screen.getByRole('button', { name: /delete keep\.txt/i }));

        await waitFor(() => {
            expect(screen.getByText(/delete failed/i)).toBeInTheDocument();
        });
    });

    test('can type in variant-bound fields after variant selected', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        // project selection triggers: variants list + Context.getProject
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        // variant selection triggers: Context.get
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: null, risks: null, other_info: null, files: []
        }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        await waitFor(() => {
            expect(screen.getByLabelText("Variant Description")).not.toBeDisabled();
        });

        fireEvent.change(screen.getByLabelText("Variant Description"), { target: { value: 'New variant desc' } });
        fireEvent.change(screen.getByLabelText("Codebase Path"), { target: { value: '/home/user/src/myproject' } });
        fireEvent.change(screen.getByLabelText("Environment"), { target: { value: 'Linux runtime' } });
        fireEvent.change(screen.getByLabelText("Risks"), { target: { value: 'Some risk' } });
        fireEvent.change(screen.getByLabelText("Other Information"), { target: { value: 'Extra info' } });

        expect(screen.getByLabelText("Variant Description")).toHaveValue('New variant desc');
        expect(screen.getByLabelText("Codebase Path")).toHaveValue('/home/user/src/myproject');
        expect(screen.getByLabelText("Environment")).toHaveValue('Linux runtime');
        expect(screen.getByLabelText("Risks")).toHaveValue('Some risk');
        expect(screen.getByLabelText("Other Information")).toHaveValue('Extra info');
    });

    test('loads and saves the codebase path from an existing variant context', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, codebase_path: '/existing/path', environment: null,
            threat_model: 'TM', risks: null, other_info: null, files: []
        }));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'desc' }));
        fetchMock.mockResponseOnce(JSON.stringify({
            variant_id: 'v1', variant_description: null, codebase_path: '/updated/path',
            environment: null, threat_model: 'TM', risks: null, other_info: null, files: []
        }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

        await waitFor(() => {
            expect(screen.getByLabelText("Codebase Path")).toHaveValue('/existing/path');
        });

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'desc' } });
        fireEvent.change(screen.getByLabelText("Codebase Path"), { target: { value: '/updated/path' } });
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            const call = fetchMock.mock.calls.find(c =>
                String(c[0]).includes('/api/variants/v1/context') && (c[1] as any)?.method === 'PUT'
            );
            expect(call).toBeDefined();
            expect(JSON.parse((call![1] as any).body)).toMatchObject({ codebase_path: '/updated/path' });
        });
    });

    test('shows error banner when variant load fails', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockRejectOnce(new Error('Variant fetch error'));
        // getProject may also fail — provide a response to avoid noise
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });

        await waitFor(() => {
            expect(document.querySelector('[role="alert"]')).toBeInTheDocument();
        });
    });
});
