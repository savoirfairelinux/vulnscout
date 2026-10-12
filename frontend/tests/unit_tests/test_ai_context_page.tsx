import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import "@testing-library/jest-dom";
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();
// @ts-expect-error TS6133
import React from 'react';

import AIContext from '../../src/pages/AIContext';
import { AGENT_WRITE_EVENT, type AgentViewContext } from '../../src/types/agent';
import {
    emptyRisk, emptyThreatModel, parseRiskRegister, parseThreatModel, serializeRiskRegister, serializeThreatModel,
} from '../../src/helpers/strideContext';
import type { StrideContextText, StrideEditorMode } from '../../src/helpers/strideContext';
import type { VariantContextData } from '../../src/handlers/context';

beforeEach(() => fetchMock.resetMocks());

function mockProjectsAndVariants() {
    // Projects list
    fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
}

function selectContextTab(name: "Context" | "System" | "Threat model" | "Risks" | "Summary") {
    fireEvent.click(screen.getByRole("tab", { name }));
}

function switchContextMode(value: "stride" | "free") {
    const selectedTab = screen.getByRole("tab", { selected: true });
    selectContextTab("Context");
    fireEvent.change(screen.getByRole("combobox", { name: "Editor mode" }), { target: { value } });
    fireEvent.click(selectedTab);
}

describe('AIContext page', () => {

    test('dropped references preserve unsaved fields and reload for the selected variant', async () => {
        const reference = { id: 'f1', original_name: 'source.zip', description: null };
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Saved project' }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', variant_id: 'v1', threat_model: 'Saved threat', files: [],
        }));
        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
        await waitFor(() => expect(screen.getByLabelText('Upload codebase references')).not.toBeDisabled());
        fireEvent.change(screen.getByLabelText('Threat Model'), { target: { value: 'Unsaved threat' } });
        fireEvent.change(screen.getByLabelText('Codebase Path'), { target: { value: '/external/source' } });
        fetchMock.mockResponseOnce('[]');
        fetchMock.mockResponseOnce(JSON.stringify(reference), { status: 201 });
        fireEvent.drop(screen.getByRole('region', { name: 'Drop codebase files' }), {
            dataTransfer: { files: [new File(['source'], 'source.zip')] },
        });
        await screen.findByRole('button', { name: 'Delete reference source.zip' });
        expect(screen.getByLabelText('Threat Model')).toHaveValue('Unsaved threat');
        expect(screen.getByLabelText('Codebase Path')).toHaveValue('/external/source');
        expect(fetchMock.mock.calls.some(([, options]) => options?.method === 'PUT')).toBe(false);
        fireEvent.change(screen.getByLabelText('Variant'), { target: { value: '' } });
        expect(screen.queryByRole('button', { name: 'Delete reference source.zip' })).not.toBeInTheDocument();
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', variant_id: 'v1', threat_model: 'Saved threat', files: [reference],
        }));
        fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
        await screen.findByRole('button', { name: 'Delete reference source.zip' });
        expect(screen.getByLabelText('Threat Model')).toHaveValue('Saved threat');
    });

    test('renders project and variant dropdowns', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        expect(await screen.findByLabelText("Project")).toBeInTheDocument();
    });

    test('defaults to Context and groups fields under accessible subtabs with shared actions', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        const tablist = screen.getByRole('tablist', { name: 'AI context sections' });
        expect(tablist).toBeVisible();
        expect(tablist).toHaveClass('flex-wrap', 'p-1');
        expect(tablist).not.toHaveClass('overflow-x-auto');
        expect(screen.queryByText('Describe the project, this variant and its operating environment.')).not.toBeInTheDocument();
        for (const name of ['Context', 'System', 'Threat model', 'Risks', 'Summary'] as const) {
            if (name !== 'Context') selectContextTab(name);
            const tab = screen.getByRole('tab', { name });
            const panel = screen.getByRole('tabpanel', { name });
            expect(tab).toHaveAttribute('aria-selected', 'true');
            expect(tab).toHaveAttribute('tabindex', '0');
            expect(panel).toHaveAttribute('id', tab.getAttribute('aria-controls'));
            expect(panel).toHaveAttribute('aria-labelledby', tab.id);
            expect(screen.getAllByRole('tabpanel')).toHaveLength(1);
            expect(screen.getAllByRole('tabpanel', { hidden: true })).toHaveLength(5);
            expect(screen.getAllByLabelText('Editor mode')).toHaveLength(1);
            if (name === 'Context') {
                expect(panel).toContainElement(screen.getByRole('combobox', { name: 'Editor mode' }));
                expect(screen.getByLabelText('Editor mode')).toHaveAccessibleDescription('Applies to System, Threat model and Risks.');
                const mode = screen.getByLabelText('Editor mode');
                const modeTitle = screen.getByText('Editor mode', { selector: 'label' });
                const modeHelp = screen.getByText('Applies to System, Threat model and Risks.');
                expect(modeTitle).toHaveClass('mb-1');
                expect(modeTitle.nextElementSibling).toBe(modeHelp);
                expect(modeHelp).toHaveClass('mb-1');
                expect(modeHelp.nextElementSibling).toBe(mode);
                const environment = screen.getByLabelText('Environment');
                expect(environment).toHaveAccessibleDescription('Describe the target platform, operating system and deployment conditions.');
                const environmentTitle = screen.getByText('Environment', { selector: 'label' });
                const environmentHelp = screen.getByText('Describe the target platform, operating system and deployment conditions.');
                expect(environmentTitle).toHaveClass('mb-1');
                expect(environmentTitle.nextElementSibling).toBe(environmentHelp);
                expect(environmentHelp).toHaveClass('mb-1');
                expect(environmentHelp.nextElementSibling).toBe(environment);
                const codebaseGroup = screen.getByRole('group', { name: 'Codebase Paths' });
                expect(codebaseGroup).toHaveAccessibleDescription('Source code locations visible to the assessment tool.');
                expect(codebaseGroup).not.toHaveClass('space-y-3');
                const codebaseTitle = screen.getByText('Codebase Paths', { selector: 'legend' });
                const codebaseHelp = screen.getByText('Source code locations visible to the assessment tool.');
                expect(codebaseTitle).toHaveClass('mb-1');
                expect(codebaseTitle.nextElementSibling).toBe(codebaseHelp);
                expect(codebaseHelp).toHaveClass('mb-1');
                expect(screen.getByLabelText('Environment').compareDocumentPosition(mode) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
                expect(mode.compareDocumentPosition(screen.getByLabelText('Other Information')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
            } else {
                expect(screen.getByLabelText('Editor mode')).not.toBeVisible();
                expect(screen.queryByRole('combobox', { name: 'Editor mode' })).not.toBeInTheDocument();
            }
            for (const label of ['System scope and assets', 'Actors and access', 'Entry points and data flows', 'Trust boundaries']) {
                if (name === 'System') expect(screen.getByLabelText(label)).toBeVisible();
                else expect(screen.getByLabelText(label)).not.toBeVisible();
            }
            for (const label of ['Project Description', 'Variant Description', 'Codebase Path 1', 'Environment', 'Other Information']) {
                if (name === 'Context') expect(screen.getByLabelText(label)).toBeVisible();
                else expect(screen.getByLabelText(label)).not.toBeVisible();
            }
            if (name === 'Threat model') expect(screen.getByRole('button', { name: 'Add threat' })).toBeVisible();
            else expect(screen.queryByRole('button', { name: 'Add threat' })).not.toBeInTheDocument();
            if (name === 'Risks') expect(screen.getByRole('button', { name: 'Add risk' })).toBeVisible();
            else expect(screen.queryByRole('button', { name: 'Add risk' })).not.toBeInTheDocument();
            expect(screen.getByLabelText('Project')).toBeVisible();
            expect(screen.getByLabelText('Variant')).toBeVisible();
            expect(screen.getByRole('button', { name: 'Import context' })).toBeVisible();
            expect(screen.getByRole('button', { name: 'Export context' })).toBeVisible();
            if (name === 'Summary') expect(screen.queryByRole('button', { name: /^save /i })).not.toBeInTheDocument();
            else expect(within(panel).getByRole('button', { name: `Save ${name}` })).toBeVisible();
        }
    });

    test('subtabs support wrapping arrow keys and Home/End with roving keyboard focus', async () => {
        mockProjectsAndVariants();
        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        screen.getByRole('tab', { name: 'Context' }).focus();
        for (const [key, name] of [
            ['ArrowRight', 'System'], ['ArrowRight', 'Threat model'], ['ArrowRight', 'Risks'], ['ArrowRight', 'Summary'], ['ArrowRight', 'Context'],
            ['ArrowLeft', 'Summary'], ['ArrowLeft', 'Risks'], ['ArrowLeft', 'Threat model'], ['ArrowLeft', 'System'], ['Home', 'Context'], ['End', 'Summary'],
        ]) {
            fireEvent.keyDown(document.activeElement!, { key });
            const selected = screen.getByRole('tab', { name });
            expect(selected).toHaveFocus();
            expect(selected).toHaveAttribute('aria-selected', 'true');
            expect(selected).toHaveAttribute('tabindex', '0');
            for (const tab of screen.getAllByRole('tab')) {
                if (tab !== selected) {
                    expect(tab).toHaveAttribute('aria-selected', 'false');
                    expect(tab).toHaveAttribute('tabindex', '-1');
                }
            }
            expect(screen.getByRole('tabpanel', { name })).toBeVisible();
        }
        fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
        expect(screen.getByRole('tab', { name: 'Summary' })).toHaveFocus();
        expect(screen.getByRole('tabpanel', { name: 'Summary' })).toBeVisible();
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
            const threatModel = screen.getByLabelText("System scope and assets");
            expect(threatModel).toBeDisabled();
        });
        expect(screen.getByLabelText("Codebase Path 1")).toBeDisabled();
        expect(screen.getByRole("button", { name: "Add Codebase Path" })).toBeDisabled();
        expect(screen.getByRole("button", { name: "Remove Codebase Path 1" })).toBeDisabled();
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
        fetchMock.mockResponseOnce(JSON.stringify([])); // pending AI assessments check
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

        await waitFor(() => expect(screen.getByLabelText("Editor mode")).not.toBeDisabled());
        selectContextTab("Threat model");
        expect(screen.getByLabelText("Editor mode")).toHaveValue("stride");
        switchContextMode("free");

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc' } });
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: 'High' } });

        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            const calls = fetchMock.mock.calls;
            const variantPut = calls.find(c =>
                typeof c[0] === 'string' && c[0].includes('/api/variants/v1/context') &&
                (c[1] as RequestInit)?.method === 'PATCH'
            );
            expect(variantPut).toBeDefined();
            expect(JSON.parse(String(variantPut![1]?.body))).toMatchObject({ threat_model: 'High' });
            expect(JSON.parse(String(variantPut![1]?.body))).not.toHaveProperty('risks');
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
            expect(screen.getByText(/saved successfully/i)).toBeInTheDocument();
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
            const tm = screen.getByLabelText("Threat Model", { selector: "textarea" }) as HTMLTextAreaElement;
            expect(tm.value).toBe('TM');
        });

        // Now change project — variant fields should clear
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: '' } });

        await waitFor(() => {
            const tm = screen.getByLabelText("System scope and assets") as HTMLTextAreaElement;
            expect(tm.value).toBe('');
        });
    });

    test('keeps unsaved project description when variant changes', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
        fetchMock.mockResponseOnce(JSON.stringify([
            { id: 'v1', name: 'Variant 1', project_id: 'p1' },
            { id: 'v2', name: 'Variant 2', project_id: 'p1' },
        ]));
        // getProject: nothing stored yet for the project description
        fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: null }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v1',
            variant_description: null, environment: null, threat_model: 'TM1',
            risks: null, other_info: null, files: [],
        }));
        fetchMock.mockResponseOnce(JSON.stringify({
            project_id: 'p1', description: null, variant_id: 'v2',
            variant_description: null, environment: null, threat_model: 'TM2',
            risks: null, other_info: null, files: [],
        }));

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
        await waitFor(() => {
            const tm = screen.getByLabelText("Threat Model", { selector: "textarea" }) as HTMLTextAreaElement;
            expect(tm.value).toBe('TM1');
        });

        // Type a project description without saving, then switch variant
        fireEvent.change(screen.getByLabelText("Project Description"), {
            target: { value: 'Unsaved description' },
        });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v2' } });

        await waitFor(() => {
            const tm = screen.getByLabelText("Threat Model", { selector: "textarea" }) as HTMLTextAreaElement;
            expect(tm.value).toBe('TM2');
        });
        expect(
            (screen.getByLabelText("Project Description") as HTMLTextAreaElement).value
        ).toBe('Unsaved description');
    });

    test('agent context updates reload clean forms and keep unsaved edits', async () => {
        const requests: string[] = [];
        let stored = 'Agent v1';
        fetchMock.mockResponse(async request => {
            requests.push(request.url);
            if (request.url.endsWith('/api/projects')) return JSON.stringify([{ id: 'p1', name: 'Project A' }]);
            if (request.url.endsWith('/variants')) return JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]);
            if (request.url.endsWith('/api/projects/p1/context')) return JSON.stringify({ project_id: 'p1', description: stored });
            return JSON.stringify({
                project_id: 'p1', description: stored, variant_id: 'v1', variant_description: null,
                environment: null, threat_model: stored, risks: null, other_info: null, files: [],
            });
        });
        const agentWrite = (tool: string) => act(() => {
            window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool } }));
        });

        render(<AIContext />);
        await screen.findByRole('option', { name: 'Project A' });
        fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
        await screen.findByRole('option', { name: 'Variant 1' });
        fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
        await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('Agent v1'));
        await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Agent v1'));

        stored = 'Agent v2';
        agentWrite('update_project_context');
        agentWrite('update_variant_context');
        await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Agent v2'));
        await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('Agent v2'));

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Unsaved description' } });
        selectContextTab("Threat model");
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: 'Unsaved threat model' } });
        stored = 'Agent v3';
        const loaded = requests.length;
        agentWrite('update_project_context');
        expect(await screen.findByText(/agent updated the project description/i)).toBeInTheDocument();
        agentWrite('update_variant_context');
        expect(await screen.findByText(/agent updated the variant context/i)).toBeInTheDocument();
        expect(requests).toHaveLength(loaded);
        expect(screen.getByLabelText("Project Description")).toHaveValue('Unsaved description');
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue('Unsaved threat model');
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
        await waitFor(() => expect(screen.getByLabelText("System scope and assets")).not.toBeDisabled());
    }

    test('required field validation is scoped to the section being saved', async () => {
        setupWithVariant();
        render(<AIContext />);
        await selectProjectAndVariant();
        selectContextTab('Context');
        fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
        expect(screen.getByRole('tab', { name: 'Context' })).toHaveFocus();
        expect(screen.getByRole('tabpanel', { name: 'Context' })).toBeVisible();
        expect(screen.getByRole('alert')).toHaveTextContent('Project Description is required.');
        expect(screen.getByLabelText('Project Description')).toHaveAccessibleDescription('Project Description is required.');
        fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: 'Device firmware' } });
        selectContextTab('Threat model');
        fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
        expect(screen.getByRole('tab', { name: 'Threat model' })).toHaveFocus();
        expect(screen.getByRole('tabpanel', { name: 'Threat model' })).toBeVisible();
        expect(screen.getByRole('alert')).toHaveTextContent('Threat Model is required.');
        expect(fetchMock.mock.calls.some(call => (call[1] as RequestInit)?.method === 'PUT')).toBe(false);
    });

    test('shows error banner when variant save fails', async () => {
        setupWithVariant();
        fetchMock.mockResponseOnce(JSON.stringify([])); // pending AI assessments check
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'Variant save failed' }), { status: 500 });

        render(<AIContext />);
        await selectProjectAndVariant();

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc' } });
        fireEvent.change(screen.getByLabelText("System scope and assets"), { target: { value: 'TM' } });
        selectContextTab('System');
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            expect(screen.getByText(/variant save failed/i)).toBeInTheDocument();
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
        fireEvent.change(screen.getByLabelText("Codebase Path 1"), { target: { value: '/home/user/src/myproject' } });
        fireEvent.change(screen.getByLabelText("Environment"), { target: { value: 'Linux runtime' } });
        fireEvent.change(screen.getByLabelText("Risk 1 mitigation"), { target: { value: 'Some mitigation' } });
        fireEvent.change(screen.getByLabelText("Other Information"), { target: { value: 'Extra info' } });

        expect(screen.getByLabelText("Variant Description")).toHaveValue('New variant desc');
        expect(screen.getByLabelText("Codebase Path 1")).toHaveValue('/home/user/src/myproject');
        expect(screen.getByLabelText("Environment")).toHaveValue('Linux runtime');
        expect(screen.getByLabelText("Risk 1 mitigation")).toHaveValue('Some mitigation');
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
        fetchMock.mockResponseOnce(JSON.stringify([])); // pending AI assessments check
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
            expect(screen.getByLabelText("Codebase Path 1")).toHaveValue('/existing/path');
        });

        fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'desc' } });
        fireEvent.change(screen.getByLabelText("Codebase Path 1"), { target: { value: '/updated/path' } });
        fireEvent.click(screen.getByRole('button', { name: /save/i }));

        await waitFor(() => {
            const call = fetchMock.mock.calls.find(c =>
                String(c[0]).includes('/api/variants/v1/context') && (c[1] as any)?.method === 'PATCH'
            );
            expect(call).toBeDefined();
            expect(JSON.parse((call![1] as any).body)).toMatchObject({ codebase_path: '/updated/path' });
        });
    });

    describe('AI assessment outdating confirmation', () => {
        const aiRow = {
            id: 'a1', vuln_id: 'CVE-1', status: 'affected', timestamp: '2026-01-01T00:00:00Z',
            origin: 'ai', packages: [], responses: [],
        };

        async function loadVariantAndEdit(aiList: unknown[], saveResponses: unknown[] = []) {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: 'TM', risks: null, other_info: null, files: [],
            }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM'));
            await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Desc'));
            fetchMock.mockResponseOnce(JSON.stringify(aiList));
            saveResponses.forEach(r => fetchMock.mockResponseOnce(JSON.stringify(r)));
            selectContextTab("Threat model");
            fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: 'TM2' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
        }

        const putCalls = () => fetchMock.mock.calls.filter(c => ['PUT', 'PATCH'].includes((c[1] as RequestInit)?.method ?? ''));

        test('asks for confirmation and saves only after confirming', async () => {
            await loadVariantAndEdit([aiRow]);
            expect(await screen.findByText(/mark all pending AI assessments/i)).toBeInTheDocument();
            expect(
                await screen.findByText(/remain outdated until they are regenerated/i)
            ).toBeInTheDocument();
            expect(
                screen.queryByText(/restored to its previous content/i)
            ).not.toBeInTheDocument();
            expect(putCalls()).toHaveLength(0);

            fetchMock.mockResponseOnce(JSON.stringify({ variant_id: 'v1' }));
            fireEvent.click(screen.getByRole('button', { name: /save and mark outdated/i }));
            await waitFor(() => expect(putCalls().some(c => String(c[0]).includes('/api/variants/v1/context'))).toBe(true));
        });

        test('cancel leaves the context unsaved', async () => {
            await loadVariantAndEdit([aiRow]);
            fireEvent.click(await screen.findByRole('button', { name: /^cancel$/i }));
            await waitFor(() => expect(screen.queryByText(/mark all pending AI assessments/i)).not.toBeInTheDocument());
            expect(putCalls()).toHaveLength(0);
        });

        test('no confirmation when the variant has no pending AI assessments', async () => {
            await loadVariantAndEdit([], [{ variant_id: 'v1' }]);
            await waitFor(() => expect(putCalls().some(c => String(c[0]).includes('/api/variants/v1/context'))).toBe(true));
            expect(screen.queryByText(/mark all pending AI assessments/i)).not.toBeInTheDocument();
        });

        test('confirms when saving normalizes whitespace from stored context', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: ' TM ', risks: null, other_info: null, files: [],
            }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue(' TM '));

            fetchMock.mockResponseOnce(JSON.stringify([aiRow]));
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));

            expect(await screen.findByText(/mark all pending AI assessments/i)).toBeInTheDocument();
            expect(putCalls()).toHaveLength(0);
        });

        test('a failed context load blocks saving until a retry succeeds', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockRejectOnce(new Error('Context fetch error'));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });

            // Without a known baseline the page cannot tell whether a save would
            // change the context, so it must not save at all.
            const retry = await screen.findByRole('button', { name: /retry/i });
            for (const name of ['Context', 'Risks', 'Threat model'] as const) {
                selectContextTab(name);
                expect(retry).toBeVisible();
                expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeDisabled();
            }
            fireEvent.change(screen.getByLabelText("System scope and assets"), { target: { value: 'TM2' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            expect(putCalls()).toHaveLength(0);

            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: 'TM', risks: null, other_info: null, files: [],
            }));
            fireEvent.click(retry);
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM'));
            selectContextTab('Threat model');
            expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeEnabled();
        });

        test('switching variants mid-check does not confirm or save the wrong variant', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([
                { id: 'v1', name: 'Variant 1', project_id: 'p1' },
                { id: 'v2', name: 'Variant 2', project_id: 'p1' },
            ]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: 'TM1', risks: null, other_info: null, files: [],
            }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM1'));

            // The pending-AI check for v1 is still in flight when v2 is selected.
            let resolvePendingCheck: (value: any) => void = () => {};
            fetchMock.mockImplementationOnce(() => new Promise(resolve => {
                resolvePendingCheck = resolve;
            }));
            selectContextTab("Threat model");
            fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: 'TM2' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));

            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v2', variant_description: null,
                environment: null, threat_model: 'TM-V2', risks: null, other_info: null, files: [],
            }));
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM-V2'));

            await act(async () => {
                resolvePendingCheck({ status: 200, body: JSON.stringify([aiRow]) });
            });

            expect(screen.queryByText(/mark all pending AI assessments/i)).not.toBeInTheDocument();
            expect(putCalls()).toHaveLength(0);
        });

        test('disables saving while a newly selected variant context is loading', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([
                { id: 'v1', name: 'Variant 1', project_id: 'p1' },
                { id: 'v2', name: 'Variant 2', project_id: 'p1' },
            ]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: 'TM1', risks: null, other_info: null, files: [],
            }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM1'));
            expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeEnabled();

            fetchMock.mockImplementationOnce(() => new Promise(() => {}));
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v2' } });

            expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeDisabled();
        });

        async function loadVariantAndEditDescriptionOnly(aiList: unknown[], saveResponses: unknown[] = []) {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fetchMock.mockResponseOnce(JSON.stringify({
                project_id: 'p1', description: 'Desc', variant_id: 'v1', variant_description: null,
                environment: null, threat_model: 'TM', risks: null, other_info: null, files: [],
            }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText("Variant"), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText("Threat Model", { selector: "textarea" })).toHaveValue('TM'));
            await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Desc'));
            fetchMock.mockResponseOnce(JSON.stringify(aiList));
            saveResponses.forEach(r => fetchMock.mockResponseOnce(JSON.stringify(r)));
            fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc2' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
        }

        async function loadWithNoVariantAndEditDescription(aiList: unknown[], saveResponses: unknown[] = []) {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });
            await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Desc'));
            fetchMock.mockResponseOnce(JSON.stringify(aiList));
            saveResponses.forEach(r => fetchMock.mockResponseOnce(JSON.stringify(r)));
            fireEvent.change(screen.getByLabelText("Project Description"), { target: { value: 'Desc2' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
        }

        test('editing only the project description triggers the pending-AI check across the whole project', async () => {
            await loadVariantAndEditDescriptionOnly([aiRow]);
            expect(await screen.findByText(/mark all pending AI assessments/i)).toBeInTheDocument();
            expect(putCalls()).toHaveLength(0);

            const checkCall = fetchMock.mock.calls.find(c => String(c[0]).includes('/api/reviews/assessments'));
            expect(checkCall).toBeDefined();
            expect(String(checkCall![0])).not.toMatch(/variant_id=/);
            expect(String(checkCall![0])).toMatch(/project_id=p1/);
        });

        test('editing the project description with no variant selected also triggers the pending-AI check', async () => {
            await loadWithNoVariantAndEditDescription([aiRow]);
            expect(await screen.findByText(/mark all pending AI assessments/i)).toBeInTheDocument();
            expect(putCalls()).toHaveLength(0);
        });

        test('a failed project context load blocks saving until a retry succeeds', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fetchMock.mockRejectOnce(new Error('Project context fetch error'));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText("Project"), { target: { value: 'p1' } });

            const retry = await screen.findByRole('button', { name: /retry/i });
            expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeDisabled();

            fetchMock.mockResponseOnce(JSON.stringify({ project_id: 'p1', description: 'Desc' }));
            fireEvent.click(retry);
            await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue('Desc'));
            expect(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i })).toBeEnabled();
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

    describe('guided STRIDE context lifecycle', () => {
        const structured: StrideContextText = {
            threatModel: serializeThreatModel({
                ...emptyThreatModel(), scope: 'Production firmware',
                threats: [
                    { id: 'T1', category: 'Spoofing', description: 'A device could be impersonated' },
                    { id: 'T2', category: 'Spoofing', description: 'An administrator could be impersonated' },
                ],
            }),
            risks: serializeRiskRegister({
                risks: [{ ...emptyRisk(), threatId: 'T1', impact: 'High' }],
                notes: 'Review key management',
            }),
        };

        async function mountVariant(
            initial: StrideContextText = { threatModel: '', risks: '' },
            onAgentContextChange?: (context: AgentViewContext) => void,
            initialPaths: string | null = null,
            initialMode: StrideEditorMode | null = null,
        ) {
            const stored = new Map<string, StrideContextText>([
                ['v1', initial], ['v2', { threatModel: 'Legacy model for variant 2', risks: 'Legacy risks for variant 2' }],
            ]);
            const puts: VariantContextData[] = [];
            const paths = new Map<string, string | null>([['v1', initialPaths], ['v2', null]]);
            const modes = new Map<string, StrideEditorMode | null>([['v1', initialMode], ['v2', null]]);
            fetchMock.mockResponse(async request => {
                const url = new URL(request.url);
                if (url.pathname === '/api/projects') return JSON.stringify([{ id: 'p1', name: 'Project A' }]);
                if (url.pathname === '/api/projects/p1/variants') return JSON.stringify([
                    { id: 'v1', name: 'Variant 1', project_id: 'p1' },
                    { id: 'v2', name: 'Variant 2', project_id: 'p1' },
                ]);
                if (url.pathname === '/api/projects/p1/context') return JSON.stringify({ description: 'Description' });
                if (url.pathname === '/api/context') {
                    const text = stored.get(url.searchParams.get('variant_id')!);
                    return JSON.stringify({
                        threat_model: text!.threatModel || null, risks: text!.risks || null,
                        codebase_path: paths.get(url.searchParams.get('variant_id')!) ?? null,
                        editor_mode: modes.get(url.searchParams.get('variant_id')!) ?? null,
                    });
                }
                if (url.pathname === '/api/reviews/assessments') return JSON.stringify([]);
                if (url.pathname === '/api/variants/v1/context' && request.method === 'PATCH') {
                    const { expected: _expected, ...fields } = await request.json();
                    const previous = stored.get('v1')!;
                    const payload: VariantContextData = {
                        variant_description: null, environment: null, other_info: null,
                        threat_model: previous.threatModel || null, risks: previous.risks || null,
                        codebase_path: paths.get('v1') ?? null, ...fields,
                        editor_mode: fields.editor_mode ?? modes.get('v1') ?? null,
                    };
                    puts.push(payload);
                    stored.set('v1', { threatModel: payload.threat_model ?? '', risks: payload.risks ?? '' });
                    paths.set('v1', payload.codebase_path);
                    modes.set('v1', payload.editor_mode ?? null);
                    return JSON.stringify(payload);
                }
                if (url.pathname === '/api/context/import') {
                    return JSON.stringify({ imported: [{ project_name: 'Project A', variant_name: 'Variant 1' }], ignored: [], failed: [] });
                }
                throw new Error(`Unexpected context request: ${request.method} ${request.url}`);
            });
            render(<AIContext onAgentContextChange={onAgentContextChange} />);
            await screen.findByRole('option', { name: 'Project A' });
            fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'p1' } });
            await screen.findByRole('option', { name: 'Variant 1' });
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText('Editor mode')).not.toBeDisabled());
            selectContextTab("Threat model");
            return { stored, puts, paths, modes };
        }

        const agentWrite = () => act(() => {
            window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool: 'update_variant_context' } }));
        });
        const contextRequests = () => fetchMock.mock.calls.filter(call =>
            String(call[0]).includes('/api/context?'));

        const patchBodies = () => fetchMock.mock.calls
            .filter(call => (call[1] as RequestInit)?.method === 'PATCH')
            .map(call => JSON.parse(String(call[1]?.body)));

        test('Context can be saved before a model exists without publishing incomplete System or threat drafts', async () => {
            const { puts } = await mountVariant();
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
            fireEvent.change(screen.getByLabelText('Component 1 name'), { target: { value: 'Unsaved device' } });
            selectContextTab('Threat model');
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Tampering' } });
            selectContextTab('Context');
            fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Zephyr RTOS' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save Context' }));
            await screen.findByText('Context saved successfully.');
            expect(patchBodies()).toEqual([{ environment: 'Zephyr RTOS', expected: { environment: null } }]);
            expect(puts[0]).toMatchObject({ environment: 'Zephyr RTOS', threat_model: null, risks: null });
            selectContextTab('System');
            expect(screen.getByLabelText('Component 1 name')).toHaveValue('Unsaved device');
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('Tampering');
        });

        test('new links require saves in dependency order without discarding local drafts', async () => {
            const { puts } = await mountVariant();
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
            fireEvent.change(screen.getByLabelText('Component 1 name'), { target: { value: 'Device' } });
            selectContextTab('Threat model');
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Device impersonation' } });
            fireEvent.change(screen.getByLabelText('Threat 1 affected system element'), { target: { value: 'C1' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            expect(await screen.findByRole('alert')).toHaveTextContent('Save System before Threat model');
            expect(puts).toHaveLength(0);
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T1' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            expect(screen.getByRole('alert')).toHaveTextContent('Save Threat model before Risks');
            selectContextTab('Context');
            fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: '' } });
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Save System' }));
            await waitFor(() => expect(puts).toHaveLength(1));
            expect(parseThreatModel(puts[0].threat_model!)?.threats).toEqual([]);
            expect(patchBodies()[0]).not.toHaveProperty('risks');
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('Device impersonation');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            selectContextTab('Risks');
            expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T1');
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            await waitFor(() => expect(puts).toHaveLength(3));
            expect(patchBodies().map(body => Object.keys(body).filter(key => key !== 'expected')))
                .toEqual([['threat_model'], ['threat_model'], ['risks']]);
            expect(fetchMock.mock.calls.some(call => String(call[0]).endsWith('/api/projects/p1/context')
                && (call[1] as RequestInit)?.method === 'PUT')).toBe(false);
        });

        test('removing a saved threat cannot reuse its identifier or strand a saved risk', async () => {
            const { puts } = await mountVariant(structured);
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T2' } });
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Remove threat 1' }));
            fireEvent.click(screen.getByRole('button', { name: 'Add threat' }));
            fireEvent.change(screen.getByLabelText('Threat 2 description'), { target: { value: 'A newly added threat' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            expect(await screen.findByRole('alert')).toHaveTextContent('Save Risks before Threat model');
            expect(puts).toHaveLength(0);
            selectContextTab('Risks');
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            await waitFor(() => expect(puts).toHaveLength(1));
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            expect(parseThreatModel(puts[1].threat_model!)?.threats.map(threat => threat.id)).toEqual(['T2', 'T3']);
        });

        test('system removals reserve saved element identifiers until references are saved', async () => {
            const model = {
                ...parseThreatModel(structured.threatModel)!,
                components: [{ id: 'C1', name: 'Original device', description: '', trustZone: '' }],
            };
            model.threats[0].targetIds = ['C1'];
            const { puts } = await mountVariant({ ...structured, threatModel: serializeThreatModel(model) });
            fireEvent.click(screen.getByRole('button', { name: 'Remove C1 from threat 1' }));
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Remove component 1' }));
            fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
            fireEvent.change(screen.getByLabelText('Component 1 name'), { target: { value: 'Different device' } });
            expect(screen.getByRole('group', { name: 'Component 1 (C2)' })).toBeVisible();
            fireEvent.click(screen.getByRole('button', { name: 'Save System' }));
            expect(await screen.findByRole('alert')).toHaveTextContent('Save Threat model before System');
            expect(puts).toHaveLength(0);
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(1));
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Save System' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            expect(parseThreatModel(puts[1].threat_model!)?.components.map(component => component.id)).toEqual(['C2']);
        });

        test('risk-only confirmation ignores unsaved project edits and retains the clicked snapshot', async () => {
            const { puts } = await mountVariant(structured);
            selectContextTab('Context');
            fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: 'Unsaved project description' } });
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 impact'), { target: { value: 'Medium' } });
            fetchMock.mockResponseOnce(JSON.stringify([{
                id: 'a1', vuln_id: 'CVE-1', status: 'affected', timestamp: '2026-01-01T00:00:00Z',
                origin: 'ai', packages: [], responses: [],
            }]));
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            await screen.findByText(/mark all pending AI assessments/i);
            expect(screen.getByText('Save Risks', { selector: 'button' })).toBeDisabled();
            const check = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/reviews/assessments'));
            expect(String(check![0])).toContain('variant_id=v1');
            expect(String(check![0])).not.toContain('project_id=');
            fireEvent.change(screen.getByLabelText('Risk 1 impact'), { target: { value: 'Low' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save and mark outdated' }));
            await waitFor(() => expect(puts).toHaveLength(1));
            expect(parseRiskRegister(puts[0].risks!)?.risks[0].impact).toBe('Medium');
            expect(screen.getByLabelText('Risk 1 impact')).toHaveValue('Low');
            expect(patchBodies()[0]).not.toHaveProperty('threat_model');
            selectContextTab('Context');
            expect(screen.getByLabelText('Project Description')).toHaveValue('Unsaved project description');
        });

        test.each([
            { status: 500, body: { error: 'Section was not saved' }, message: 'Section was not saved' },
            { status: 409, body: { error: 'Section was not saved' }, message: 'Section was not saved' },
            { status: 503, body: {}, message: 'Failed to save section (503)' },
        ])('a failed section save ($status) keeps both its draft and other sections drafts', async ({ status, body, message }) => {
            const { puts } = await mountVariant(structured);
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Unsaved threat' } });
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Unsaved mitigation' } });
            fetchMock.mockResponseOnce(JSON.stringify([]));
            fetchMock.mockResponseOnce(JSON.stringify(body), { status });
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            expect(await screen.findByRole('alert')).toHaveTextContent(message);
            expect(puts).toHaveLength(0);
            expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Unsaved mitigation');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('Unsaved threat');
            expect(screen.getByRole('button', { name: 'Save Risks' })).toBeEnabled();
        });

        test('saving Context does not let an agent refresh discard an unserialized threat draft', async () => {
            const { stored } = await mountVariant();
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Spoofing' } });
            selectContextTab('Context');
            fireEvent.click(screen.getByRole('button', { name: 'Save Context' }));
            await screen.findByText('Context saved successfully.');
            stored.set('v1', { threatModel: 'Model updated by agent', risks: '' });
            const requests = contextRequests().length;
            agentWrite();
            expect(await screen.findByRole('alert')).toHaveTextContent('Your unsaved edits were kept');
            expect(contextRequests()).toHaveLength(requests);
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('Spoofing');
        });

        test('Summary reflects unsaved edits and separate saves preserve other sections drafts', async () => {
            const { puts } = await mountVariant(structured);
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Updated device impersonation' } });
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Validate device credentials' } });
            const requests = fetchMock.mock.calls.length;
            selectContextTab('Summary');
            const panel = screen.getByRole('tabpanel', { name: 'Summary' });
            expect(within(panel).getByRole('table', { name: 'Threats and linked risk evaluations' }))
                .toHaveTextContent('Updated device impersonation');
            expect(panel).toHaveTextContent('Validate device credentials');
            expect(within(panel).queryByRole('textbox')).not.toBeInTheDocument();
            expect(within(panel).queryByRole('combobox')).not.toBeInTheDocument();
            expect(fetchMock.mock.calls).toHaveLength(requests);
            expect(screen.queryByRole('button', { name: /^save /i })).not.toBeInTheDocument();
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(parseThreatModel(puts[0].threat_model!)?.threats[0].description).toBe('Updated device impersonation');
            expect(puts[0].risks).toBe(structured.risks);
            selectContextTab('Risks');
            expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Validate device credentials');
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            expect(parseRiskRegister(puts[1].risks!)?.risks[0].mitigation).toBe('Validate device credentials');
        });

        test('viewing Summary does not dirty saved data and clean agent refreshes update its rows', async () => {
            const { stored, puts } = await mountVariant(structured);
            selectContextTab('Summary');
            expect(screen.queryByRole('button', { name: /^save /i })).not.toBeInTheDocument();
            expect(puts).toHaveLength(0);
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
            const model = parseThreatModel(structured.threatModel)!;
            stored.set('v1', {
                ...structured, threatModel: serializeThreatModel({
                    ...model, threats: model.threats.map(threat => ({ ...threat, description: `Agent updated ${threat.description}` })),
                }),
            });
            agentWrite();
            await waitFor(() => expect(screen.getByRole('table', { name: 'Threats and linked risk evaluations' }))
                .toHaveTextContent('Agent updated A device could be impersonated'));
            expect(screen.getByRole('tab', { name: 'Summary' })).toHaveAttribute('aria-selected', 'true');
            selectContextTab('Context');
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByLabelText('Editor mode')).toHaveValue('free'));
            selectContextTab('Summary');
            expect(screen.getByRole('tabpanel', { name: 'Summary' })).toHaveTextContent('Legacy model for variant 2');
            expect(screen.getByRole('tabpanel', { name: 'Summary' })).toHaveTextContent('Legacy risks for variant 2');
            expect(screen.queryByRole('table')).not.toBeInTheDocument();
        });

        test('System architecture and threat targets save, refresh and remain scoped to their variant', async () => {
            const { puts } = await mountVariant();
            selectContextTab('System');
            for (const [number, name] of [[1, 'Update service'], [2, 'OTA updater']] as const) {
                fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
                fireEvent.change(screen.getByLabelText(`Component ${number} name`), { target: { value: name } });
            }
            fireEvent.click(screen.getByRole('button', { name: 'Add interaction' }));
            fireEvent.change(screen.getByLabelText('Interaction 1 name'), { target: { value: 'Firmware download' } });
            fireEvent.change(screen.getByLabelText('Interaction 1 source component'), { target: { value: 'C1' } });
            fireEvent.change(screen.getByLabelText('Interaction 1 destination component'), { target: { value: 'C2' } });
            fireEvent.change(screen.getByLabelText('Interaction 1 interface / protocol'), { target: { value: 'HTTPS' } });
            selectContextTab('Threat model');
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Tampering' } });
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Unauthorized firmware replacement' } });
            fireEvent.change(screen.getByLabelText('Threat 1 affected system element'), { target: { value: 'C2' } });
            fireEvent.change(screen.getByLabelText('Threat 1 affected system element'), { target: { value: 'I1' } });
            selectContextTab('Risks');
            fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T1' } });
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Verify firmware signatures' } });
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts).toHaveLength(1);
            const saved = puts[0].threat_model!;
            expect(saved).toContain('<!-- VulnScout STRIDE v2 -->');
            expect(parseThreatModel(saved)).toMatchObject({
                components: [{ id: 'C1', name: 'Update service' }, { id: 'C2', name: 'OTA updater' }],
                interactions: [{ id: 'I1', name: 'Firmware download', sourceId: 'C1', destinationId: 'C2', protocol: 'HTTPS' }],
                threats: [],
            });
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            selectContextTab('Risks');
            fireEvent.click(screen.getByRole('button', { name: 'Save Risks' }));
            await waitFor(() => expect(puts).toHaveLength(3));
            selectContextTab('System');
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('Component 2 name')).toHaveValue('OTA updater'));
            fireEvent.change(screen.getByLabelText('Component 2 name'), { target: { value: 'Privileged update agent' } });
            agentWrite();
            await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/your unsaved edits were kept/i));
            expect(screen.getByLabelText('Component 2 name')).toHaveValue('Privileged update agent');
            selectContextTab('Threat model');
            expect(screen.getByRole('list', { name: 'Threat 1 affected system elements' })).toHaveTextContent('Privileged update agent');
            selectContextTab('System');
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByLabelText('Editor mode')).toHaveValue('free'));
            expect(screen.getByRole('tabpanel', { name: 'System' })).toHaveTextContent('In Advanced free mode');
            expect(screen.queryByRole('textbox', { name: 'Component 1 name' })).not.toBeInTheDocument();
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByRole('textbox', { name: 'Component 2 name' })).toHaveValue('OTA updater'));
            expect(screen.getByLabelText('Interaction 1 source component')).toHaveValue('C1');
            selectContextTab('Threat model');
            expect(screen.getByRole('list', { name: 'Threat 1 affected system elements' })).toHaveTextContent('Interaction I1: Firmware download');
            selectContextTab('Risks');
            expect(screen.getByRole('list', { name: 'Risk 1 affected system elements' })).toHaveTextContent('Component C2: OTA updater');
            expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Verify firmware signatures');
        });

        test('default blank threats do not dirty saved context or prevent an agent refresh', async () => {
            const saved = serializeThreatModel({ ...emptyThreatModel(), scope: 'Device firmware' });
            const { stored, puts } = await mountVariant({ threatModel: saved, risks: '' });
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('');
            const refreshed = serializeThreatModel({ ...emptyThreatModel(), scope: 'Updated system scope' });
            stored.set('v1', { threatModel: refreshed, risks: '' });
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('System scope and assets')).toHaveValue('Updated system scope'));
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0]).toMatchObject({ threat_model: refreshed, risks: null });
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
        });

        test('codebase paths load as separate rows and can be added, edited and removed without losing other paths', async () => {
            const { puts } = await mountVariant(structured, undefined, '/src/app;/src/lib');
            selectContextTab('Context');
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/src/app');
            expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/src/lib');
            expect(screen.queryByText(/separate multiple paths with a semicolon/i)).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            fireEvent.change(screen.getByLabelText('Codebase Path 3'), { target: { value: '/src/drivers' } });
            fireEvent.click(screen.getByRole('button', { name: 'Remove Codebase Path 2' }));
            expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/src/drivers');
            fireEvent.change(screen.getByLabelText('Codebase Path 1'), { target: { value: '/src/updated-app' } });
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            selectContextTab('Threat model');
            selectContextTab('Risks');
            selectContextTab('Context');
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/src/updated-app');
            expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/src/drivers');
            expect(screen.getByLabelText('Codebase Path 3')).toHaveValue('');
            selectContextTab('Context');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0].codebase_path).toBe('/src/updated-app;/src/drivers');
            selectContextTab('Context');
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/src/drivers'));
            expect(screen.getAllByRole('textbox', { name: /^Codebase Path \d+$/ })).toHaveLength(2);
        });

        test('empty path drafts remain editable but do not change saved paths or trigger assessment outdating', async () => {
            const original = '/src/app ; /src/lib';
            const { puts } = await mountVariant(structured, undefined, original);
            selectContextTab('Context');
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/src/app ');
            expect(screen.getByLabelText('Codebase Path 2')).toHaveValue(' /src/lib');
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            fireEvent.change(screen.getByLabelText('Codebase Path 3'), { target: { value: ' ' } });
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            selectContextTab('Threat model');
            selectContextTab('Context');
            expect(screen.getByLabelText('Codebase Path 3')).toHaveValue(' ');
            expect(screen.getByLabelText('Codebase Path 4')).toHaveValue('');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts).toHaveLength(0);
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
        });

        test('all codebase paths can be removed and empty replacement rows save as null', async () => {
            const { puts } = await mountVariant(structured, undefined, '/src/app;/src/lib');
            selectContextTab('Context');
            fireEvent.click(screen.getByRole('button', { name: 'Remove Codebase Path 1' }));
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/src/lib');
            fireEvent.click(screen.getByRole('button', { name: 'Remove Codebase Path 1' }));
            expect(screen.queryByRole('textbox', { name: /^Codebase Path / })).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0].codebase_path).toBeNull();
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            fireEvent.change(screen.getByLabelText('Codebase Path 1'), { target: { value: ' ' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts).toHaveLength(1);
        });

        test('agent path updates reload clean rows and preserve unsaved path edits', async () => {
            const { paths } = await mountVariant(structured, undefined, '/src/app');
            selectContextTab('Context');
            paths.set('v1', '/agent/app;/agent/lib');
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/agent/lib'));
            fireEvent.change(screen.getByLabelText('Codebase Path 2'), { target: { value: '/unsaved/lib' } });
            paths.set('v1', '/newer/agent');
            const requests = contextRequests().length;
            agentWrite();
            await screen.findByText(/agent updated the variant context/i);
            expect(contextRequests()).toHaveLength(requests);
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/agent/app');
            expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/unsaved/lib');
        });

        test('variant and project switches reset path drafts without discarding the unsaved project description', async () => {
            const { paths } = await mountVariant(structured, undefined, '/src/app;/src/lib');
            paths.set('v2', '/variant-2/source');
            selectContextTab('Context');
            fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: 'Unsaved description' } });
            fireEvent.click(screen.getByRole('button', { name: 'Add Codebase Path' }));
            fireEvent.change(screen.getByLabelText('Codebase Path 3'), { target: { value: '/unsaved/source' } });
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/variant-2/source'));
            expect(screen.queryByLabelText('Codebase Path 2')).not.toBeInTheDocument();
            expect(screen.getByLabelText('Project Description')).toHaveValue('Unsaved description');
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/src/lib'));
            expect(screen.queryByLabelText('Codebase Path 3')).not.toBeInTheDocument();
            fireEvent.change(screen.getByLabelText('Project'), { target: { value: '' } });
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('');
            expect(screen.getByLabelText('Codebase Path 1')).toBeDisabled();
            expect(screen.queryByLabelText('Codebase Path 2')).not.toBeInTheDocument();
        });

        test('imported semicolon-separated paths replace the rows without changing the import format', async () => {
            const { paths } = await mountVariant(structured, undefined, '/existing/source');
            paths.set('v1', '/imported/app;/imported/drivers');
            const envelope = JSON.stringify({
                version: '1.0', projects: [{
                    project_name: 'Project A', project_description: 'Description',
                    variants: [{
                        variant_name: 'Variant 1', threat_model: structured.threatModel,
                        codebase_path: '/imported/app;/imported/drivers',
                    }],
                }],
            });
            const file = new File([envelope], 'context.json', { type: 'application/json' });
            Object.defineProperty(file, 'text', { value: () => Promise.resolve(envelope) });
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });
            await screen.findByText(/import complete/i);
            selectContextTab('Context');
            await waitFor(() => expect(screen.getByLabelText('Codebase Path 2')).toHaveValue('/imported/drivers'));
            expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/imported/app');
            const imported = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/context/import'));
            expect(JSON.parse(String(imported![1]?.body)).projects[0].variants[0].codebase_path)
                .toBe('/imported/app;/imported/drivers');
        });

        test('the single Editor mode choice in Context changes both Threat model and Risks', async () => {
            await mountVariant(structured);
            selectContextTab('Context');
            const mode = screen.getByRole('combobox', { name: 'Editor mode' });
            expect(mode).toHaveValue('stride');
            expect(screen.getAllByLabelText('Editor mode')).toHaveLength(1);
            fireEvent.change(mode, { target: { value: 'free' } });
            expect(screen.getByRole('tab', { name: 'Context' })).toHaveAttribute('aria-selected', 'true');
            selectContextTab('Threat model');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue(structured.threatModel);
            expect(screen.queryByRole('combobox', { name: 'Editor mode' })).not.toBeInTheDocument();
            selectContextTab('Risks');
            expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue(structured.risks);
            expect(screen.queryByRole('combobox', { name: 'Editor mode' })).not.toBeInTheDocument();
            selectContextTab('Context');
            expect(screen.getByRole('combobox', { name: 'Editor mode' })).toBe(mode);
            fireEvent.change(mode, { target: { value: 'stride' } });
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Threat 2 description')).toHaveValue('An administrator could be impersonated');
            expect(screen.getByRole('textbox', { name: 'Additional notes' })).toBeVisible();
            selectContextTab('Risks');
            expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T1');
            expect(screen.getByLabelText('Risk 1 impact')).toHaveValue('High');
            expect(screen.getAllByLabelText('Editor mode')).toHaveLength(1);
        });

        test('Additional notes saves and reloads without a show/hide control', async () => {
            const { puts } = await mountVariant(structured);
            expect(screen.queryByRole('button', { name: /additional notes/i })).not.toBeInTheDocument();
            fireEvent.change(screen.getByRole('textbox', { name: 'Additional notes' }), {
                target: { value: 'Debug access is disabled in production.' },
            });
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(parseThreatModel(puts[0].threat_model!)?.notes).toBe('Debug access is disabled in production.');
            selectContextTab('Threat model');
            agentWrite();
            await waitFor(() => expect(screen.getByRole('textbox', { name: 'Additional notes' }))
                .toHaveValue('Debug access is disabled in production.'));
            expect(screen.queryByRole('button', { name: /additional notes/i })).not.toBeInTheDocument();
        });

        test('refreshing variant mode leaves unsaved Context fields and their focus intact', async () => {
            const { stored } = await mountVariant(structured);
            selectContextTab('Context');
            const description = screen.getByRole('textbox', { name: 'Project Description' });
            fireEvent.change(description, { target: { value: 'Unsaved project description' } });
            description.focus();
            stored.set('v1', { threatModel: 'Free model from agent', risks: 'Free risks from agent' });
            agentWrite();
            await waitFor(() => expect(screen.getByRole('combobox', { name: 'Editor mode' })).toHaveValue('free'));
            expect(screen.getByRole('textbox', { name: 'Project Description' })).toBe(description);
            expect(description).toHaveValue('Unsaved project description');
            expect(description).toHaveFocus();
        });

        test.each(['Context', 'System', 'Threat model', 'Risks'] as const)(
            'Save from %s persists only that section and preserves other drafts',
            async saveTab => {
                const { puts } = await mountVariant(structured);
                selectContextTab('Context');
                fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: 'Unsaved project description' } });
                fireEvent.change(screen.getByLabelText('Variant Description'), { target: { value: 'Production device' } });
                fireEvent.change(screen.getByLabelText('Codebase Path 1'), { target: { value: '/workspace/firmware' } });
                fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Zephyr RTOS' } });
                fireEvent.change(screen.getByLabelText('Other Information'), { target: { value: 'Requires authenticated updates' } });
                selectContextTab('System');
                fireEvent.change(screen.getByLabelText('System scope and assets'), { target: { value: 'Unsaved system scope' } });
                selectContextTab('Threat model');
                fireEvent.change(screen.getByLabelText('Threat 2 description'), { target: { value: 'Updated administrator impersonation' } });
                fireEvent.click(screen.getByRole('button', { name: 'Add threat' }));
                fireEvent.change(screen.getByLabelText('Threat 3 STRIDE category'), { target: { value: 'Tampering' } });
                fireEvent.change(screen.getByRole('textbox', { name: 'Additional notes' }), {
                    target: { value: 'Physical debug access is disabled' },
                });
                selectContextTab('Risks');
                fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T2' } });
                fireEvent.change(screen.getByLabelText('Risk 1 likelihood'), { target: { value: 'Medium' } });
                fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Require device authentication' } });
                fireEvent.click(screen.getByRole('button', { name: 'Add risk' }));
                const requests = fetchMock.mock.calls.length;
                selectContextTab('Context');
                expect(screen.getByLabelText('Project Description')).toHaveValue('Unsaved project description');
                expect(screen.getByLabelText('Codebase Path 1')).toHaveValue('/workspace/firmware');
                selectContextTab('System');
                expect(screen.getByLabelText('System scope and assets')).toHaveValue('Unsaved system scope');
                selectContextTab('Threat model');
                expect(screen.getByLabelText('Threat 3 STRIDE category')).toHaveValue('Tampering');
                expect(screen.getByLabelText('Threat 3 description')).toHaveValue('');
                expect(screen.queryByRole('button', { name: /additional notes/i })).not.toBeInTheDocument();
                expect(screen.getByRole('textbox', { name: 'Additional notes' })).toHaveValue('Physical debug access is disabled');
                selectContextTab('Risks');
                expect(screen.getByRole('note', { name: 'Risk 1 selected threat' })).toHaveTextContent('Updated administrator impersonation');
                expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T2');
                expect(screen.getByLabelText('Risk 1 likelihood')).toHaveValue('Medium');
                expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Require device authentication');
                expect(screen.getByRole('group', { name: 'Risk 2' })).toBeVisible();
                expect(screen.getByLabelText('Risk 2 threat')).toHaveValue('');
                expect(fetchMock.mock.calls).toHaveLength(requests);
                selectContextTab(saveTab);
                fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
                await screen.findByText(/saved successfully/i);
                expect(puts).toHaveLength(1);
                expect(puts[0]).toMatchObject(saveTab === 'Context' ? {
                    variant_description: 'Production device', codebase_path: '/workspace/firmware',
                    environment: 'Zephyr RTOS', other_info: 'Requires authenticated updates',
                } : { variant_description: null, codebase_path: null, environment: null, other_info: null });
                expect(parseThreatModel(puts[0].threat_model!)).toMatchObject({
                    scope: saveTab === 'System' ? 'Unsaved system scope' : 'Production firmware',
                    notes: saveTab === 'Threat model' ? 'Physical debug access is disabled' : '',
                    threats: saveTab === 'Threat model' ? [
                        { id: 'T1', category: 'Spoofing', description: 'A device could be impersonated' },
                        { id: 'T2', category: 'Spoofing', description: 'Updated administrator impersonation' },
                        { id: 'T3', category: 'Tampering', description: '' },
                    ] : parseThreatModel(structured.threatModel)!.threats,
                });
                expect(parseRiskRegister(puts[0].risks!)?.risks).toEqual(saveTab === 'Risks' ? [{
                    ...emptyRisk(), threatId: 'T2', likelihood: 'Medium', impact: 'High',
                    mitigation: 'Require device authentication',
                }] : parseRiskRegister(structured.risks)!.risks);
                const projectPut = fetchMock.mock.calls.find(call =>
                    String(call[0]).endsWith('/api/projects/p1/context') && (call[1] as RequestInit)?.method === 'PUT');
                if (saveTab === 'Context')
                    expect(JSON.parse(String(projectPut![1]?.body))).toEqual({ description: 'Unsaved project description' });
                else expect(projectPut).toBeUndefined();
                expect(screen.getByRole('tab', { name: saveTab })).toHaveAttribute('aria-selected', 'true');
                selectContextTab('Threat model');
                expect(screen.getByLabelText('Threat 3 STRIDE category')).toHaveValue('Tampering');
                selectContextTab('System');
                expect(screen.getByLabelText('System scope and assets')).toHaveValue('Unsaved system scope');
                selectContextTab('Risks');
                expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Require device authentication');
            },
        );

        test('navigation alone does not reload context or trigger assessment outdating', async () => {
            const { puts } = await mountVariant(structured);
            const requests = fetchMock.mock.calls.length;
            for (const name of ['Risks', 'Context', 'Threat model', 'Risks'] as const) selectContextTab(name);
            expect(fetchMock.mock.calls).toHaveLength(requests);
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0]).toMatchObject({ threat_model: structured.threatModel, risks: structured.risks });
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
        });

        test('incomplete unsaved STRIDE drafts survive Context and Advanced free-mode navigation', async () => {
            await mountVariant();
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Spoofing' } });
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: ' ' } });
            selectContextTab('Risks');
            fireEvent.click(screen.getByRole('button', { name: 'Add risk' }));
            switchContextMode('free');
            expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue('');
            selectContextTab('Context');
            selectContextTab('Threat model');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue('');
            switchContextMode('stride');
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('Spoofing');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue(' ');
            selectContextTab('Risks');
            expect(screen.getByRole('group', { name: 'Risk 2' })).toBeVisible();
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            expect(screen.getByRole('tab', { name: 'Threat model' })).toHaveFocus();
            expect(screen.getByRole('alert')).toHaveTextContent('Threat Model is required.');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue(' ');
        });

        test('active subtab is included in the agent view context without changing project or variant scope', async () => {
            const changed = jest.fn();
            await mountVariant(structured, changed);
            for (const [name, section] of [
                ['System', 'system'], ['Threat model', 'threat_model'], ['Context', 'context'], ['Risks', 'risks'], ['Summary', 'summary'],
            ] as const) {
                selectContextTab(name);
                expect(changed).toHaveBeenLastCalledWith(expect.objectContaining({
                    section, selectedProjectId: 'p1', selectedProjectName: 'Project A',
                    selectedVariantId: 'v1', selectedVariantName: 'Variant 1',
                }));
            }
        });

        test('Advanced free mode and its unsaved fields survive all subtab switches', async () => {
            const { puts } = await mountVariant({ threatModel: 'Existing free model', risks: 'Existing free risks' });
            fireEvent.change(screen.getByRole('textbox', { name: 'Threat Model' }), { target: { value: 'Unsaved free model' } });
            selectContextTab('Risks');
            expect(screen.queryByRole('textbox', { name: 'Threat Model' })).not.toBeInTheDocument();
            fireEvent.change(screen.getByRole('textbox', { name: 'Risks' }), { target: { value: 'Unsaved free risks' } });
            selectContextTab('Context');
            expect(screen.getByRole('combobox', { name: 'Editor mode' })).toBeVisible();
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Editor mode')).toHaveValue('free');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue('Unsaved free model');
            expect(screen.queryByRole('textbox', { name: 'Risks' })).not.toBeInTheDocument();
            selectContextTab('Risks');
            expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue('Unsaved free risks');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0]).toMatchObject({ threat_model: 'Existing free model', risks: 'Unsaved free risks' });
            selectContextTab('Threat model');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue('Unsaved free model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            expect(puts[1]).toMatchObject({ threat_model: 'Unsaved free model', risks: 'Unsaved free risks' });
        });

        test('blank templates remain invalid even after adding empty risks or switching modes', async () => {
            const { puts } = await mountVariant();
            expect(screen.getByRole('group', { name: 'Threat 1' })).toBeVisible();
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('');
            selectContextTab("Risks");
            expect(screen.getByRole('group', { name: 'Risk 1' })).toBeVisible();
            expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('');
            fireEvent.click(screen.getByRole('button', { name: 'Add risk' }));
            selectContextTab("Threat model");
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Spoofing' } });
            switchContextMode('free');
            switchContextMode('stride');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            expect(await screen.findByText('Threat Model is required.')).toBeInTheDocument();
            expect(puts).toHaveLength(0);
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
        });

        test('guided fields save as the existing readable text fields and restore after a reload', async () => {
            const { puts } = await mountVariant();
            selectContextTab("System");
            fireEvent.change(screen.getByLabelText('System scope and assets'), { target: { value: 'Firmware and credentials' } });
            fireEvent.change(screen.getByLabelText('Trust boundaries'), { target: { value: 'Internet -> device API' } });
            selectContextTab("Threat model");
            fireEvent.change(screen.getByLabelText('Threat 1 STRIDE category'), { target: { value: 'Spoofing' } });
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Device impersonation' } });
            fireEvent.click(screen.getByRole('button', { name: 'Add threat' }));
            fireEvent.change(screen.getByLabelText('Threat 2 STRIDE category'), { target: { value: 'Spoofing' } });
            fireEvent.change(screen.getByLabelText('Threat 2 description'), { target: { value: 'Administrator impersonation' } });
            selectContextTab("Risks");
            fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T2' } });
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Require signed images' } });
            selectContextTab('System');
            fireEvent.click(screen.getByRole('button', { name: 'Save System' }));
            await waitFor(() => expect(puts).toHaveLength(1));
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            selectContextTab('Risks');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await waitFor(() => expect(puts).toHaveLength(3));
            expect(parseThreatModel(puts[2].threat_model!)).toMatchObject({
                scope: 'Firmware and credentials', trust_boundaries: 'Internet -> device API',
                threats: [
                    { id: 'T1', category: 'Spoofing', description: 'Device impersonation' },
                    { id: 'T2', category: 'Spoofing', description: 'Administrator impersonation' },
                ],
            });
            expect(parseRiskRegister(puts[2].risks!)).toMatchObject({
                risks: [{ threatId: 'T2', mitigation: 'Require signed images' }],
            });
            expect(puts[2].risks).not.toContain('STRIDE category');
            expect(puts[2].risks).not.toContain('Threat scenario');
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('System scope and assets')).toHaveValue('Firmware and credentials'));
            expect(screen.getByLabelText('Editor mode')).toHaveValue('stride');
            expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Require signed images');
            expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T2');
            expect(screen.getByLabelText('Threat 1 STRIDE category')).toHaveValue('Spoofing');
            expect(screen.getByLabelText('Threat 2 STRIDE category')).toHaveValue('Spoofing');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('Device impersonation');
            expect(screen.getByLabelText('Threat 2 description')).toHaveValue('Administrator impersonation');
            expect(screen.getByRole('note', { name: 'Risk 1 selected threat' })).toHaveTextContent('Administrator impersonation');
        });

        test('reassigning a risk and editing its threat persists a single association and updated threat details', async () => {
            const { puts } = await mountVariant(structured);
            selectContextTab("Risks");
            fireEvent.change(screen.getByLabelText('Risk 1 threat'), { target: { value: 'T2' } });
            selectContextTab("Threat model");
            fireEvent.change(screen.getByLabelText('Threat 2 STRIDE category'), { target: { value: 'Tampering' } });
            fireEvent.change(screen.getByLabelText('Threat 2 description'), { target: { value: 'Modified administrator credentials' } });
            selectContextTab("Risks");
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(parseRiskRegister(puts[0].risks!)?.risks).toEqual([{ ...emptyRisk(), threatId: 'T2', impact: 'High' }]);
            expect(puts[0].threat_model).toBe(structured.threatModel);
            selectContextTab('Threat model');
            fireEvent.click(screen.getByRole('button', { name: 'Save Threat model' }));
            await waitFor(() => expect(puts).toHaveLength(2));
            expect(parseThreatModel(puts[1].threat_model!)?.threats[1]).toEqual({
                id: 'T2', category: 'Tampering', description: 'Modified administrator credentials',
            });
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T2'));
            selectContextTab('Risks');
            expect(screen.getByRole('note', { name: 'Risk 1 selected threat' })).toHaveTextContent('Tampering');
            expect(screen.getByRole('note', { name: 'Risk 1 selected threat' })).toHaveTextContent('Modified administrator credentials');
        });

        test('a populated model leaves unused risks null rather than saving risk placeholders', async () => {
            const { puts } = await mountVariant();
            selectContextTab("System");
            fireEvent.change(screen.getByLabelText('Actors and access'), { target: { value: 'Remote attackers and administrators' } });
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0].risks).toBeNull();
            expect(parseThreatModel(puts[0].threat_model!)?.actors).toBe('Remote attackers and administrators');
        });

        test('switching modes on a saved template does not trigger assessment outdating', async () => {
            const { puts } = await mountVariant(structured);
            expect(screen.getByLabelText('System scope and assets')).toHaveValue('Production firmware');
            switchContextMode('free');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue(structured.threatModel);
            switchContextMode('stride');
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            await screen.findByText(/saved successfully/i);
            expect(puts[0]).toMatchObject({ threat_model: structured.threatModel, risks: structured.risks });
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
        });

        test('STRIDE edits retain pending-assessment confirmation and its save snapshot', async () => {
            const { puts } = await mountVariant(structured);
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'A different device could be impersonated' } });
            fetchMock.mockResponseOnce(JSON.stringify([{
                id: 'a1', vuln_id: 'CVE-1', status: 'affected', timestamp: '2026-01-01T00:00:00Z',
                origin: 'ai', packages: [], responses: [],
            }]));
            fireEvent.click(screen.getByRole('button', { name: /^save (context|system|threat model|risks)$/i }));
            expect(await screen.findByText(/mark all pending AI assessments/i)).toBeInTheDocument();
            expect(puts).toHaveLength(0);
            const check = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/reviews/assessments'));
            expect(String(check![0])).toContain('variant_id=v1');
            fireEvent.click(screen.getByRole('button', { name: /save and mark outdated/i }));
            await screen.findByText(/saved successfully/i);
            expect(parseThreatModel(puts[0].threat_model!)?.threats[0].description).toBe('A different device could be impersonated');
            expect(parseThreatModel(puts[0].threat_model!)?.threats[1].description).toBe('An administrator could be impersonated');
        });

        test('variant switches reset editor drafts and mode without discarding unsaved project edits', async () => {
            await mountVariant(structured);
            fireEvent.change(screen.getByLabelText('Project Description'), { target: { value: 'Unsaved description' } });
            fireEvent.change(screen.getByLabelText('System scope and assets'), { target: { value: 'Unsaved model' } });
            selectContextTab("Risks");
            fireEvent.click(screen.getByRole('button', { name: 'Add risk' }));
            selectContextTab("Threat model");
            fireEvent.click(screen.getByRole('button', { name: 'Add threat' }));
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue('Legacy model for variant 2'));
            expect(screen.getByLabelText('Editor mode')).toHaveValue('free');
            selectContextTab("Risks");
            expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue('Legacy risks for variant 2');
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText('System scope and assets')).toHaveValue('Production firmware'));
            expect(screen.queryByRole('group', { name: 'Risk 2' })).not.toBeInTheDocument();
            selectContextTab("Threat model");
            expect(screen.queryByRole('group', { name: 'Threat 3' })).not.toBeInTheDocument();
            expect(screen.getByLabelText('Project Description')).toHaveValue('Unsaved description');
        });

        test('agent writes reload clean templates, transition to free text, and keep unsaved guided risk edits', async () => {
            const { stored } = await mountVariant(structured);
            stored.set('v1', { ...structured, threatModel: serializeThreatModel({
                ...parseThreatModel(structured.threatModel)!, scope: 'Updated by agent',
            }) });
            agentWrite();
            await waitFor(() => expect(screen.getByLabelText('System scope and assets')).toHaveValue('Updated by agent'));
            selectContextTab("Risks");
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: 'Unsaved mitigation' } });
            stored.set('v1', { threatModel: 'Plain model from agent', risks: 'Plain risks from agent' });
            const loaded = contextRequests().length;
            agentWrite();
            expect(await screen.findByText(/agent updated the variant context/i)).toBeInTheDocument();
            expect(contextRequests()).toHaveLength(loaded);
            expect(screen.getByLabelText('Risk 1 mitigation')).toHaveValue('Unsaved mitigation');
            fireEvent.change(screen.getByLabelText('Risk 1 mitigation'), { target: { value: '' } });
            agentWrite();
            await waitFor(() => expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue('Plain risks from agent'));
            expect(screen.getByLabelText('Threat Model', { selector: 'textarea' })).toHaveValue('Plain model from agent');
            expect(screen.getByLabelText('Editor mode')).toHaveValue('free');
            expect(screen.getByRole('tab', { name: 'Risks' })).toHaveAttribute('aria-selected', 'true');
        });

        test('import reloads a structured model and risks into the guided editor on the same variant', async () => {
            const { stored } = await mountVariant({ threatModel: 'Existing free model', risks: 'Existing free risks' });
            selectContextTab("Risks");
            stored.set('v1', structured);
            const { threats, notes, ...system } = parseThreatModel(structured.threatModel)!;
            const importedVariant = {
                variant_name: 'Variant 1', editor_mode: 'stride', system,
                threat_model: { threats: threats.map(threat => ({ ...threat, targetIds: threat.targetIds ?? [] })), notes },
                risks: parseRiskRegister(structured.risks),
            };
            const envelope = JSON.stringify({
                version: '2.0', projects: [{
                    project_name: 'Project A', project_description: 'Description',
                    variants: [importedVariant],
                }],
            });
            const file = new File([envelope], 'stride-context.json', { type: 'application/json' });
            Object.defineProperty(file, 'text', { value: () => Promise.resolve(envelope) });
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });
            await screen.findByText(/import complete/i);
            await waitFor(() => expect(screen.getByLabelText('System scope and assets')).toHaveValue('Production firmware'));
            expect(screen.getByLabelText('Editor mode')).toHaveValue('stride');
            expect(screen.getByLabelText('Risk 1 threat')).toBeVisible();
            expect(screen.getByLabelText('Risk 1 threat')).toHaveValue('T1');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('A device could be impersonated');
            expect(screen.getByLabelText('Threat 2 description')).toHaveValue('An administrator could be impersonated');
            const imported = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/context/import'));
            expect(JSON.parse(String(imported![1]?.body)).projects[0].variants[0]).toEqual(importedVariant);
        });

        test('legacy imports keep recognizable STRIDE Markdown in Advanced free mode after reload', async () => {
            const { modes } = await mountVariant(structured);
            modes.set('v1', 'free');
            const envelope = JSON.stringify({
                version: '1.0', projects: [{
                    project_name: 'Project A', project_description: 'Description',
                    variants: [{ variant_name: 'Variant 1', threat_model: structured.threatModel, risks: structured.risks }],
                }],
            });
            const file = new File([envelope], 'legacy.json', { type: 'application/json' });
            Object.defineProperty(file, 'text', { value: () => Promise.resolve(envelope) });
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });
            await screen.findByText(/import complete/i);
            await waitFor(() => expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue(structured.threatModel));
            expect(screen.getByLabelText('Editor mode')).toHaveValue('free');
            selectContextTab('Risks');
            expect(screen.getByRole('textbox', { name: 'Risks' })).toHaveValue(structured.risks);
            expect(screen.queryByLabelText('Risk 1 threat')).not.toBeInTheDocument();
        });

        test('Context saves a mode-only change without publishing drafts or checking assessment outdating', async () => {
            const { puts, modes } = await mountVariant(structured, undefined, null, 'free');
            expect(screen.getByRole('textbox', { name: 'Threat Model' })).toHaveValue(structured.threatModel);
            switchContextMode('stride');
            fireEvent.change(screen.getByLabelText('Threat 1 description'), { target: { value: 'Unsaved threat draft' } });
            selectContextTab('Context');
            fireEvent.click(screen.getByRole('button', { name: 'Save Context' }));
            await screen.findByText('Context saved successfully.');
            expect(patchBodies()).toEqual([{ editor_mode: 'stride', expected: { editor_mode: 'free' } }]);
            expect(puts[0]).toMatchObject({ editor_mode: 'stride', threat_model: structured.threatModel, risks: structured.risks });
            expect(modes.get('v1')).toBe('stride');
            expect(fetchMock.mock.calls.some(call => String(call[0]).includes('/api/reviews/assessments'))).toBe(false);
            selectContextTab('Threat model');
            expect(screen.getByLabelText('Threat 1 description')).toHaveValue('Unsaved threat draft');
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v2' } });
            await waitFor(() => expect(screen.getByLabelText('Editor mode')).toHaveValue('free'));
            fireEvent.change(screen.getByLabelText('Variant'), { target: { value: 'v1' } });
            await waitFor(() => expect(screen.getByLabelText('Threat 1 description')).toHaveValue('A device could be impersonated'));
            expect(screen.getByLabelText('Editor mode')).toHaveValue('stride');
        });

        test('an unsaved mode change is retained when the agent refreshes otherwise clean text', async () => {
            await mountVariant(structured, undefined, null, 'free');
            switchContextMode('stride');
            const loaded = contextRequests().length;
            agentWrite();
            expect(await screen.findByText(/agent updated the variant context/i)).toBeInTheDocument();
            expect(contextRequests()).toHaveLength(loaded);
            expect(screen.getByLabelText('Editor mode')).toHaveValue('stride');
        });
    });

    describe('import / export', () => {
        let createObjSpy: jest.Mock;
        let clickSpy: jest.SpyInstance;

        beforeEach(() => {
            createObjSpy = jest.fn(() => 'blob:mock');
            (global.URL as any).createObjectURL = createObjSpy;
            (global.URL as any).revokeObjectURL = jest.fn();
            clickSpy = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        });

        afterEach(() => {
            clickSpy.mockRestore();
        });

        test('shows Import before Export', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }]));
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            const transferActions = screen.getAllByRole('button')
                .map(button => button.getAttribute('aria-label'))
                .filter(label => label === 'Import context' || label === 'Export context');
            expect(transferActions).toEqual(['Import context', 'Export context']);
        });

        test('export menu loads variants and downloads selected', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }])); // projects
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            // Opening the menu lazily loads all variants
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'v1', name: 'Variant 1', project_id: 'p1' }]));
            fireEvent.click(screen.getByRole('button', { name: /export context/i }));

            const checkbox = await screen.findByLabelText('Export Project A / Variant 1');
            fireEvent.click(checkbox);

            // Export selected -> server-side exportSelected(variant_ids), no client filtering
            fetchMock.mockResponseOnce(JSON.stringify({
                version: '2.0',
                exported_at: '2026-07-22T00:00:00+00:00',
                projects: [
                    {
                        project_name: 'Project A',
                        project_description: 'd',
                        variants: [
                            {
                                variant_name: 'Variant 1',
                                variant_description: null, codebase_paths: [], environment: null, editor_mode: 'free',
                                threat_model: 't', risks: null, other_info: null,
                            },
                        ],
                    },
                ],
            }));
            fireEvent.click(screen.getByRole('button', { name: /export selected/i }));

            await waitFor(() => expect(clickSpy).toHaveBeenCalled());
            expect(createObjSpy).toHaveBeenCalled();
            const exportCall = fetchMock.mock.calls.find(c => String(c[0]).includes('/api/context/export'));
            expect(exportCall).toBeDefined();
            expect(String(exportCall![0])).toContain('variant_ids=v1');
        });


        test('import shows summary banner and detail list', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }])); // projects
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            fetchMock.mockResponseOnce(JSON.stringify({
                imported: [{ project_name: 'Project A', variant_name: 'Variant 1' }],
                ignored: [{ project_name: 'X', variant_name: 'Y', reason: 'Project not found' }],
                failed: [],
            }));

            const payload = JSON.stringify([
                {
                    project_name: 'Project A',
                    project_description: 'd',
                    variants: [{ variant_name: 'Variant 1', threat_model: 't' }],
                },
            ]);
            const file = new File([payload], 'ctx.json', { type: 'application/json' });
            (file as any).text = () => Promise.resolve(payload);
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });

            await waitFor(() => expect(screen.getByText(/import complete/i)).toBeInTheDocument());
            expect(screen.getByText(/Project not found/i)).toBeInTheDocument();

            const importCall = fetchMock.mock.calls.find(
                c => String(c[0]).includes('/api/context/import') && (c[1] as any)?.method === 'POST'
            );
            expect(importCall).toBeDefined();
        });

        test('import forwards an envelope object to the backend', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }])); // projects
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            fetchMock.mockResponseOnce(JSON.stringify({
                imported: [{ project_name: 'Project A', variant_name: 'Variant 1' }],
                ignored: [],
                failed: [],
            }));

            const envelope = JSON.stringify({
                version: '1.0',
                exported_at: '2026-07-22T00:00:00+00:00',
                projects: [
                    {
                        project_name: 'Project A',
                        project_description: 'd',
                        variants: [
                            { variant_name: 'Variant 1', threat_model: 't' },
                        ],
                    },
                ],
            });
            const file = new File([envelope], 'ctx.json', { type: 'application/json' });
            (file as any).text = () => Promise.resolve(envelope);
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });

            await waitFor(() => expect(screen.getByText(/import complete/i)).toBeInTheDocument());
            const importCall = fetchMock.mock.calls.find(
                c => String(c[0]).includes('/api/context/import') && (c[1] as any)?.method === 'POST'
            );
            expect(importCall).toBeDefined();
            expect(JSON.parse((importCall![1] as any).body).version).toBe('1.0');
        });

        test('import rejects a file that is not valid JSON', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }])); // projects
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            const file = new File(['not json'], 'ctx.json', { type: 'application/json' });
            (file as any).text = () => Promise.resolve('not json');
            fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });

            await waitFor(() => expect(screen.getByText(/not valid JSON/i)).toBeInTheDocument());
            // No import request should have been sent
            const importCall = fetchMock.mock.calls.find(c => String(c[0]).includes('/api/context/import'));
            expect(importCall).toBeUndefined();
        });

        test('import help tooltip toggles on the question-mark button', async () => {
            fetchMock.mockResponseOnce(JSON.stringify([{ id: 'p1', name: 'Project A' }])); // projects
            render(<AIContext />);
            await screen.findByRole('option', { name: 'Project A' });

            expect(screen.queryByRole('tooltip')).toBeNull();
            fireEvent.click(screen.getByRole('button', { name: /import help/i }));
            const tip = await screen.findByRole('tooltip');
            expect(tip).toHaveTextContent(/overwrites the existing context/i);
        });
    });
});
