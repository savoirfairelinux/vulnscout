import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();
// @ts-expect-error TS6133
import React from 'react';
import { useState } from 'react';

import AIContext from '../../src/pages/AIContext';
import type { AiContextScope } from '../../src/pages/AIContext';
import { UnsavedGuardProvider, useUnsavedGuard } from '../../src/hooks/useUnsavedGuard';
import { AGENT_WRITE_EVENT } from '../../src/types/agent';
import type { AgentViewContext } from '../../src/types/agent';
import { emptyStrideModel } from '../../src/helpers/strideModel';

const PROJECTS = [{ id: 'p1', name: 'Project A' }];
const VARIANTS = [
    { id: 'v1', name: 'Variant 1', project_id: 'p1' },
    { id: 'v2', name: 'Variant 2', project_id: 'p1' },
];
const AI_ROW = {
    id: 'a1', vuln_id: 'CVE-1', status: 'affected', timestamp: '2026-01-01T00:00:00Z',
    origin: 'ai', packages: [], responses: [],
};
const DIRTY_VARIANT_TEXT = "The agent updated the variant context. Your unsaved edits were kept; saving replaces the agent's change.";
const DIRTY_PROJECT_TEXT = "The agent updated the project description. Your unsaved edits were kept; saving replaces the agent's change.";

type Request = { url: string; method: string; body: string | null };
type FileRow = { id: string; original_name: string; description: string | null };
type Backend = {
    description: string; threat: string; aiRows: unknown[]; requests: Request[]; files: FileRow[];
    variantPutError?: { error: string; fields: Record<string, string> };
    echoPut?: boolean;
};

function variantContext(variantId: string, threat: string, files: FileRow[] = []) {
    return {
        project_id: 'p1', description: 'ignored', variant_id: variantId, variant_description: null,
        codebase_path: null, environment: null, threat_model: threat, risks: null, other_info: null, files,
        editor: {
            editor_mode: 'free', codebase_source: 'paths', codebase_path: null,
            free: { threat_model: threat, risks: null },
            system: { scope: null, actors: null, entry_points: null, trust_boundaries: null },
            stride: emptyStrideModel(), files, updated_at: null,
        },
    };
}

function respond(backend: Backend, url: string, method: string, body: string | null): unknown {
    const path = url.replace('http://localhost', '').split('?')[0];
    if (path === '/api/version') return { version: 'test' };
    if (path === '/api/projects') return PROJECTS;
    if (path === '/api/variants') return VARIANTS;
    if (path === '/api/projects/p1/variants') return VARIANTS;
    if (path === '/api/reviews/assessments') return backend.aiRows;
    if (path === '/api/projects/p1/context') {
        if (method === 'PUT') backend.description = JSON.parse(body ?? '{}').description;
        return { project_id: 'p1', description: backend.description };
    }
    if (path === '/api/context') {
        const variantId = new URL(url).searchParams.get('variant_id') ?? '';
        return variantContext(variantId, backend.threat, backend.files);
    }
    if (/^\/api\/variants\/[^/]+\/context\/files$/.test(path)) {
        const reference = { id: `f${backend.files.length + 1}`, original_name: 'source.zip', description: null };
        backend.files = [...backend.files, reference];
        return reference;
    }
    const variantPut = /^\/api\/variants\/([^/]+)\/context$/.exec(path);
    if (variantPut) {
        const ctx = variantContext(variantPut[1], backend.threat, backend.files);
        // Echo the saved editor shape back, as the real server does.
        return backend.echoPut ? { ...ctx, editor: { ...ctx.editor, ...JSON.parse(body ?? '{}') } } : ctx;
    }
    return {};
}

function mockBackend(overrides: Partial<Backend> = {}): Backend {
    const backend: Backend = { description: 'Desc', threat: 'TM', aiRows: [], requests: [], files: [], ...overrides };
    fetchMock.mockResponse(async request => {
        const body = request.method === 'GET' ? null : await request.text();
        backend.requests.push({ url: request.url, method: request.method, body });
        if (backend.variantPutError && request.method === 'PUT' && request.url.includes('/api/variants/')) {
            return { status: 400, body: JSON.stringify(backend.variantPutError) };
        }
        return JSON.stringify(respond(backend, request.url, request.method, body));
    });
    return backend;
}

const requestsTo = (backend: Backend, fragment: string, method = 'GET') =>
    backend.requests.filter(r => r.url.includes(fragment) && r.method === method);

function renderPage(scope: AiContextScope, onAgentContextChange?: (context: AgentViewContext) => void) {
    const ui = (s: AiContextScope) => (
        <UnsavedGuardProvider>
            <AIContext scope={s} onAgentContextChange={onAgentContextChange} />
        </UnsavedGuardProvider>
    );
    const utils = render(ui(scope));
    return { ...utils, setScope: (s: AiContextScope) => utils.rerender(ui(s)) };
}

const sidebarItem = (name: string) => screen.getByRole('button', { name });

async function openProjectDescription() {
    fireEvent.click(await screen.findByRole('button', { name: 'Project description' }));
    await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
}

async function openVariant1() {
    await waitFor(() => expect(screen.getByLabelText('Variant description')).toBeInTheDocument());
}

const variantTab = (name: string) => screen.getByRole('tab', { name });

const agentWrite = (tool: string) => act(() => {
    window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool } }));
});

beforeEach(() => fetchMock.resetMocks());

describe('AIContext page', () => {
    test('sidebar lists all project variants and locks out-of-scope ones', async () => {
        mockBackend();
        renderPage({ projectId: 'p1', variantIds: ['v1'] });

        const locked = await screen.findByRole('button', { name: 'Variant 2' });
        expect(locked).toHaveAttribute('aria-disabled', 'true');
        expect(locked).toHaveAttribute('aria-describedby', 'ai-context-scope-hint');
        expect(document.getElementById('ai-context-scope-hint')).toHaveTextContent(
            'Locked variants are outside the current scope. Add them with the project/variant selector in the top bar.'
        );
        expect(sidebarItem('Variant 1')).not.toHaveAttribute('aria-disabled');
        expect(screen.getByText('1 of 2 in scope')).toBeInTheDocument();
        expect(sidebarItem('Project description')).toBeInTheDocument();
    });

    test('locked variant cannot be selected by click or keyboard', async () => {
        const backend = mockBackend();
        const user = userEvent.setup();
        renderPage({ projectId: 'p1', variantIds: ['v1'] });
        const locked = await screen.findByRole('button', { name: 'Variant 2' });
        await waitFor(() => expect(sidebarItem('Variant 1')).toHaveAttribute('aria-current', 'true'));

        await user.click(locked);
        locked.focus();
        await user.keyboard('{Enter}');
        await user.keyboard(' ');

        expect(sidebarItem('Variant 1')).toHaveAttribute('aria-current', 'true');
        expect(locked).not.toHaveAttribute('aria-current');
        expect(requestsTo(backend, 'variant_id=v2')).toHaveLength(0);
    });

    test('initial selection is the first in-scope variant', async () => {
        const backend = mockBackend();
        const { setScope } = renderPage({ projectId: 'p1', variantIds: ['v2'] });

        await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
        expect(await screen.findByRole('region', { name: 'Variant 2' })).toBeInTheDocument();
        await waitFor(() => expect(requestsTo(backend, 'variant_id=v2')).toHaveLength(1));
        expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(0);

        // Whole-project scope: every variant is in scope, the first one opens.
        setScope({ projectId: 'p1' });
        await waitFor(() => expect(screen.getByText('2 of 2 in scope')).toBeInTheDocument());
        expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true');
    });

    test('opens the project description when no variant is in scope', async () => {
        mockBackend();
        renderPage({ projectId: 'p1', variantIds: [] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        expect(sidebarItem('Project description')).toHaveAttribute('aria-current', 'true');
    });

    test('switching sidebar item with unsaved edits asks Save/Discard/Cancel', async () => {
        mockBackend();
        renderPage({ projectId: 'p1' });
        await openProjectDescription();
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Edited' } });
        expect(screen.getByText('Unsaved changes in Project A')).toHaveAttribute('role', 'status');

        fireEvent.click(sidebarItem('Variant 2'));
        const dialog = await screen.findByRole('alertdialog', { name: 'Unsaved changes' });
        expect(dialog).toHaveTextContent('You have unsaved changes in Project A.');
        expect(within(dialog).getByRole('button', { name: 'Save' })).toHaveFocus();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
        expect(screen.getByLabelText('Project description')).toHaveValue('Edited');
        expect(sidebarItem('Project description')).toHaveAttribute('aria-current', 'true');

        fireEvent.click(sidebarItem('Variant 2'));
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Discard' }));
        await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
        expect(screen.queryByText('Unsaved changes in Project A')).not.toBeInTheDocument();
    });

    test('guard Save goes through the outdated-assessment confirmation', async () => {
        const backend = mockBackend({ aiRows: [AI_ROW] });
        renderPage({ projectId: 'p1' });
        await openProjectDescription();
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'New desc' } });

        // Cancelling the confirmation keeps the item open with its edits.
        fireEvent.click(sidebarItem('Variant 2'));
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
        expect(await screen.findByText('Mark AI assessments as outdated?')).toBeInTheDocument();
        expect(requestsTo(backend, 'project_id=p1').some(r => r.url.includes('/api/reviews/assessments'))).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        await waitFor(() => expect(screen.queryByText('Mark AI assessments as outdated?')).not.toBeInTheDocument());
        expect(requestsTo(backend, '/api/projects/p1/context', 'PUT')).toHaveLength(0);
        expect(sidebarItem('Project description')).toHaveAttribute('aria-current', 'true');
        expect(screen.getByLabelText('Project description')).toHaveValue('New desc');

        // Confirming saves, then the switch goes ahead.
        fireEvent.click(sidebarItem('Variant 2'));
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
        fireEvent.click(await screen.findByRole('button', { name: 'Save and mark outdated' }));
        await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
        const puts = requestsTo(backend, '/api/projects/p1/context', 'PUT');
        expect(puts).toHaveLength(1);
        expect(JSON.parse(puts[0].body ?? '{}')).toEqual({ description: 'New desc' });
    });

    test('project description Save disabled until changed and requires text', async () => {
        const backend = mockBackend();
        renderPage({ projectId: 'p1', variantIds: [] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        const save = screen.getByRole('button', { name: 'Save changes' });
        expect(save).toBeDisabled();
        expect(screen.getByText(
            'Changing the project description marks AI assessments of every variant in this project as outdated.'
        )).toBeInTheDocument();
        expect(screen.getByText('Project')).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Desc!' } });
        expect(save).toBeEnabled();
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: '   ' } });
        fireEvent.click(save);

        expect(await screen.findByText('Project description is required.')).toBeInTheDocument();
        expect(requestsTo(backend, '/api/projects/p1/context', 'PUT')).toHaveLength(0);
        expect(requestsTo(backend, '/api/reviews/assessments')).toHaveLength(0);
    });

    test('saved announcement is spoken via status region', async () => {
        const backend = mockBackend();
        renderPage({ projectId: 'p1', variantIds: [] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Saved desc' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

        await waitFor(() => expect(screen.getByText('Saved.')).toHaveAttribute('role', 'status'));
        expect(requestsTo(backend, '/api/projects/p1/context', 'PUT')).toHaveLength(1);
        expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
        expect(screen.queryByText('Unsaved changes in Project A')).not.toBeInTheDocument();
        expect(screen.queryByText('Mark AI assessments as outdated?')).not.toBeInTheDocument();
    });

    test('agent write keeps unsaved edits and shows banner', async () => {
        const backend = mockBackend();
        renderPage({ projectId: 'p1', variantIds: [] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Mine' } });
        backend.description = 'Agent';
        const loads = requestsTo(backend, '/api/projects/p1/context').length;

        agentWrite('update_project_context');

        expect(await screen.findByText(DIRTY_PROJECT_TEXT)).toBeInTheDocument();
        expect(requestsTo(backend, '/api/projects/p1/context')).toHaveLength(loads);
        expect(screen.getByLabelText('Project description')).toHaveValue('Mine');
        expect(screen.queryByText(DIRTY_VARIANT_TEXT)).not.toBeInTheDocument();
    });

    test('agent write reloads when clean', async () => {
        const backend = mockBackend();
        const onAgentContextChange = jest.fn();
        renderPage({ projectId: 'p1' }, onAgentContextChange);
        await waitFor(() => expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(1));
        await waitFor(() => expect(onAgentContextChange).toHaveBeenLastCalledWith(expect.objectContaining({
            selectedProjectId: 'p1', selectedProjectName: 'Project A',
            selectedVariantId: 'v1', selectedVariantName: 'Variant 1',
        })));

        agentWrite('update_variant_context');
        await waitFor(() => expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(2));

        await openProjectDescription();
        expect(onAgentContextChange).toHaveBeenLastCalledWith(expect.objectContaining({
            selectedProjectId: 'p1', selectedVariantId: undefined,
        }));
        backend.description = 'Agent v2';
        agentWrite('update_project_context');
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Agent v2'));
        expect(screen.queryByText(DIRTY_PROJECT_TEXT)).not.toBeInTheDocument();
    });

    test('scope change removing the selected variant falls back to first in-scope', async () => {
        mockBackend();
        const { setScope } = renderPage({ projectId: 'p1' });
        await waitFor(() => expect(sidebarItem('Variant 1')).toHaveAttribute('aria-current', 'true'));
        fireEvent.click(sidebarItem('Variant 2'));
        await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));

        setScope({ projectId: 'p1', variantIds: ['v1'] });
        await waitFor(() => expect(sidebarItem('Variant 1')).toHaveAttribute('aria-current', 'true'));
        expect(sidebarItem('Variant 2')).toHaveAttribute('aria-disabled', 'true');

        // A scope applied after "Discard" drops the open item's edits.
        await openProjectDescription();
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Dropped' } });
        setScope({ projectId: 'p1', variantIds: ['v2'] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        expect(screen.queryByText('Unsaved changes in Project A')).not.toBeInTheDocument();
    });

    test('discard before applying an identical scope drops the edits', async () => {
        mockBackend();
        const { setScope } = renderPage({ projectId: 'p1', revision: 1 });
        await openProjectDescription();
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Dropped' } });
        expect(screen.getByText('Unsaved changes in Project A')).toBeInTheDocument();

        // Same in-scope set, new revision: what Explorer applies after "Discard".
        setScope({ projectId: 'p1', revision: 2 });

        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        expect(screen.queryByText('Unsaved changes in Project A')).not.toBeInTheDocument();
        fireEvent.click(sidebarItem('Variant 2'));
        expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
        await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
    });

    test('asks before importing while the open item has unsaved edits', async () => {
        mockBackend();
        renderPage({ projectId: 'p1', variantIds: [] });
        await waitFor(() => expect(screen.getByLabelText('Project description')).toHaveValue('Desc'));
        fireEvent.change(screen.getByLabelText('Project description'), { target: { value: 'Edited' } });
        const pick = jest.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(() => {});

        fireEvent.click(screen.getByRole('button', { name: 'Import context' }));
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' }));
        await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
        expect(pick).not.toHaveBeenCalled();

        fireEvent.click(screen.getByRole('button', { name: 'Import context' }));
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Discard' }));
        await waitFor(() => expect(pick).toHaveBeenCalledTimes(1));
        pick.mockRestore();
    });

    describe('variant editor', () => {
        test('title row shows the variant name, badge and actions', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();

            expect(screen.getByRole('heading', { level: 2, name: 'Variant 1' })).toBeInTheDocument();
            expect(screen.getByText('Variant')).toBeInTheDocument();
            expect(screen.getByRole('button', { name: 'Copy from…' })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
            const fields = ['Variant description', 'Codebase paths', 'Environment', 'Other information']
                .map(name => screen.getByRole('textbox', { name }));
            fields.slice(1).forEach((field, index) => {
                expect(fields[index].compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
            });
            expect(screen.getByText('Separate several paths with ";".')).toBeInTheDocument();
        });

        test('tabs follow the WAI-ARIA keyboard pattern', async () => {
            mockBackend();
            const user = userEvent.setup();
            renderPage({ projectId: 'p1' });
            await openVariant1();

            const tablist = screen.getByRole('tablist', { name: 'Variant context sections' });
            const names = within(tablist).getAllByRole('tab').map(tab => tab.textContent);
            expect(names).toEqual(['Context', 'System', 'Threat model', 'Risks']);
            expect(variantTab('Context')).toHaveAttribute('aria-selected', 'true');
            expect(variantTab('Context')).toHaveAttribute('tabindex', '0');
            expect(variantTab('System')).toHaveAttribute('tabindex', '-1');
            const panels = screen.getAllByRole('tabpanel', { hidden: true });
            expect(panels).toHaveLength(4);
            expect(screen.getByRole('tabpanel', { name: 'Context' })).toBeVisible();
            expect(panels.filter(panel => panel.hidden)).toHaveLength(3);

            variantTab('Context').focus();
            await user.keyboard('{ArrowLeft}');
            expect(variantTab('Risks')).toHaveFocus();
            expect(variantTab('Risks')).toHaveAttribute('aria-selected', 'true');
            expect(screen.getByRole('tabpanel', { name: 'Risks' })).toBeVisible();
            await user.keyboard('{ArrowRight}');
            expect(variantTab('Context')).toHaveFocus();
            await user.keyboard('{ArrowRight}');
            expect(variantTab('System')).toHaveFocus();
            expect(variantTab('System')).toHaveAttribute('tabindex', '0');
            expect(variantTab('Context')).toHaveAttribute('tabindex', '-1');
            await user.keyboard('{End}');
            expect(variantTab('Risks')).toHaveFocus();
            await user.keyboard('{Home}');
            expect(variantTab('Context')).toHaveFocus();
            expect(screen.getByLabelText('Variant description')).toBeVisible();
        });

        test('edits survive switching tabs', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Factory floor' } });

            fireEvent.click(variantTab('Threat model'));
            expect(screen.getByLabelText('Environment')).not.toBeVisible();
            fireEvent.click(variantTab('Context'));

            expect(screen.getByLabelText('Environment')).toHaveValue('Factory floor');
            expect(screen.getByText('Unsaved changes in Variant 1')).toBeInTheDocument();
        });

        test('codebase radio shows only the selected source and keeps the hidden value', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            const source = screen.getByRole('radiogroup', { name: 'Codebase source' });
            expect(within(source).getByRole('radio', { name: 'Codebase paths' })).toBeChecked();
            expect(screen.queryByRole('region', { name: 'Codebase references' })).not.toBeInTheDocument();
            fireEvent.change(screen.getByRole('textbox', { name: 'Codebase paths' }), { target: { value: '/src/a;/src/b' } });

            fireEvent.click(within(source).getByRole('radio', { name: 'Codebase references' }));
            expect(screen.getByRole('region', { name: 'Codebase references' })).toBeVisible();
            expect(screen.getByRole('textbox', { name: 'Codebase paths', hidden: true })).not.toBeVisible();

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
            await waitFor(() => expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(1));
            const body = JSON.parse(requestsTo(backend, '/api/variants/v1/context', 'PUT')[0].body ?? '{}');
            expect(body.codebase_source).toBe('references');
            expect(body.codebase_path).toBe('/src/a;/src/b');
        });

        test('switching editor mode Free to STRIDE pre-fills notes', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            const mode = screen.getByRole('radiogroup', { name: 'Editor mode' });
            expect(within(mode).getByRole('radio', { name: 'Free' })).toBeChecked();

            fireEvent.click(within(mode).getByRole('radio', { name: 'STRIDE' }));
            expect(within(mode).getByRole('radio', { name: 'STRIDE' })).toBeChecked();
            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            await waitFor(() => expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(1));
            const body = JSON.parse(requestsTo(backend, '/api/variants/v1/context', 'PUT')[0].body ?? '{}');
            expect(body.editor_mode).toBe('stride');
            expect(body.stride.notes).toBe('TM');
            expect(body.free.threat_model).toBe('TM');
        });

        test('Save changes disabled until the draft differs from saved', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            const save = screen.getByRole('button', { name: 'Save changes' });
            expect(save).toBeDisabled();

            fireEvent.change(screen.getByLabelText('Other information'), { target: { value: 'x' } });
            expect(save).toBeEnabled();
            fireEvent.change(screen.getByLabelText('Other information'), { target: { value: '' } });
            expect(save).toBeDisabled();
            expect(screen.queryByText('Unsaved changes in Variant 1')).not.toBeInTheDocument();
        });

        test('variant save sends the editor shape through saveVariantEditor', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Variant description'), { target: { value: 'Gateway' } });
            fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Lab' } });

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            await waitFor(() => expect(screen.getByText('Saved.')).toBeInTheDocument());
            const puts = requestsTo(backend, '/api/variants/v1/context', 'PUT');
            expect(puts).toHaveLength(1);
            expect(JSON.parse(puts[0].body ?? '{}')).toEqual({
                variant_description: 'Gateway', environment: 'Lab', other_info: null,
                editor_mode: 'free', codebase_source: 'paths', codebase_path: null,
                free: { threat_model: 'TM', risks: null },
                system: { scope: null, actors: null, entry_points: null, trust_boundaries: null },
                stride: emptyStrideModel(),
            });
        });

        test('a missing threat model blocks the save and opens the Threat model tab', async () => {
            const backend = mockBackend({ threat: '' });
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Lab' } });

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            expect(await screen.findByText('A threat model is required.')).toBeInTheDocument();
            expect(variantTab('Threat model')).toHaveAttribute('aria-selected', 'true');
            expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(0);
        });

        test('save 400 marks the offending field and shows the error banner', async () => {
            mockBackend({ variantPutError: { error: 'Invalid variant context', fields: { environment: 'must be text' } } });
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Environment'), { target: { value: 'Lab' } });

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            expect(await screen.findByText('Invalid variant context')).toBeInTheDocument();
            const environment = screen.getByLabelText('Environment');
            expect(environment).toHaveAttribute('aria-invalid', 'true');
            expect(environment).toHaveAccessibleDescription('must be text');
            expect(screen.getByLabelText('Other information')).not.toHaveAttribute('aria-invalid');
            expect(environment).toHaveValue('Lab');
        });

        test('agent write on a dirty variant keeps the edits and shows the banner', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Variant description'), { target: { value: 'Mine' } });
            const loads = requestsTo(backend, 'variant_id=v1').length;

            agentWrite('update_variant_context');

            expect(await screen.findByText(DIRTY_VARIANT_TEXT)).toBeInTheDocument();
            expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(loads);
            expect(screen.getByLabelText('Variant description')).toHaveValue('Mine');
            expect(screen.queryByText(DIRTY_PROJECT_TEXT)).not.toBeInTheDocument();
        });

        test('uploading references keeps unsaved fields', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.change(screen.getByLabelText('Variant description'), { target: { value: 'Unsaved desc' } });
            fireEvent.click(screen.getByRole('radio', { name: 'Codebase references' }));

            fireEvent.drop(screen.getByRole('region', { name: 'Drop codebase files' }), {
                dataTransfer: { files: [new File(['source'], 'source.zip')] },
            });

            await screen.findByRole('button', { name: 'Delete reference source.zip' });
            expect(screen.getByLabelText('Variant description')).toHaveValue('Unsaved desc');
            expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(0);
            expect(requestsTo(backend, '/api/variants/v1/context/files', 'POST')).toHaveLength(1);

            // Reopening the variant shows the stored reference from the server.
            fireEvent.click(sidebarItem('Variant 2'));
            fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Discard' }));
            await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
            fireEvent.click(sidebarItem('Variant 1'));
            await screen.findByRole('region', { name: 'Variant 1' });
            await waitFor(() => expect(screen.getByLabelText('Variant description')).toHaveValue(''));
            fireEvent.click(screen.getByRole('radio', { name: 'Codebase references' }));
            expect(await screen.findByRole('button', { name: 'Delete reference source.zip' })).toBeInTheDocument();
        });
    });

    describe('system tab', () => {
        async function openSystemTab(backend?: Partial<Backend>) {
            const mocked = mockBackend(backend);
            const utils = renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.click(screen.getByRole('radio', { name: 'STRIDE' }));
            fireEvent.click(variantTab('System'));
            return { backend: mocked, ...utils };
        }
        const addComponent = (name: string) => {
            fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
            const inputs = screen.getAllByLabelText(/^Component C\d+ name$/);
            fireEvent.change(inputs[inputs.length - 1], { target: { value: name } });
        };

        test('free mode shows only the note', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await openVariant1();
            fireEvent.click(variantTab('System'));

            expect(screen.getByText('In Free mode, describe the system and its interactions in Threat model.')).toBeInTheDocument();
            expect(screen.queryByLabelText('System scope and assets')).not.toBeInTheDocument();
            expect(screen.queryByRole('table', { name: 'Components' })).not.toBeInTheDocument();
        });

        test('STRIDE mode shows the four system fields and both tables with column headers', async () => {
            await openSystemTab();

            ['System scope and assets', 'Actors and access', 'Entry points and data flows', 'Trust boundaries']
                .forEach(label => expect(screen.getByLabelText(label)).toBeInTheDocument());
            const components = screen.getByRole('table', { name: 'Components' });
            expect(within(components).getAllByRole('columnheader').map(h => h.textContent))
                .toEqual(['ID', 'Name', 'Description / role', 'Trust zone', 'Remove']);
            const interactions = screen.getByRole('table', { name: 'Interactions' });
            expect(within(interactions).getAllByRole('columnheader').map(h => h.textContent)).toEqual([
                'ID', 'Name', 'Source', 'Destination', 'Interface / protocol', 'Data / commands', 'Trust boundary', 'Remove',
            ]);
        });

        test('adds and removes a component and saves the rows', async () => {
            const { backend } = await openSystemTab();
            fireEvent.change(screen.getByLabelText('System scope and assets'), { target: { value: 'Gateway' } });
            addComponent('Broker');
            fireEvent.change(screen.getByLabelText('Component C1 trust zone'), { target: { value: 'DMZ' } });
            addComponent('Temp');
            expect(screen.getByLabelText('Component C2 name')).toHaveValue('Temp');

            fireEvent.click(screen.getByRole('button', { name: 'Remove component C2' }));
            expect(screen.queryByLabelText('Component C2 name')).not.toBeInTheDocument();
            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            await waitFor(() => expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(1));
            const body = JSON.parse(requestsTo(backend, '/api/variants/v1/context', 'PUT')[0].body ?? '{}');
            expect(body.system.scope).toBe('Gateway');
            expect(body.stride.components).toEqual([{ id: 'C1', name: 'Broker', description: '', trust_zone: 'DMZ' }]);
        });

        test('removed ids are not reused by the next add', async () => {
            await openSystemTab();
            addComponent('A');
            addComponent('B');
            fireEvent.click(screen.getByRole('button', { name: 'Remove component C2' }));

            addComponent('C');

            expect(screen.getByLabelText('Component C3 name')).toHaveValue('C');
            expect(screen.queryByLabelText('Component C2 name')).not.toBeInTheDocument();
        });

        test('a referenced component cannot be removed and says why', async () => {
            await openSystemTab();
            addComponent('A');
            addComponent('B');
            fireEvent.click(screen.getByRole('button', { name: 'Add interaction' }));
            fireEvent.change(screen.getByLabelText('Interaction I1 source'), { target: { value: 'C1' } });
            fireEvent.change(screen.getByLabelText('Interaction I1 destination'), { target: { value: 'C2' } });

            const remove = screen.getByRole('button', { name: 'Remove component C1' });
            expect(remove).toBeDisabled();
            expect(remove).toHaveAccessibleDescription('Remove its interactions, threat targets and risks first.');
            expect(screen.getByRole('button', { name: 'Remove interaction I1' })).toBeEnabled();

            fireEvent.click(screen.getByRole('button', { name: 'Remove interaction I1' }));
            expect(screen.getByRole('button', { name: 'Remove component C1' })).toBeEnabled();
        });

        test('endpoint selects list named components and disable unnamed ones', async () => {
            await openSystemTab();
            addComponent('Broker');
            fireEvent.click(screen.getByRole('button', { name: 'Add component' }));
            fireEvent.click(screen.getByRole('button', { name: 'Add interaction' }));

            const source = screen.getByLabelText('Interaction I1 source');
            const options = within(source).getAllByRole('option');
            expect(options.map(o => o.textContent)).toEqual(['Select a component', 'C1: Broker', 'C2: ']);
            expect(options[1]).toBeEnabled();
            expect(options[2]).toBeDisabled();
        });

        test('save 400 maps server paths to cells and opens the System tab', async () => {
            const { backend } = await openSystemTab({
                variantPutError: {
                    error: 'Invalid variant context',
                    fields: { 'components[0].name': 'name is required', 'system.actors': 'must be text' },
                },
            });
            addComponent('Broker');
            fireEvent.click(variantTab('Context'));

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

            expect(await screen.findByText('Invalid variant context')).toBeInTheDocument();
            expect(variantTab('System')).toHaveAttribute('aria-selected', 'true');
            const cell = screen.getByLabelText('Component C1 name');
            expect(cell).toHaveAttribute('aria-invalid', 'true');
            expect(cell).toHaveAccessibleDescription('name is required');
            expect(screen.getByLabelText('Actors and access')).toHaveAccessibleDescription('must be text');
            expect(screen.getByLabelText('Component C1 trust zone')).not.toHaveAttribute('aria-invalid');
            expect(requestsTo(backend, '/api/variants/v1/context', 'PUT')).toHaveLength(1);
        });

        async function failSave() {
            const utils = await openSystemTab({
                variantPutError: { error: 'Invalid variant context', fields: { 'system.actors': 'must be text' } },
            });
            fireEvent.change(screen.getByLabelText('Actors and access'), { target: { value: 'x' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
            expect(await screen.findByText('must be text')).toBeInTheDocument();
            expect(variantTab('System')).toHaveAttribute('aria-selected', 'true');
            return utils;
        }

        test('discarding with a same-scope revision clears errors and returns to the Context tab', async () => {
            const { setScope } = await failSave();

            setScope({ projectId: 'p1', revision: 1 });

            await waitFor(() => expect(screen.queryByText('must be text')).not.toBeInTheDocument());
            expect(variantTab('Context')).toHaveAttribute('aria-selected', 'true');
        });

        test('importing over the open item clears errors and returns to the Context tab', async () => {
            const createObjectURL = jest.fn(() => 'blob:mock');
            (global.URL as any).createObjectURL = createObjectURL;
            await failSave();
            fetchMock.mockResponseOnce(JSON.stringify({ imported: [], ignored: [], failed: [] }));
            const text = JSON.stringify({ version: '1.0', exported_at: 'x', projects: [] });
            const file = new File([text], 'ctx.json', { type: 'application/json' });
            (file as any).text = () => Promise.resolve(text);

            const pick = jest.spyOn(HTMLInputElement.prototype, 'click').mockImplementation(() => {});
            fireEvent.click(screen.getByRole('button', { name: 'Import context' }));
            fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Discard' }));
            await waitFor(() => expect(pick).toHaveBeenCalledTimes(1));
            pick.mockRestore();
            await act(async () => {
                fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });
            });

            await waitFor(() => expect(screen.queryByText('must be text')).not.toBeInTheDocument());
            expect(variantTab('Context')).toHaveAttribute('aria-selected', 'true');
        });

        test('removed ids are reserved until the draft is saved', async () => {
            await openSystemTab({ echoPut: true });
            addComponent('A');
            addComponent('B');
            fireEvent.click(screen.getByRole('button', { name: 'Remove component C2' }));
            addComponent('C');
            expect(screen.getByLabelText('Component C3 name')).toHaveValue('C');
            fireEvent.click(screen.getByRole('button', { name: 'Remove component C3' }));

            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
            await waitFor(() => expect(screen.getByText('Saved.')).toBeInTheDocument());
            addComponent('D');

            expect(screen.getByLabelText('Component C2 name')).toHaveValue('D');
        });

        test('a scope-driven selection change clears field errors and returns to the Context tab', async () => {
            const { setScope } = await openSystemTab({
                variantPutError: { error: 'Invalid variant context', fields: { 'system.actors': 'must be text' } },
            });
            fireEvent.change(screen.getByLabelText('Actors and access'), { target: { value: 'x' } });
            fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
            expect(await screen.findByText('must be text')).toBeInTheDocument();

            setScope({ projectId: 'p1', variantIds: ['v2'] });

            await waitFor(() => expect(sidebarItem('Variant 2')).toHaveAttribute('aria-current', 'true'));
            expect(await screen.findByRole('tab', { name: 'Context' })).toHaveAttribute('aria-selected', 'true');
            expect(screen.queryByText('must be text')).not.toBeInTheDocument();
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

        async function importFile(text: string) {
            const file = new File([text], 'ctx.json', { type: 'application/json' });
            (file as any).text = () => Promise.resolve(text);
            await act(async () => {
                fireEvent.change(screen.getByLabelText('Import context file'), { target: { files: [file] } });
            });
        }

        test('shows Import before Export', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await screen.findByRole('button', { name: 'Variant 1' });

            const transferActions = screen.getAllByRole('button')
                .map(button => button.getAttribute('aria-label'))
                .filter(label => label === 'Import context' || label === 'Export context');
            expect(transferActions).toEqual(['Import context', 'Export context']);
        });

        test('export menu loads variants and downloads selected', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await screen.findByRole('button', { name: 'Variant 1' });

            fireEvent.click(screen.getByRole('button', { name: /export context/i }));
            fireEvent.click(await screen.findByLabelText('Export Project A / Variant 1'));
            fireEvent.click(screen.getByRole('button', { name: /export selected/i }));

            await waitFor(() => expect(clickSpy).toHaveBeenCalled());
            expect(createObjSpy).toHaveBeenCalled();
            const exportCall = requestsTo(backend, '/api/context/export');
            expect(exportCall).toHaveLength(1);
            expect(exportCall[0].url).toContain('variant_ids=v1');
        });

        test('import shows summary banner and detail list, then reloads the open item', async () => {
            const backend = mockBackend();
            renderPage({ projectId: 'p1' });
            await waitFor(() => expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(1));
            fetchMock.mockResponseOnce(JSON.stringify({
                imported: [{ project_name: 'Project A', variant_name: 'Variant 1' }],
                ignored: [{ project_name: 'X', variant_name: 'Y', reason: 'Project not found' }],
                failed: [],
            }));

            await importFile(JSON.stringify({ version: '1.0', exported_at: 'x', projects: [] }));

            await waitFor(() => expect(screen.getByText(/import complete/i)).toBeInTheDocument());
            expect(screen.getByText(/Project not found/i)).toBeInTheDocument();
            const importCall = fetchMock.mock.calls.find(
                c => String(c[0]).includes('/api/context/import') && (c[1] as any)?.method === 'POST'
            );
            expect(JSON.parse((importCall![1] as any).body).version).toBe('1.0');
            await waitFor(() => expect(requestsTo(backend, 'variant_id=v1')).toHaveLength(2));
        });

        test('import rejects a file that is not valid JSON', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await screen.findByRole('button', { name: 'Variant 1' });

            await importFile('not json');

            await waitFor(() => expect(screen.getByText(/not valid JSON/i)).toBeInTheDocument());
            expect(fetchMock.mock.calls.find(c => String(c[0]).includes('/api/context/import'))).toBeUndefined();
        });

        test('import help tooltip toggles on the question-mark button', async () => {
            mockBackend();
            renderPage({ projectId: 'p1' });
            await screen.findByRole('button', { name: 'Variant 1' });

            expect(screen.queryByRole('tooltip')).toBeNull();
            fireEvent.click(screen.getByRole('button', { name: /import help/i }));
            expect(await screen.findByRole('tooltip')).toHaveTextContent(/overwrites the existing context/i);
        });
    });
});

function GuardHarness({ save }: Readonly<{ save: () => Promise<boolean> }>) {
    const { registerGuard, hasGuard, confirmLeave } = useUnsavedGuard();
    const [result, setResult] = useState('');
    return (
        <div>
            <button type="button" onClick={() => registerGuard({ label: 'Thing', save })}>register</button>
            <button type="button" onClick={() => registerGuard(null)}>unregister</button>
            <button type="button" onClick={() => { void confirmLeave().then(ok => setResult(String(ok))); }}>leave</button>
            <span data-testid="has-guard">{String(hasGuard)}</span>
            <span data-testid="result">{result}</span>
        </div>
    );
}

describe('useUnsavedGuard', () => {
    test('confirmLeave resolves true without a guard and Escape cancels', async () => {
        const save = jest.fn().mockResolvedValue(true);
        // Without a provider the hook is a no-op guard.
        const { unmount } = render(<GuardHarness save={save} />);
        fireEvent.click(screen.getByRole('button', { name: 'leave' }));
        await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('true'));
        unmount();

        render(<UnsavedGuardProvider><GuardHarness save={save} /></UnsavedGuardProvider>);
        fireEvent.click(screen.getByRole('button', { name: 'leave' }));
        await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('true'));
        expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'register' }));
        expect(screen.getByTestId('has-guard')).toHaveTextContent('true');
        const leave = screen.getByRole('button', { name: 'leave' });
        leave.focus();
        fireEvent.click(leave);
        const dialog = await screen.findByRole('alertdialog', { name: 'Unsaved changes' });
        expect(dialog).toHaveTextContent('You have unsaved changes in Thing.');
        expect(within(dialog).getByRole('button', { name: 'Save' })).toHaveFocus();
        fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
        await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('false'));
        expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
        expect(leave).toHaveFocus();

        fireEvent.click(leave);
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
        await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
        await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('true'));

        save.mockResolvedValueOnce(false);
        fireEvent.click(leave);
        fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Save' }));
        await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('false'));
    });

    test('beforeunload is prevented only while a guard is registered', () => {
        render(<UnsavedGuardProvider><GuardHarness save={jest.fn()} /></UnsavedGuardProvider>);
        const unload = () => {
            const event = new Event('beforeunload', { cancelable: true });
            window.dispatchEvent(event);
            return event.defaultPrevented;
        };

        expect(unload()).toBe(false);
        fireEvent.click(screen.getByRole('button', { name: 'register' }));
        expect(unload()).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: 'unregister' }));
        expect(unload()).toBe(false);
    });
});
