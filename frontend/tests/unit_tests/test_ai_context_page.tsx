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
type Backend = { description: string; threat: string; aiRows: unknown[]; requests: Request[] };

function variantContext(variantId: string, threat: string) {
    return {
        project_id: 'p1', description: 'ignored', variant_id: variantId, variant_description: null,
        codebase_path: null, environment: null, threat_model: threat, risks: null, other_info: null, files: [],
        editor: {
            editor_mode: 'free', codebase_source: 'paths', codebase_path: null,
            free: { threat_model: threat, risks: null },
            system: { scope: null, actors: null, entry_points: null, trust_boundaries: null },
            stride: emptyStrideModel(), files: [], updated_at: null,
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
        return variantContext(variantId, backend.threat);
    }
    const variantPut = /^\/api\/variants\/([^/]+)\/context$/.exec(path);
    if (variantPut) return variantContext(variantPut[1], backend.threat);
    return {};
}

function mockBackend(overrides: Partial<Backend> = {}): Backend {
    const backend: Backend = { description: 'Desc', threat: 'TM', aiRows: [], requests: [], ...overrides };
    fetchMock.mockResponse(async request => {
        const body = request.method === 'GET' ? null : await request.text();
        backend.requests.push({ url: request.url, method: request.method, body });
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
        expect(screen.getByRole('region', { name: 'Variant editor' })).toBeInTheDocument();
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
