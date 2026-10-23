import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { ReadableStream, TextDecoderStream } from 'node:stream/web';
import { TextEncoder } from 'node:util';
// @ts-expect-error TS6133
import React from 'react';

import AgentChat from '../../src/components/AgentChat';
import { buildAssessmentReviewAction } from '../../src/helpers/aiAssessmentReview';
import { AGENT_WRITE_EVENT } from '../../src/types/agent';
import type { AgentContext } from '../../src/types/agent';
import { enqueueAgentMessages, getAgentQueue, resetAgentQueue } from '../../src/handlers/agentQueue';

const usage = { cost: null, input_tokens: null, output_tokens: null };
const signedIn = { authenticated: true, login: 'tester', configured: true, device_login: true,
    token_connected: true, messages: [], model: 'auto', usage };
const signedOut = { ...signedIn, authenticated: false, token_connected: false, login: null };
const context: AgentContext = { page: 'vulnerabilities', projectId: 'project', variantId: 'variant',
    view: { visibleVulnerabilityIds: ['CVE-2024-1234'] } };
const models = { models: [{ id: 'auto', name: 'Auto' }] };

function jsonResponse(data: unknown): Response {
    return { ok: true, headers: { get: () => 'application/json' }, json: async () => data } as unknown as Response;
}

function streamResponse(chunks: string[]): Response {
    const encoder = new TextEncoder();
    return { ok: true, headers: { get: () => 'application/x-ndjson' },
        body: new ReadableStream<Uint8Array>({ start(controller) {
            chunks.forEach(chunk => controller.enqueue(encoder.encode(chunk)));
            controller.close();
        } }) } as unknown as Response;
}

beforeEach(() => {
    resetAgentQueue();
    Object.assign(global, { TextDecoderStream });
});
afterEach(() => jest.useRealTimers());

test('device flow polls at the interval returned by the server', async () => {
    jest.useFakeTimers();
    const requests: string[] = [];
    global.fetch = async input => {
        const path = String(input);
        requests.push(path);
        if (path.endsWith('/auth/poll')) return jsonResponse(requests.filter(item => item.endsWith('/auth/poll')).length === 1
            ? { status: 'pending', interval: 2 } : { status: 'connected', login: 'tester' });
        if (path.endsWith('/auth')) return jsonResponse({ user_code: 'ABCD-EFGH', verification_uri: 'https://github.com/login/device', interval: 1 });
        if (path.endsWith('/models')) return jsonResponse(models);
        return jsonResponse(signedOut);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Step 1 of 3')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(screen.getByRole('button', { name: /sign in with github/i }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Step 3 of 3')).toBeInTheDocument();
    expect(screen.getByText('ABCD-EFGH')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start using' })).toBeDisabled();
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(2);
    expect(screen.getByText('Connection verified')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Start using' }));
    expect(screen.getByRole('button', { name: 'Configure model provider' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
});

test('connects a local provider when already signed in and restores the GitHub account on disconnect', async () => {
    const connections: { provider: string; base_url: string; api_key: string }[] = [];
    let connected = false;
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/provider') && options?.method === 'POST') {
            connections.push(JSON.parse(String(options.body)));
            connected = true;
            return jsonResponse({ provider: 'local', model: '' });
        }
        if (path.endsWith('/provider') && options?.method === 'DELETE') {
            connected = false;
            return jsonResponse({ provider: null, model: 'auto' });
        }
        if (path.endsWith('/models')) return jsonResponse(connected ? {
            models: [{ id: 'Qwen/Qwen3-Coder', name: 'Qwen/Qwen3-Coder' }],
        } : models);
        return jsonResponse(connected ? { ...signedIn, provider: 'local', login: null,
            token_connected: false, model: '' } : signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('radio', { name: /local model/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.queryByRole('textbox', { name: 'Provider model' })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Use custom endpoint URL/ }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Provider API base URL' }), { target: { value: 'http://localhost:11434/v1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    expect(await screen.findByText('Connection verified')).toBeInTheDocument();
    expect(connections).toEqual([{ provider: 'local', base_url: 'http://localhost:11434/v1', api_key: '' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Start using' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue(''));
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeDisabled();
    fireEvent.change(screen.getByRole('combobox', { name: 'Agent model' }), { target: { value: 'Qwen/Qwen3-Coder' } });
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('Qwen/Qwen3-Coder'));
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    expect(screen.queryByRole('button', { name: 'Disconnect provider' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect provider' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('auto'));
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
});

test('connector wizard shows only the selected authentication fields', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedOut);

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Select a connector');
    expect(screen.getByRole('radio', { name: /github copilot/i })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Back' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('button', { name: 'Sign in with GitHub' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Provider API key')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /microsoft foundry/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.queryByRole('textbox', { name: 'Provider model' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Provider API key')).toBeRequired();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Use custom endpoint URL/ }));
    expect(screen.getByRole('textbox', { name: 'Provider API base URL' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /anthropic/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByLabelText('Provider API key')).toBeRequired();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /local model/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByLabelText('Provider API key')).not.toBeRequired();
    expect(screen.getByRole('button', { name: /Use custom endpoint URL \(required\)/ })).toBeInTheDocument();
});

test('keeps model selection in the composer and exposes sign-out only through the plug', async () => {
    const requests: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/auth') && options?.method === 'DELETE') {
            requests.push(path);
            return jsonResponse({ cleanup_error: null });
        }
        return jsonResponse(signedIn);
    };
    const { container } = render(<AgentChat context={context} onClose={() => undefined} />);
    const model = await screen.findByRole('combobox', { name: 'Agent model' });
    expect(container.querySelector('header')).not.toContainElement(model);
    expect(screen.getByRole('textbox', { name: 'Message the agent' }).closest('form')).toContainElement(model);
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.queryByRole('combobox', { name: 'Agent model' })).not.toBeInTheDocument();
    expect(screen.getByText('GitHub Copilot · tester')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByText('Select a connector');
    expect(requests).toEqual(['/api/agent/auth']);
    expect(screen.queryByRole('button', { name: 'Configure model provider' })).not.toBeInTheDocument();
});

test('streams split NDJSON events without a write permission checkbox', async () => {
    const requests: { message: string; allow_writes?: boolean }[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            requests.push(JSON.parse(String(options?.body)));
            return streamResponse([
                '{"type":"tool_start","id":"call","name":"get_vulnerability"}\n{"type":"del',
                'ta","message_id":"msg","text":"First "}\n{"type":"delta","message_id":"msg","text":"answer"}\n',
                '{"type":"tool_end","id":"call","success":true}\n',
                '{"type":"done","reply":"First answer","model":"auto","usage":{"cost":0.5,"input_tokens":10,"output_tokens":2}}\n',
            ]);
        }
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Assess this' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await screen.findByText('First answer');
    expect(requests[0]).toMatchObject({ message: 'Assess this' });
    expect(screen.getByText('get vulnerability')).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /allow changes/i })).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'One more' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].allow_writes).toBeUndefined();
});

test('sends every selected variant so the backend enforces the displayed scope', async () => {
    const variantIds = Array.from({ length: 60 }, (_, index) => `variant-${index}`);
    const requests: { context: AgentContext }[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            requests.push(JSON.parse(String(options?.body)));
            return streamResponse([`{"type":"done","reply":"Scoped","model":"auto","usage":${JSON.stringify(usage)}}\n`]);
        }
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={{ page: 'metrics', projectId: 'project', variantIds }} />);
    const input = await screen.findByRole('textbox', { name: 'Message the agent' });
    await waitFor(() => expect(input).toBeEnabled());
    fireEvent.change(input, { target: { value: 'Summarize' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await screen.findByText('Scoped');
    expect(requests[0].context.variantIds).toEqual(variantIds);
    expect(requests[0].context).not.toHaveProperty('variantCount');
});

test('notifies views only after a successful write tool completes', async () => {
    const writes: string[] = [];
    const onWrite = (event: Event) => writes.push((event as CustomEvent<{ tool: string }>).detail.tool);
    window.addEventListener(AGENT_WRITE_EVENT, onWrite);
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) return streamResponse([
            '{"type":"tool_start","id":"read","name":"get_assessment"}\n',
            '{"type":"tool_end","id":"read","success":true,"write":false}\n',
            '{"type":"tool_start","id":"failed","name":"update_project_context"}\n',
            '{"type":"tool_end","id":"failed","success":false,"write":true}\n',
            '{"type":"tool_start","id":"saved","name":"write_assessment"}\n',
            '{"type":"tool_end","id":"saved","success":true,"write":true}\n',
            '{"type":"done","reply":"Saved","model":"auto","usage":' + JSON.stringify(usage) + '}\n',
        ]);
        return jsonResponse(signedIn);
    };

    try {
        render(<AgentChat onClose={() => undefined} context={context} />);
        fireEvent.click(await screen.findByRole('button', { name: 'Summarize vulnerabilities' }));
        await screen.findByText('Saved');
        expect(writes).toEqual(['write_assessment']);
    } finally {
        window.removeEventListener(AGENT_WRITE_EVENT, onWrite);
    }
});

test('reset discards messages but retains the connection', async () => {
    const requests: string[] = [];
    global.fetch = async input => {
        const path = String(input);
        requests.push(path);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/conversation')) return jsonResponse({ messages: [], usage });
        return jsonResponse({ ...signedIn, messages: [{ role: 'user', content: 'Previous question' }] });
    };
    window.localStorage.setItem('vulnscout.agent.skipDiscardConfirmation', 'true');

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Previous question');
    fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
    await waitFor(() => expect(screen.queryByText('Previous question')).not.toBeInTheDocument());
    expect(requests.some(path => path.endsWith('/conversation'))).toBe(true);
    expect(screen.getByRole('button', { name: 'Configure model provider' })).toBeInTheDocument();
});

test('interrupted response restores the draft', async () => {
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) return streamResponse(['{"type":"delta","message_id":"one","text":"Partial"}\n']);
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Continue' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Response interrupted');
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveValue('Continue');
});

test('large vulnerability view disables the unavailable summary action', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedIn);
    render(<AgentChat onClose={() => undefined} context={{ ...context, view: {
        visibleVulnerabilityIds: Array.from({ length: 101 }, (_, index) => `CVE-${index}`),
    } }} />);
    expect(await screen.findByRole('button', { name: 'Summarize vulnerabilities' })).toBeDisabled();
    expect(screen.getByText(/Filter to 100 or fewer vulnerabilities/)).toBeInTheDocument();
});

test('sign-out shows a remote cleanup error after discarding local identity', async () => {
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/auth') && options?.method === 'DELETE') return jsonResponse({
            authenticated: false, cleanup_error: 'Could not delete the stored conversation on the Copilot server.',
        });
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not delete the stored conversation');
    expect(screen.getByText('Select a connector')).toBeInTheDocument();
});

test('keyboard send renders structured Markdown, usage, and response copy', async () => {
    const reply = '# Report\n\n## Findings\n\n### Details\n\n- First\n\n1. Second\n\n> Evidence\n\n[Source](https://example.com) with `code`.\n\n```text\nlog\n```\n\n| Name | Result |\n| --- | --- |\n| Example | Passed |';
    const copied: string[] = [];
    const requests: { message: string; allow_writes?: boolean }[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text: string) => { copied.push(text); } } });
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            requests.push(JSON.parse(String(options?.body)));
            return streamResponse([
                '{"type":"status","text":"Reading findings"}\n',
                '{"type":"tool_start","id":"call","name":"list_assessments_by_vuln"}\n',
                '{"type":"tool_end","id":"call","success":false}\n',
                `${JSON.stringify({ type: 'done', reply, model: 'auto', usage: { cost: 0.5, input_tokens: 10, output_tokens: 2 } })}\n`,
            ]);
        }
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    const composer = screen.getByRole('textbox', { name: 'Message the agent' });
    fireEvent.change(composer, { target: { value: 'Review evidence' } });
    fireEvent.keyDown(composer, { key: 'Enter', code: 'Enter' });
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Report' })).toBeInTheDocument());
    expect(requests).toMatchObject([{ message: 'Review evidence' }]);
    expect(requests[0].allow_writes).toBeUndefined();
    expect(screen.getByRole('heading', { name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Details' })).toBeInTheDocument();
    expect(screen.getByRole('blockquote')).toHaveTextContent('Evidence');
    expect(screen.getByRole('link', { name: 'Source' })).toHaveAttribute('href', 'https://example.com');
    expect(screen.getByRole('table')).toHaveTextContent('Passed');
    expect(screen.getByText('list assessments by vuln')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Conversation usage'));
    expect(screen.getByText('SDK cost 0.5000')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy response' }));
    await waitFor(() => expect(copied).toEqual([reply]));
});

test('model rejection restores the choice and retry reloads the connection', async () => {
    const requests: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        requests.push(path);
        if (path.endsWith('/models')) return jsonResponse({ models: [...models.models, { id: 'alternate', name: 'Alternate' }] });
        if (path.endsWith('/model') && options?.method === 'POST') return {
            ...jsonResponse({ error: 'Model unavailable' }), ok: false, status: 400,
        };
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    const select = await screen.findByRole('combobox', { name: 'Agent model' });
    await screen.findByRole('option', { name: 'Alternate' });
    fireEvent.change(select, { target: { value: 'alternate' } });
    expect(await screen.findByRole('alert')).toHaveTextContent('Model unavailable');
    expect(select).toHaveValue('auto');
    fireEvent.click(screen.getByRole('button', { name: 'Retry connection' }));
    await waitFor(() => expect(requests.filter(path => path === '/api/agent')).toHaveLength(2));
});

test('reset confirmation can be cancelled and then saves the preference', async () => {
    const showModal = HTMLDialogElement.prototype.showModal;
    const close = HTMLDialogElement.prototype.close;
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    let closed = false;
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/conversation')) return jsonResponse({ usage });
        return jsonResponse({ ...signedIn, messages: [{ role: 'user', content: 'Earlier question' }] });
    };

    try {
        render(<AgentChat onClose={() => { closed = true; }} context={context} />);
        await screen.findByText('Earlier question');
        fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
        const dialog = screen.getByRole('dialog');
        expect(dialog).toHaveAttribute('open');
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(dialog).not.toHaveAttribute('open');
        fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
        fireEvent.click(screen.getByRole('checkbox', { name: 'Never ask again' }));
        fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
        await waitFor(() => expect(screen.queryByText('Earlier question')).not.toBeInTheDocument());
        expect(window.localStorage.getItem('vulnscout.agent.skipDiscardConfirmation')).toBe('true');
        fireEvent.click(screen.getByRole('button', { name: 'Close agent' }));
        expect(closed).toBe(true);
    } finally {
        HTMLDialogElement.prototype.showModal = showModal;
        HTMLDialogElement.prototype.close = close;
    }
});

test('device authorization can be cancelled and the code copied', async () => {
    const copied: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text: string) => { copied.push(text); } } });
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/auth')) return jsonResponse({ user_code: 'ABCD-EFGH', verification_uri: 'https://github.com/login/device', interval: 300 });
        return jsonResponse(signedOut);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Select a connector');
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(await screen.findByRole('button', { name: /sign in with github/i }));
    await screen.findByText('ABCD-EFGH');
    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));
    await waitFor(() => expect(copied).toEqual(['ABCD-EFGH']));
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByRole('button', { name: /sign in with github/i })).toBeInTheDocument();
});

test('scrolling away from the latest message exposes a return control', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedIn);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    const log = screen.getByRole('log', { name: 'Agent conversation' });
    Object.defineProperties(log, {
        scrollHeight: { configurable: true, value: 300 },
        clientHeight: { configurable: true, value: 100 },
        scrollTop: { configurable: true, writable: true, value: 0 },
    });
    fireEvent.scroll(log);
    fireEvent.click(screen.getByRole('button', { name: 'Jump to latest message' }));
    expect(log.scrollTop).toBe(300);
});
test('sends queued actions when connected and accepts subsequent actions through the shared store', async () => {
    const sent: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            const { message } = JSON.parse(String(options?.body));
            sent.push(message);
            return streamResponse([`{"type":"done","reply":"Reply ${sent.length}","model":"auto","usage":${JSON.stringify(usage)}}\n`]);
        }
        return jsonResponse(signedIn);
    };

    const first = { id: 'q1', text: 'Assess the selected targets', key: 'assess:a', kind: 'assess' as const, title: '1 target' };
    enqueueAgentMessages([first], context);
    enqueueAgentMessages([{ ...first }], context);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Reply 1');
    await waitFor(() => expect(getAgentQueue()).toEqual([]));
    expect(sent).toEqual(['Assess the selected targets']);

    act(() => enqueueAgentMessages([{ id: 'q2', text: 'Review assessment', key: 'assess:x', kind: 'assess', title: 'assessment x' }], context));
    await screen.findByText('Reply 2');
    expect(sent).toEqual(['Assess the selected targets', 'Review assessment']);
});

test('all chat windows see the same queue and work continues after the originating window unmounts', async () => {
    const sent: string[] = [];
    let finish: (response: Response) => void = () => {};
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            sent.push(JSON.parse(String(options?.body)).message);
            if (sent.length === 1) return new Promise(resolve => { finish = resolve; });
            return jsonResponse({ reply: 'Second completed', model: 'auto', usage });
        }
        return jsonResponse(signedIn);
    };
    const source = render(<AgentChat context={context} threadId="bulk" onClose={() => undefined} />);
    const globalChat = render(<AgentChat context={{ page: 'metrics' }} onClose={() => undefined} />);
    const sourceView = within(source.container);
    const globalView = within(globalChat.container);
    await waitFor(() => expect(sourceView.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    await waitFor(() => expect(globalView.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    fireEvent.change(sourceView.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'First request' } });
    fireEvent.click(sourceView.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(sent).toEqual(['First request']));
    fireEvent.change(globalView.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Second request' } });
    fireEvent.click(globalView.getByRole('button', { name: 'Send message' }));
    fireEvent.click(sourceView.getByRole('button', { name: 'AI queue (2)' }));
    fireEvent.click(globalView.getByRole('button', { name: 'AI queue (2)' }));
    for (const view of [sourceView, globalView]) {
        const queue = within(view.getByRole('region', { name: 'Queued AI actions' }));
        expect(queue.getAllByRole('listitem')).toHaveLength(2);
        expect(queue.getByText('Bulk assessment chat · running')).toBeInTheDocument();
        expect(queue.getByText('Global chat · queued')).toBeInTheDocument();
    }
    source.unmount();
    await act(async () => finish(jsonResponse({ reply: 'First completed', model: 'auto', usage })));
    await globalView.findByText('Second completed');
    expect(sent).toEqual(['First request', 'Second request']);
    expect(getAgentQueue()).toEqual([]);
});

test.each(['missing', 'partial', 'unchanged', 'stale', 'read failure', 'changed targets'])(
    'pauses a review after an HTTP success with %s saved reviews, then verifies all targets on retry',
    async failure => {
        let attempts = 0;
        let finishedTurn = false;
        const targets = [{ variant_id: 'variant', package: 'pkg@1' }, { variant_id: 'other', package: 'pkg@2' }];
        const assessment = { id: 'assessment', vuln_id: 'CVE-2024-1234', origin: 'custom', status: 'affected',
            timestamp: '2026-10-21T10:00:00Z', targets, packages: ['pkg@1', 'pkg@2'] };
        const reviews = (timestamp: string) => targets.map((target, index) => ({
            ...target, id: `review-${index}`, assessment_id: assessment.id, timestamp, is_stale: false,
        }));
        global.fetch = async input => {
            const path = String(input);
            if (path.endsWith('/models')) return jsonResponse(models);
            if (path.endsWith('/messages')) {
                attempts++;
                finishedTurn = true;
                return jsonResponse({ reply: 'Finished', model: 'auto', usage });
            }
            if (path.endsWith('/assessment/reviews')) {
                if (finishedTurn && attempts === 1 && failure === 'read failure') throw new TypeError('unavailable');
                if (!finishedTurn || failure === 'unchanged' && attempts === 1) {
                    return jsonResponse({ reviews: failure === 'unchanged' ? reviews('2026-10-21T11:00:00Z') : [] });
                }
                const saved = reviews(`2026-10-21T12:00:0${attempts}Z`);
                return jsonResponse({ reviews: attempts !== 1 ? saved
                    : failure === 'missing' ? [] : failure === 'partial' ? saved.slice(0, 1)
                        : failure === 'stale' ? saved.map(item => ({ ...item, is_stale: true })) : saved });
            }
            if (path.endsWith('/assessments/assessment')) return jsonResponse({
                ...assessment, targets: finishedTurn && attempts === 1 && failure === 'changed targets' ? targets.slice(0, 1) : targets,
            });
            return jsonResponse(signedIn);
        };
        const first = { ...buildAssessmentReviewAction(assessment), id: 'first' };
        enqueueAgentMessages([first, {
            id: 'second', key: 'assess:next', kind: 'assess', text: 'Next assessment', title: 'next',
        }], context);
        render(<AgentChat context={context} onClose={() => undefined} />);
        await waitFor(() => expect(getAgentQueue()[0].status).toBe('failed'));
        expect(attempts).toBe(1);
        expect(screen.getByText(/Queue paused/)).toBeInTheDocument();
        expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveValue(first.text);
        expect(screen.getByRole('alert')).toBeInTheDocument();
        finishedTurn = false;
        fireEvent.click(screen.getByRole('button', { name: 'Retry failed action' }));
        await waitFor(() => expect(getAgentQueue()).toEqual([]));
        expect(attempts).toBe(3);
        expect(screen.queryByText(/Queue paused/)).not.toBeInTheDocument();
    },
);

test('does not send a queued message while signed out', async () => {
    const sent: string[] = [];
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/messages')) sent.push(path);
        return jsonResponse(signedOut);
    };

    enqueueAgentMessages([{ id: 'q1', text: 'Assess', key: 'assess:a', kind: 'assess', title: '1 target' }], context);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Step 1 of 3');
    expect(sent).toEqual([]);
    expect(getAgentQueue()[0].status).toBe('queued');
});

test.each(['provider', 'stream', 'interrupted stream'])('pauses a multi-action queue on %s failure and retries the same item', async failure => {
    const sent: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            const { message } = JSON.parse(String(options?.body));
            sent.push(message);
            if (sent.length <= 2) {
                if (failure === 'stream') return streamResponse(['{"type":"error","error":"Provider unavailable"}\n']);
                if (failure === 'interrupted stream') return streamResponse(['{"type":"delta","message_id":"m1","text":"Partial"}\n']);
                return { ...jsonResponse({ error: 'Provider unavailable' }), ok: false } as Response;
            }
            return streamResponse([`{"type":"done","reply":"Reply ${sent.length}","model":"auto","usage":${JSON.stringify(usage)}}\n`]);
        }
        return jsonResponse(signedIn);
    };
    enqueueAgentMessages([
        { id: 'q1', text: 'Assess CVE-1', key: 'assess:1', kind: 'assess', title: 'CVE-1' },
        { id: 'q2', text: 'Assess CVE-2', key: 'assess:2', kind: 'assess', title: 'CVE-2' },
    ], context);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Queue paused. Retry or remove the failed action to continue.');
    expect(getAgentQueue()[0].status).toBe('failed');
    expect(sent).toEqual(['Assess CVE-1']);
    expect(screen.getByLabelText('Message the agent')).toHaveValue('Assess CVE-1');
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Assess displayed' })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(failure === 'interrupted stream' ? 'Response interrupted' : 'Provider unavailable');
    expect(screen.getByRole('region', { name: 'Queued AI actions' })).toHaveTextContent('AI queue · 1 queued');
    await act(async () => { await Promise.resolve(); });
    expect(sent).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Retry failed action' }));
    await waitFor(() => expect(sent).toHaveLength(2));
    await waitFor(() => expect(getAgentQueue()[0].status).toBe('failed'));
    expect(sent).toEqual(['Assess CVE-1', 'Assess CVE-1']);
    expect(screen.getByLabelText('Message the agent')).toHaveValue('Assess CVE-1');
    fireEvent.click(screen.getByRole('button', { name: 'Retry failed action' }));
    await screen.findByText('Reply 4');
    expect(sent).toEqual(['Assess CVE-1', 'Assess CVE-1', 'Assess CVE-1', 'Assess CVE-2']);
    expect(getAgentQueue()).toEqual([]);
    expect(screen.getByText('No AI requests queued.')).toBeInTheDocument();
});

test.each(['remove', 'clear'])('%s releases a failed action without retrying it', async action => {
    const sent: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) {
            sent.push(JSON.parse(String(options?.body)).message);
            if (sent.length === 1) throw new TypeError('Failed to fetch');
            return jsonResponse({ reply: 'Second done', model: 'auto', usage });
        }
        return jsonResponse(signedIn);
    };
    enqueueAgentMessages([
        { id: 'q1', text: 'Assess CVE-1', key: 'assess:1', kind: 'assess', title: 'CVE-1' },
        { id: 'q2', text: 'Assess CVE-2', key: 'assess:2', kind: 'assess', title: 'CVE-2' },
    ], context);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Queue paused. Retry or remove the failed action to continue.');
    expect(sent).toEqual(['Assess CVE-1']);
    fireEvent.click(screen.getByRole('button', { name: action === 'remove' ? 'Remove assess CVE-1 from queue' : 'Clear all' }));
    if (action === 'remove') await screen.findByText('Second done');
    else expect(screen.getByText('No AI requests queued.')).toBeInTheDocument();
    expect(sent).toEqual(action === 'remove' ? ['Assess CVE-1', 'Assess CVE-2'] : ['Assess CVE-1']);
    expect(screen.getByLabelText('Message the agent')).toHaveValue('');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('lists queued actions with remove and clear controls', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedOut);
    enqueueAgentMessages([
        { id: 'q1', text: 'Assess', key: 'assess:a', kind: 'assess', title: '2 targets', detail: 'default · pkg@1.0.0' },
        { id: 'q2', text: 'Review', key: 'review:x', kind: 'review', title: 'assessment 1a2b3c4d' },
    ], context);
    render(<AgentChat onClose={() => undefined} context={context} />);
    fireEvent.click(screen.getByRole('button', { name: 'AI queue (2)' }));

    const queue = await screen.findByRole('region', { name: 'Queued AI actions' });
    expect(queue).toHaveTextContent('AI queue · 2 queued');
    const items = within(queue).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('1Assess 2 targets');
    expect(items[0]).toHaveTextContent('default · pkg@1.0.0');
    expect(items[1]).toHaveTextContent('2Review assessment 1a2b3c4d');

    fireEvent.click(within(queue).getByRole('button', { name: 'Remove review assessment 1a2b3c4d from queue' }));
    expect(getAgentQueue().map(item => item.id)).toEqual(['q1']);
    fireEvent.click(within(queue).getByRole('button', { name: 'Clear all' }));
    expect(getAgentQueue()).toEqual([]);
});
