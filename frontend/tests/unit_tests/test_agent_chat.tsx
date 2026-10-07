import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { ReadableStream, TextDecoderStream } from 'node:stream/web';
import { TextEncoder } from 'node:util';
// @ts-expect-error TS6133
import React from 'react';

import AgentChat from '../../src/components/AgentChat';
import { AGENT_WRITE_EVENT } from '../../src/types/agent';
import type { AgentContext } from '../../src/types/agent';

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

beforeEach(() => Object.assign(global, { TextDecoderStream }));
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
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
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
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect provider' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('auto'));
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
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
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
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
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
    expect(await screen.findByRole('heading', { name: 'Report' })).toBeInTheDocument();
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