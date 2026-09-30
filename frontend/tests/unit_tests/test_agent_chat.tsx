import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { ReadableStream, TextDecoderStream } from 'node:stream/web';
import { TextEncoder } from 'node:util';
// @ts-expect-error TS6133
import React from 'react';

import AgentChat from '../../src/components/AgentChat';
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
    fireEvent.click(screen.getByRole('button', { name: /sign in with github/i }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('ABCD-EFGH')).toBeInTheDocument();
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
});

test('streams split NDJSON events and only permits writes for the chosen turn', async () => {
    const requests: { message: string; allow_writes: boolean }[] = [];
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
    fireEvent.click(screen.getByRole('checkbox', { name: /allow changes/i }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Assess this' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await screen.findByText('First answer');
    expect(requests[0]).toMatchObject({ message: 'Assess this', allow_writes: true });
    expect(screen.getByText('get vulnerability')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /allow changes/i })).not.toBeChecked();

    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'One more' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].allow_writes).toBe(false);
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

test('interrupted response restores the draft and removes the write grant', async () => {
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/messages')) return streamResponse(['{"type":"delta","message_id":"one","text":"Partial"}\n']);
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    fireEvent.click(screen.getByRole('checkbox', { name: /allow changes/i }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Continue' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Response interrupted');
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveValue('Continue');
    expect(screen.getByRole('checkbox', { name: /allow changes/i })).not.toBeChecked();
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
    expect(screen.getByRole('button', { name: /sign in with github/i })).toBeInTheDocument();
});

test('keyboard send renders structured Markdown, usage, and response copy', async () => {
    const reply = '# Report\n\n## Findings\n\n### Details\n\n- First\n\n1. Second\n\n> Evidence\n\n[Source](https://example.com) with `code`.\n\n```text\nlog\n```\n\n| Name | Result |\n| --- | --- |\n| Example | Passed |';
    const copied: string[] = [];
    const requests: { message: string; allow_writes: boolean }[] = [];
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
    expect(requests).toMatchObject([{ message: 'Review evidence', allow_writes: false }]);
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
    fireEvent.click(await screen.findByRole('button', { name: /sign in with github/i }));
    await screen.findByText('ABCD-EFGH');
    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));
    await waitFor(() => expect(copied).toEqual(['ABCD-EFGH']));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
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