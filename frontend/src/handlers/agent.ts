import type { AgentStreamEvent } from '../types/agent';

export function agentErrorMessage(reason: unknown) {
    if (reason instanceof TypeError) return 'Connection lost. Check the backend and retry.';
    return reason instanceof Error ? reason.message : 'Something went wrong. Please try again.';
}

export async function agentRequest<T>(path: string, options?: RequestInit, onEvent?: (event: AgentStreamEvent) => void): Promise<T> {
    const response = await fetch(`/api/agent${path}`, {
        credentials: 'same-origin',
        ...options,
        headers: { 'Content-Type': 'application/json', ...(onEvent ? { Accept: 'application/x-ndjson' } : {}), ...options?.headers },
    });
    if (response.ok && onEvent && response.headers.get('content-type')?.includes('application/x-ndjson') && response.body) {
        const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
        let buffer = '';
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) throw new Error('Response interrupted. The agent may still finish this request; reload to check before retrying.');
                buffer += value;
                let boundary = buffer.indexOf('\n');
                while (boundary !== -1) {
                    const line = buffer.slice(0, boundary);
                    buffer = buffer.slice(boundary + 1);
                    if (line.trim()) {
                        const event = JSON.parse(line) as AgentStreamEvent;
                        if (event.type === 'error') throw new Error(event.error);
                        onEvent(event);
                        if (event.type === 'done') return event as T;
                    }
                    boundary = buffer.indexOf('\n');
                }
            }
        } finally {
            await reader.cancel();
            reader.releaseLock();
        }
    }
    if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('Agent service unavailable. Check that agent chat is enabled on the backend, then retry.');
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Agent request failed (${response.status})`);
    return data as T;
}
