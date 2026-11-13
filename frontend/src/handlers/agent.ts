export function agentErrorMessage(reason: unknown) {
    if (reason instanceof TypeError) return 'Connection lost. Check the backend and retry.';
    return reason instanceof Error ? reason.message : 'Something went wrong. Please try again.';
}

export async function agentRequest<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`/api/agent${path}`, {
        credentials: 'same-origin',
        ...options,
        headers: { 'Content-Type': 'application/json', ...options?.headers },
    });
    if (!response.headers.get('content-type')?.includes('application/json')) {
        throw new Error('Agent service unavailable. Check that agent chat is enabled on the backend, then retry.');
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Agent request failed (${response.status})`);
    return data as T;
}
