import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowUp, faArrowUpRightFromSquare, faCircleNotch, faPlus, faXmark } from '@fortawesome/free-solid-svg-icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

type Message = { role: 'user' | 'assistant'; content: string };
type Usage = { cost: number | null; input_tokens: number | null; output_tokens: number | null };
type AgentState = { authenticated: boolean; login: string | null; configured: boolean; device_login: boolean; token_connected: boolean; messages: Message[]; model: string; usage: Usage };
type DeviceCode = { user_code: string; verification_uri: string; interval: number };
type DevicePoll = { status: 'pending' | 'connected'; interval?: number | null; login?: string | null };
type ModelChoice = { id: string; name: string };
const emptyUsage: Usage = { cost: null, input_tokens: null, output_tokens: null };

async function agentRequest<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`/api/agent${path}`, {
        credentials: 'same-origin',
        ...options,
        headers: { 'Content-Type': 'application/json', ...options?.headers },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Agent request failed (${response.status})`);
    return data as T;
}

function AgentChat({ onClose }: Readonly<{ onClose: () => void }>) {
    const [state, setState] = useState<AgentState | null>(null);
    const [error, setError] = useState('');
    const [draft, setDraft] = useState('');
    const [device, setDevice] = useState<DeviceCode | null>(null);
    const [allowWrites, setAllowWrites] = useState(false);
    const [busy, setBusy] = useState(false);
    const [modelBusy, setModelBusy] = useState(false);
    const [models, setModels] = useState<ModelChoice[]>([]);
    const [selectedModel, setSelectedModel] = useState('auto');
    const [neverAsk, setNeverAsk] = useState(false);
    const confirmation = useRef<HTMLDialogElement>(null);
    const bottom = useRef<HTMLDivElement>(null);

    useEffect(() => {
        let active = true;
        agentRequest<AgentState>('').then(result => {
            if (active) {
                setState(result);
                setSelectedModel(result.model);
            }
        }).catch(reason => {
            if (active) setError(String(reason));
        });
        return () => { active = false; };
    }, []);

    useEffect(() => {
        if (!state?.authenticated) return;
        let active = true;
        agentRequest<{ models: ModelChoice[] }>('/models').then(result => {
            if (active) setModels(result.models);
        }).catch(reason => {
            if (active) setError(String(reason));
        });
        return () => { active = false; };
    }, [state?.authenticated, state?.token_connected]);

    useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }); }, [state?.messages.length, busy]);

    useEffect(() => {
        if (!device) return;
        let active = true;
        let interval = device.interval;
        let timer = 0;
        const poll = async () => {
            try {
                const result = await agentRequest<DevicePoll>('/auth/poll', { method: 'POST' });
                if (!active) return;
                if (result.status === 'pending') {
                    interval = result.interval ?? interval;
                    timer = window.setTimeout(() => void poll(), interval * 1000);
                    return;
                }
                setState(previous => previous && { ...previous, authenticated: true, login: result.login ?? null, token_connected: true, messages: [], model: 'auto', usage: emptyUsage });
                setSelectedModel('auto');
                setDevice(null);
            } catch (reason) {
                if (!active) return;
                setError(String(reason));
                setDevice(null);
            }
        };
        timer = window.setTimeout(() => void poll(), interval * 1000);
        return () => { active = false; window.clearTimeout(timer); };
    }, [device]);

    async function signIn() {
        setBusy(true);
        setError('');
        try {
            setDevice(await agentRequest<DeviceCode>('/auth', { method: 'POST' }));
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function reset() {
        if (busy || modelBusy) return;
        setBusy(true);
        setError('');
        try {
            const result = await agentRequest<{ usage: Usage }>('/conversation', { method: 'DELETE' });
            setState(previous => previous && { ...previous, messages: [], usage: result.usage });
            setDraft('');
            setAllowWrites(false);
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    async function selectModel(model: string) {
        const previous = selectedModel;
        setSelectedModel(model);
        setModelBusy(true);
        setError('');
        try {
            await agentRequest('/model', { method: 'POST', body: JSON.stringify({ model }) });
            setState(current => current && { ...current, model });
        } catch (reason) {
            setSelectedModel(previous);
            setError(String(reason));
        } finally {
            setModelBusy(false);
        }
    }

    async function send(event?: FormEvent) {
        event?.preventDefault();
        const message = draft.trim();
        if (!message || busy) return;
        setBusy(true);
        setError('');
        setDraft('');
        const writes = allowWrites;
        setAllowWrites(false);
        try {
            const result = await agentRequest<{ reply: string; model: string; usage: Usage }>('/messages', {
                method: 'POST', body: JSON.stringify({ message, allow_writes: writes, model: selectedModel }),
            });
            setState(previous => previous && { ...previous, messages: [
                ...previous.messages, { role: 'user', content: message },
                { role: 'assistant', content: result.reply },
            ], model: result.model, usage: result.usage });
        } catch (reason) {
            setDraft(message);
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    }

    function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            void send();
        }
    }

    return <div className="flex h-full min-h-0 flex-col font-sans">
        <header className="flex h-12 shrink-0 items-center justify-end gap-3 border-b border-neutral-800 px-4">
            <button type="button" title="New conversation" aria-label="New conversation" onClick={() => {
                let skipConfirmation = neverAsk;
                try { skipConfirmation = localStorage.getItem('vulnscout.agent.skipDiscardConfirmation') === 'true'; } catch { skipConfirmation = neverAsk; }
                if (skipConfirmation) {
                    void reset();
                } else {
                    setNeverAsk(false);
                    confirmation.current?.showModal();
                }
            }} disabled={busy || modelBusy || !state} className="flex h-9 w-9 items-center justify-center rounded hover:bg-neutral-800 disabled:opacity-40"><FontAwesomeIcon icon={faPlus} /></button>
            <button type="button" title="Close agent" aria-label="Close agent" onClick={onClose} className="flex h-9 w-9 items-center justify-center rounded hover:bg-neutral-800"><FontAwesomeIcon icon={faXmark} /></button>
        </header>
        <dialog ref={confirmation} aria-labelledby="agent-discard-title" aria-describedby="agent-discard-description" className="w-[calc(100%-2rem)] max-w-sm rounded border border-neutral-700 bg-neutral-900 p-5 text-neutral-100 backdrop:bg-black/60" onCancel={() => setNeverAsk(false)} onKeyDown={event => {
            if (event.key === 'Escape') {
                event.preventDefault();
                event.stopPropagation();
                setNeverAsk(false);
                confirmation.current?.close();
            }
        }}>
            <h2 id="agent-discard-title" className="text-base font-semibold">New conversation?</h2>
            <p id="agent-discard-description" className="mt-3 text-sm">This conversation will be discarded forever. This cannot be undone.</p>
            <label className="mt-4 flex items-center gap-2 text-sm">
                <input type="checkbox" checked={neverAsk} onChange={event => setNeverAsk(event.target.checked)} className="accent-cyan-500" />
                Never ask again
            </label>
            <div className="mt-5 flex justify-end gap-3">
                <button type="button" autoFocus onClick={() => { setNeverAsk(false); confirmation.current?.close(); }} className="rounded border border-neutral-600 px-3 py-2 text-sm hover:bg-neutral-800">Cancel</button>
                <button type="button" onClick={() => {
                    try { localStorage.setItem('vulnscout.agent.skipDiscardConfirmation', String(neverAsk)); } catch { setNeverAsk(neverAsk); }
                    confirmation.current?.close();
                    void reset();
                }} className="rounded bg-cyan-700 px-3 py-2 text-sm font-semibold hover:bg-cyan-600">Confirm</button>
            </div>
        </dialog>

        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-neutral-800 bg-neutral-900 px-4 py-2 text-xs">
            <label className="flex min-w-0 items-center gap-2 text-neutral-300">Model
                <select aria-label="Agent model" value={selectedModel} onChange={event => void selectModel(event.target.value)} disabled={busy || modelBusy || !models.length} className="max-w-[170px] border border-neutral-600 bg-neutral-950 px-2 py-1 text-neutral-100 disabled:opacity-50">
                    {!models.length && <option value={selectedModel}>Loading...</option>}
                    {models.map(model => <option key={model.id} value={model.id}>{model.name}</option>)}
                </select>
            </label>
            <span title="Sum of cost values reported by the Copilot SDK for this conversation; no currency inferred" className="tabular-nums text-neutral-300">{state?.usage?.cost == null ? 'Cost not reported' : `SDK cost ${state.usage.cost.toFixed(4)}`}</span>
            {state?.usage?.input_tokens != null && <span className="text-neutral-400">{state.usage.input_tokens.toLocaleString()} in · {(state.usage.output_tokens ?? 0).toLocaleString()} out tokens</span>}
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-4 py-5" role="log" aria-label="Agent conversation" aria-live="polite">
            {!state && !error && <p role="status" className="text-sm text-neutral-400">Connecting to agent...</p>}
            {state && !state.configured && <div className="border-l-2 border-amber-400 bg-neutral-900 p-3 text-sm text-neutral-200">
                Set <span className="font-mono">VULNSCOUT_MCP_SERVER_PATH</span> on the backend to the full path of the vulnscout-mcp <span className="font-mono">run_server.py</span>, then reopen this panel.
            </div>}
            {state && !state.authenticated && <div className="space-y-3 border-l-2 border-cyan-500 bg-neutral-900 p-3 text-sm">
                {!device ? <>
                    <p>Connect a GitHub account with Copilot access.</p>
                    <button type="button" onClick={() => void signIn()} disabled={busy} className="block bg-cyan-700 px-3 py-2 font-semibold hover:bg-cyan-600 disabled:opacity-40">Sign in with GitHub</button>
                </> : <>
                    <p>Enter this code on GitHub:</p>
                    <div className="flex items-center gap-2">
                        <code className="bg-neutral-950 px-3 py-2 font-mono text-lg tracking-widest text-cyan-100">{device.user_code}</code>
                        <button type="button" onClick={() => void navigator.clipboard.writeText(device.user_code)} className="border border-neutral-600 px-2 py-2 text-xs hover:bg-neutral-800">Copy</button>
                    </div>
                    <a className="inline-flex items-center gap-2 text-cyan-300 hover:underline" href={device.verification_uri} target="_blank" rel="noopener noreferrer">Open {device.verification_uri.replace('https://', '')} <FontAwesomeIcon icon={faArrowUpRightFromSquare} /></a>
                    <p role="status" className="flex items-center gap-2 text-xs text-neutral-400"><FontAwesomeIcon icon={faCircleNotch} spin /> Waiting for approval on GitHub...
                        <button type="button" onClick={() => setDevice(null)} className="underline hover:text-white">Cancel</button></p>
                </>}
            </div>}
            {state?.authenticated && state.token_connected && <button type="button" disabled={busy} onClick={async () => {
                setBusy(true);
                try {
                    await agentRequest('/auth', { method: 'DELETE' });
                    setState(await agentRequest<AgentState>(''));
                } catch (reason) { setError(String(reason)); }
                finally { setBusy(false); }
            }} className="text-xs text-neutral-400 underline hover:text-white">Sign out</button>}
            {state?.authenticated && state.messages.length === 0 && <div className="space-y-3 pt-6 text-sm text-neutral-400">
                <p className="text-neutral-100">What would you like to investigate?</p>
                <p>Ask about a CVE, compare assessments, or review variant context.</p>
            </div>}
            {state?.messages.map((message, index) => <div key={index} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[92%] break-words px-3 py-2 text-sm leading-relaxed ${message.role === 'user' ? 'whitespace-pre-wrap rounded bg-cyan-800 text-white' : 'border-l-2 border-cyan-600 bg-neutral-900 text-neutral-100'}`}>
                    {message.role === 'assistant' ? <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
                        p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-cyan-300 underline">{children}</a>,
                        code: ({ children }) => <code className="rounded bg-neutral-800 px-1 font-mono text-xs text-cyan-100">{children}</code>,
                        pre: ({ children }) => <pre className="my-2 overflow-x-auto bg-neutral-950 p-2">{children}</pre>,
                        table: ({ children }) => <div className="my-2 max-w-full overflow-x-auto"><table className="w-full min-w-[420px] border-collapse text-left text-xs">{children}</table></div>,
                        th: ({ children }) => <th className="border border-neutral-600 bg-neutral-800 p-2 font-semibold">{children}</th>,
                        td: ({ children }) => <td className="border border-neutral-700 p-2 align-top">{children}</td>,
                    }}>{message.content}</ReactMarkdown> : message.content}
                </div>
            </div>)}
            {busy && <div role="status" className="flex items-center gap-2 text-xs text-cyan-300"><FontAwesomeIcon icon={faCircleNotch} spin /> Working...</div>}
            {error && <p role="alert" className="border-l-2 border-red-400 bg-red-950/50 p-3 text-sm text-red-100">{error}</p>}
            <div ref={bottom} />
        </div>

        <form onSubmit={event => void send(event)} className="shrink-0 space-y-3 border-t border-neutral-800 bg-neutral-900 p-4">
            <label htmlFor="agent-prompt" className="sr-only">Message the agent</label>
            <div className="flex items-end gap-2 border border-neutral-600 bg-neutral-950 p-2 focus-within:border-cyan-500">
                <textarea id="agent-prompt" rows={2} maxLength={8000} value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={onKeyDown} disabled={!state?.authenticated || !state.configured || busy || modelBusy || !models.length} placeholder="Ask the agent..." className="min-w-0 flex-1 resize-none bg-transparent text-sm text-white outline-none placeholder:text-neutral-500 disabled:opacity-40" />
                <button type="submit" title="Send message" aria-label="Send message" disabled={!draft.trim() || busy || modelBusy || !state?.authenticated || !state.configured || !models.length} className="flex h-9 w-9 shrink-0 items-center justify-center rounded bg-cyan-700 hover:bg-cyan-600 disabled:bg-neutral-700 disabled:text-neutral-500"><FontAwesomeIcon icon={faArrowUp} /></button>
            </div>
            <label className="flex cursor-pointer items-start gap-2 text-xs text-neutral-300">
                <input type="checkbox" checked={allowWrites} onChange={event => setAllowWrites(event.target.checked)} disabled={busy} className="mt-0.5 accent-cyan-500" />
                Allow assessment and context changes for the next message
            </label>
        </form>
    </div>;
}

export default AgentChat;
