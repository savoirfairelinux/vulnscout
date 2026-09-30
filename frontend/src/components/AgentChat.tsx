import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowUp, faArrowUpRightFromSquare, faCircleNotch, faRobot, faTrashCan, faXmark } from '@fortawesome/free-solid-svg-icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

type Message = { role: 'user' | 'assistant'; content: string };
type AgentState = { authenticated: boolean; login: string | null; configured: boolean; device_login: boolean; token_connected: boolean; messages: Message[] };
type DeviceCode = { user_code: string; verification_uri: string; interval: number };
type DevicePoll = { status: 'pending' | 'connected'; interval?: number | null; login?: string | null };

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
    const bottom = useRef<HTMLDivElement>(null);

    useEffect(() => {
        let active = true;
        agentRequest<AgentState>('').then(result => {
            if (active) setState(result);
        }).catch(reason => {
            if (active) setError(String(reason));
        });
        return () => { active = false; };
    }, []);

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
                setState(previous => previous && { ...previous, authenticated: true, login: result.login ?? null, token_connected: true, messages: [] });
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
        setBusy(true);
        setError('');
        try {
            await agentRequest('/conversation', { method: 'DELETE' });
            setState(previous => previous && { ...previous, messages: [] });
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
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
            const result = await agentRequest<{ reply: string }>('/messages', {
                method: 'POST', body: JSON.stringify({ message, allow_writes: writes }),
            });
            setState(previous => previous && { ...previous, messages: [
                ...previous.messages, { role: 'user', content: message },
                { role: 'assistant', content: result.reply },
            ] });
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
        <header className="flex h-16 shrink-0 items-center gap-3 border-b border-neutral-800 px-4">
            <span className="flex h-8 w-8 items-center justify-center rounded bg-cyan-700 text-white"><FontAwesomeIcon icon={faRobot} /></span>
            <div className="min-w-0 flex-1 leading-tight">
                <h2 className="text-sm font-bold">VulnScout Agent</h2>
                <span className="text-xs text-neutral-400">{state?.authenticated ? `Connected${state.login ? ` as ${state.login}` : ''}` : 'Not connected'}</span>
            </div>
            <button type="button" title="Clear chat" aria-label="Clear chat" onClick={() => void reset()} disabled={busy || !state} className="flex h-9 w-9 items-center justify-center rounded hover:bg-neutral-800 disabled:opacity-40"><FontAwesomeIcon icon={faTrashCan} /></button>
            <button type="button" title="Close agent" aria-label="Close agent" onClick={onClose} className="flex h-9 w-9 items-center justify-center rounded hover:bg-neutral-800"><FontAwesomeIcon icon={faXmark} /></button>
        </header>

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
                <textarea id="agent-prompt" rows={2} maxLength={8000} value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={onKeyDown} disabled={!state?.authenticated || !state.configured || busy} placeholder="Ask the agent..." className="min-w-0 flex-1 resize-none bg-transparent text-sm text-white outline-none placeholder:text-neutral-500 disabled:opacity-40" />
                <button type="submit" title="Send message" aria-label="Send message" disabled={!draft.trim() || busy || !state?.authenticated || !state.configured} className="flex h-9 w-9 shrink-0 items-center justify-center rounded bg-cyan-700 hover:bg-cyan-600 disabled:bg-neutral-700 disabled:text-neutral-500"><FontAwesomeIcon icon={faArrowUp} /></button>
            </div>
            <label className="flex cursor-pointer items-start gap-2 text-xs text-neutral-300">
                <input type="checkbox" checked={allowWrites} onChange={event => setAllowWrites(event.target.checked)} disabled={busy} className="mt-0.5 accent-cyan-500" />
                Allow assessment and context changes for the next message
            </label>
        </form>
    </div>;
}

export default AgentChat;
