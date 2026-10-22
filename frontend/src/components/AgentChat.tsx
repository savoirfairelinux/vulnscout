import { useCallback, useEffect, useId, useRef, useState, useSyncExternalStore, type FormEvent, type KeyboardEvent } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowDown, faArrowRight, faArrowRotateRight, faArrowUp, faArrowUpRightFromSquare, faCheck, faChevronDown, faCircleCheck, faCircleNotch, faClock, faCopy, faLocationDot, faPlug, faPlus, faXmark } from '@fortawesome/free-solid-svg-icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AGENT_MESSAGE_MAX_LENGTH, type AgentContext, type Activity, type AgentMessage as Message, type AgentUsage as Usage, type AgentStreamEvent as StreamEvent, type QueuedAgentMessage } from '../types/agent';
import { providerIcons } from '../assets/providers';
import { agentRequest, agentErrorMessage as errorMessage } from '../handlers/agent';
import { configureAgentQueue, enqueueAgentMessages, getAgentConversation, getAgentQueue, initializeAgentConversation, resetAgentConversation, resetAgentQueue, subscribeAgentQueue } from '../handlers/agentQueue';
import AgentQueue from './AgentQueue';
type AgentState = { authenticated: boolean; login: string | null; configured: boolean; device_login: boolean; token_connected: boolean; provider: string | null; messages: Message[]; model: string; usage: Usage };
type DeviceCode = { user_code: string; verification_uri: string; interval: number };
type DevicePoll = { status: 'pending' | 'connected'; interval?: number | null; login?: string | null };
type ModelChoice = { id: string; name: string };
const emptyUsage: Usage = { cost: null, input_tokens: null, output_tokens: null };
const pageLabels: Record<string, string> = { metrics: 'Overview', packages: 'SBOM', vulnerabilities: 'Vulnerabilities', scans: 'Scans', review: 'Review', exports: 'Export', settings: 'Settings', ai: 'AI context', unknown: 'Page not found' };
const iconButton = 'flex h-9 w-9 shrink-0 items-center justify-center rounded text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600 disabled:cursor-not-allowed disabled:opacity-40 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-white';
const skipDiscardKey = 'vulnscout.agent.skipDiscardConfirmation';
const connectionChangedEvent = 'vulnscout:agent-connection-changed';
const connectors = [
    { id: 'github', label: 'GitHub Copilot', description: 'Sign in through GitHub on another device.', icon: providerIcons.github },
    { id: 'openai', label: 'OpenAI', description: 'Use an OpenAI API key.', icon: providerIcons.openai },
    { id: 'azure', label: 'Microsoft Foundry', description: 'Connect an Azure endpoint.', icon: providerIcons.azure },
    { id: 'anthropic', label: 'Anthropic', description: 'Use an Anthropic API key.', icon: providerIcons.anthropic },
    { id: 'local', label: 'Local model', description: 'Connect an OpenAI-compatible server, such as Qwen on Ollama.', icon: providerIcons.local },
] as const;
type Connector = (typeof connectors)[number]['id'];

function ActivityLog({ items, pending = false }: Readonly<{ items: Activity[]; pending?: boolean }>) {
    if (!items.length) return null;
    return <details open={pending || undefined} className="mb-3 rounded border border-neutral-200 p-3 text-xs text-neutral-500 dark:border-neutral-700 dark:text-neutral-400">
        <summary className="cursor-pointer">Activity ({items.length})</summary>
        <ul className="mt-3 space-y-2">{items.map(item => <li key={item.id} className="flex items-start gap-2">
            <FontAwesomeIcon icon={item.status === 'running' ? faCircleNotch : item.status === 'done' ? faCheck : faXmark} spin={item.status === 'running'} className="mt-1 shrink-0" />
            <span className="min-w-0 break-words">{item.name.replace(/_/g, ' ')}<span className="sr-only">: {item.status}</span></span>
        </li>)}</ul>
    </details>;
}

export type { QueuedAgentMessage } from '../types/agent';

type QueueProps = {
    /** Pending AI actions, oldest first; the head is sent once the chat is idle. */
    queue?: QueuedAgentMessage[];
    onQueuedMessageSent?: (id: string) => void;
    onQueuedMessageDone?: (id: string, success: boolean) => void;
    onQueueRemove?: (id: string) => void;
    onQueueClear?: () => void;
};

function AgentChat({ onClose, context, active = true, threadId, queue = [], onQueuedMessageSent, onQueuedMessageDone }: Readonly<{ onClose: () => void; context: AgentContext; active?: boolean; threadId?: string } & QueueProps>) {
    const request = useCallback(<T,>(path: string, options?: RequestInit, onEvent?: (event: StreamEvent) => void) => agentRequest<T>(path, {
        ...options,
        headers: { ...options?.headers, ...(threadId ? { 'X-Agent-Thread': threadId } : {}) },
    }, onEvent), [threadId]);
    const [state, setState] = useState<AgentState | null>(null);
    const [error, setError] = useState('');
    const [draft, setDraft] = useState('');
    const [device, setDevice] = useState<DeviceCode | null>(null);
    const [showConnections, setShowConnections] = useState(false);
    const [setupStep, setSetupStep] = useState<1 | 2 | 3>(1);
    const [checkState, setCheckState] = useState<'idle' | 'checking' | 'success' | 'error'>('idle');
    const [providerChoice, setProviderChoice] = useState<Connector>('github');
    const [providerKey, setProviderKey] = useState('');
    const [providerUrl, setProviderUrl] = useState('');
    const [showEndpoint, setShowEndpoint] = useState(false);
    const [busy, setBusy] = useState(false);
    const [modelBusy, setModelBusy] = useState(false);
    const [models, setModels] = useState<ModelChoice[]>([]);
    const [selectedModel, setSelectedModel] = useState('auto');
    const [neverAsk, setNeverAsk] = useState(false);
    const [refresh, setRefresh] = useState(0);
    const conversation = useSyncExternalStore(subscribeAgentQueue, () => getAgentConversation(threadId));
    const sharedQueue = useSyncExternalStore(subscribeAgentQueue, getAgentQueue);
    const { pendingMessage, liveReply, activity, progress } = conversation;
    const [queueOpen, setQueueOpen] = useState(queue.length > 0);
    const composerId = useId();
    const queueId = useId();
    const providerFormId = useId();
    const endpointId = useId();
    const discardTitleId = useId();
    const discardDescriptionId = useId();
    const [copied, setCopied] = useState<string | null>(null);
    const [awayFromBottom, setAwayFromBottom] = useState(false);
    const confirmation = useRef<HTMLDialogElement>(null);
    const connectionSource = useRef(Symbol('agent-chat'));
    const conversationLog = useRef<HTMLDivElement>(null);
    const composer = useRef<HTMLTextAreaElement>(null);
    const followMessages = useRef(true);
    const failedTask = sharedQueue.find(item => item.threadId === threadId && item.status === 'failed');
    const failedQueuedId = failedTask?.id;
    const previousFailed = useRef<string>();
    const threadBusy = Boolean(pendingMessage);
    const ready = Boolean(state?.authenticated && state.configured && models.length && selectedModel && !showConnections);
    const pageLabel = pageLabels[context.page] ?? context.page;
    const source = !threadId ? 'Global chat' : context.page === 'review' ? 'Review chat'
        : context.view?.openVulnerabilityId ? `Vulnerability ${context.view.openVulnerabilityId}` : 'Bulk assessment chat';
    const scopeLabel = context.view?.openVulnerabilityId ?? context.view?.selectedVariantName ?? context.view?.selectedProjectName;
    const largeVulnerabilityView = context.page === 'vulnerabilities' && !context.view?.openVulnerabilityId &&
        (context.view?.visibleVulnerabilityIds?.length ?? context.view?.visibleCount ?? 0) > 100;
    const prompts = context.view?.openVulnerabilityId
        ? [{ label: 'Assess this vulnerability', message: `Assess ${context.view.openVulnerabilityId} in the current scope. Retrieve its details with VulnScout MCP first.` }, { label: 'Review existing assessments', message: 'Review the existing assessments for the open vulnerability in the current scope.' }]
        : [{ label: `Summarize ${pageLabel.toLowerCase()}`, message: `Summarize the current ${pageLabel.toLowerCase()} view and its project scope using VulnScout MCP.` }, { label: 'Prioritize next steps', message: 'Review the current scope and recommend the most important next steps. Do not make changes.' }];

    useEffect(() => {
        const reload = (event: Event) => {
            if ((event as CustomEvent).detail !== connectionSource.current) setRefresh(value => value + 1);
        };
        window.addEventListener(connectionChangedEvent, reload);
        return () => window.removeEventListener(connectionChangedEvent, reload);
    }, []);

    const notifyConnectionChange = () => {
        resetAgentQueue();
        window.dispatchEvent(new CustomEvent(connectionChangedEvent, { detail: connectionSource.current }));
    };

    useEffect(() => {
        let active = true;
        request<AgentState>('').then(result => {
            if (active) {
                setState(result);
                setSelectedModel(result.model);
                initializeAgentConversation(threadId, result.messages, result.usage);
            }
        }).catch(reason => {
            if (active) setError(errorMessage(reason));
        });
        return () => { active = false; };
    }, [refresh, request, threadId]);

    useEffect(() => {
        configureAgentQueue(threadId, {
            ready: Boolean(state?.authenticated && state.configured && models.length && selectedModel) && !modelBusy && !busy,
            model: selectedModel,
        });
    }, [threadId, state?.authenticated, state?.configured, models.length, modelBusy, busy, selectedModel]);

    useEffect(() => {
        if (!queue.length) return;
        try {
            enqueueAgentMessages(queue, context, threadId, source, {
                onSent: onQueuedMessageSent, onDone: onQueuedMessageDone,
            });
        } catch (reason) {
            setError(errorMessage(reason));
        }
    }, [queue, context, threadId, source, onQueuedMessageSent, onQueuedMessageDone]);

    useEffect(() => {
        if (!state?.authenticated) return;
        let active = true;
        request<{ models: ModelChoice[] }>('/models').then(result => {
            if (active) setModels(result.models);
        }).catch(reason => {
            if (active) setError(errorMessage(reason));
        });
        return () => { active = false; };
    }, [state?.authenticated, state?.token_connected, refresh, request]);

    useEffect(() => {
        if (active && followMessages.current && conversationLog.current) {
            conversationLog.current.scrollTop = conversationLog.current.scrollHeight;
        }
    }, [active, conversation.messages.length, pendingMessage, liveReply, activity]);

    useEffect(() => {
        if (!active || !composer.current) return;
        composer.current.style.height = 'auto';
        composer.current.style.height = `${Math.min(composer.current.scrollHeight, 160)}px`;
    }, [active, draft, ready]);

    useEffect(() => {
        if (!copied) return;
        const timer = window.setTimeout(() => setCopied(null), 2000);
        return () => window.clearTimeout(timer);
    }, [copied]);

    async function copy(text: string, key: string) {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(key);
        } catch {
            setError('Clipboard unavailable. Select the text to copy it manually.');
        }
    }

    useEffect(() => {
        if (!device) return;
        let active = true;
        let interval = device.interval;
        let timer = 0;
        const poll = async () => {
            try {
                const result = await request<DevicePoll>('/auth/poll', { method: 'POST' });
                if (!active) return;
                if (result.status === 'pending') {
                    interval = result.interval ?? interval;
                    timer = window.setTimeout(() => void poll(), interval * 1000);
                    return;
                }
                setState(previous => previous && { ...previous, authenticated: true, login: result.login ?? null, token_connected: true, provider: null, messages: [], model: 'auto', usage: emptyUsage });
                setSelectedModel('auto');
                setDevice(null);
                setCheckState('success');
                notifyConnectionChange();
            } catch (reason) {
                if (!active) return;
                setError(errorMessage(reason));
                setCheckState('error');
                setDevice(null);
            }
        };
        timer = window.setTimeout(() => void poll(), interval * 1000);
        return () => { active = false; window.clearTimeout(timer); };
    }, [device, request]);

    async function signIn() {
        setBusy(true);
        setError('');
        setShowConnections(true);
        setSetupStep(3);
        setCheckState('checking');
        try {
            setDevice(await request<DeviceCode>('/auth', { method: 'POST' }));
        } catch (reason) {
            setError(errorMessage(reason));
            setCheckState('error');
        } finally {
            setBusy(false);
        }
    }

    async function verifyGitHub() {
        setSetupStep(3);
        setCheckState('checking');
        setError('');
        try {
            const result = await request<AgentState>('');
            if (!result.authenticated) throw new Error('GitHub is not connected. Sign in to continue.');
            await request('/models');
            setCheckState('success');
        } catch (reason) {
            setError(errorMessage(reason));
            setCheckState('error');
        }
    }

    async function connectProvider(event: FormEvent) {
        event.preventDefault();
        if ((providerChoice === 'azure' || providerChoice === 'local') && !providerUrl.trim()) {
            setShowEndpoint(true);
            setError('Enter the endpoint URL for this connector.');
            return;
        }
        setBusy(true);
        setError('');
        setSetupStep(3);
        setCheckState('checking');
        try {
            const result = await request<{ provider: string; model: string }>('/provider', {
                method: 'POST', body: JSON.stringify({ provider: providerChoice, api_key: providerKey, base_url: providerUrl }),
            });
            setProviderKey('');
            setShowConnections(true);
            setModels([]);
            setSelectedModel(result.model);
            setState(previous => previous && { ...previous, provider: result.provider, authenticated: true, login: null, model: result.model, messages: [], usage: emptyUsage });
            setRefresh(value => value + 1);
            setCheckState('success');
            notifyConnectionChange();
        } catch (reason) {
            setError(errorMessage(reason));
            setCheckState('error');
        } finally {
            setBusy(false);
        }
    }

    async function disconnectProvider() {
        setBusy(true);
        setError('');
        try {
            await request('/provider', { method: 'DELETE' });
            setModels([]);
            setDraft('');
            setShowConnections(false);
            setSetupStep(1);
            setProviderChoice('github');
            setShowEndpoint(false);
            setState(previous => previous && { ...previous, provider: null, authenticated: false, login: null, model: 'auto', messages: [], usage: emptyUsage });
            setSelectedModel('auto');
            setRefresh(value => value + 1);
            notifyConnectionChange();
        } catch (reason) {
            setError(errorMessage(reason));
        } finally {
            setBusy(false);
        }
    }

    async function signOut() {
        setBusy(true);
        setError('');
        try {
            const result = await request<{ cleanup_error: string | null }>('/auth', { method: 'DELETE' });
            setModels([]);
            setDraft('');
            setShowConnections(false);
            setSetupStep(1);
            setState(previous => previous && { ...previous, authenticated: false, login: null, token_connected: false, messages: [], model: 'auto', usage: emptyUsage });
            setSelectedModel('auto');
            notifyConnectionChange();
            if (result.cleanup_error) setError(result.cleanup_error);
        } catch (reason) {
            setError(errorMessage(reason));
        } finally {
            setBusy(false);
        }
    }

    async function reset() {
        if (busy || modelBusy || threadBusy || sharedQueue.some(item => item.threadId === threadId)) return;
        setBusy(true);
        setError('');
        try {
            const result = await request<{ usage: Usage }>('/conversation', { method: 'DELETE' });
            setState(previous => previous && { ...previous, messages: [], usage: result.usage });
            resetAgentConversation(threadId);
            setDraft('');
            followMessages.current = true;
            setAwayFromBottom(false);
            composer.current?.focus();
        } catch (reason) {
            setError(errorMessage(reason));
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
            await request('/model', { method: 'POST', body: JSON.stringify({ model }) });
            setState(current => current && { ...current, model });
        } catch (reason) {
            setSelectedModel(previous);
            setError(errorMessage(reason));
        } finally {
            setModelBusy(false);
        }
    }

    function send(event?: FormEvent, actionMessage?: string) {
        event?.preventDefault();
        const message = (actionMessage ?? draft).trim();
        if (!message || busy || modelBusy || !ready) return;
        try {
            const id = crypto.randomUUID();
            enqueueAgentMessages([{ id, key: id, text: message, kind: 'message', title: message }], context, threadId, source);
            setDraft('');
            setError('');
            followMessages.current = true;
            setAwayFromBottom(false);
        } catch (reason) {
            setError(errorMessage(reason));
        }
    }

    useEffect(() => {
        if (failedTask) {
            setDraft(current => current || failedTask.text);
            setQueueOpen(true);
        } else if (previousFailed.current) {
            const failedText = previousFailed.current;
            setDraft(current => current === failedText ? '' : current);
        }
        previousFailed.current = failedTask?.text;
    }, [failedTask]);

    function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
            event.preventDefault();
            void send();
        }
    }

    return <div className="flex h-full min-h-0 min-w-0 flex-col bg-white text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
        <header className="flex min-h-14 shrink-0 items-center gap-1 border-b border-neutral-200 px-3 dark:border-neutral-800">
            <h2 className="min-w-0 flex-1 truncate pr-2 text-sm font-semibold" title={source}>{source}</h2>
            <button type="button" title="AI queue" aria-label={`AI queue (${sharedQueue.length})`} aria-expanded={queueOpen} aria-controls={queueId} onClick={() => setQueueOpen(value => !value)} className={iconButton}>
                <FontAwesomeIcon icon={faClock} /><span className="ml-1 text-xs">{sharedQueue.length}</span>
            </button>
            {state?.authenticated && <button type="button" title="Configure model provider" aria-label="Configure model provider" aria-expanded={showConnections} onClick={() => {
                setShowConnections(value => !value);
                setProviderChoice((state.provider as Connector | null) ?? 'github');
                setSetupStep(1);
                setDevice(null);
                setShowEndpoint(false);
                setCheckState('idle');
                setError('');
            }} disabled={busy || modelBusy || sharedQueue.length > 0} className={iconButton}><FontAwesomeIcon icon={faPlug} /></button>}
            <button type="button" title="New conversation" aria-label="New conversation" onClick={() => {
                let skipConfirmation = neverAsk;
                try { skipConfirmation = localStorage.getItem(skipDiscardKey) === 'true'; } catch { skipConfirmation = neverAsk; }
                if (skipConfirmation) {
                    void reset();
                } else {
                    setNeverAsk(false);
                    confirmation.current?.showModal();
                }
            }} disabled={busy || modelBusy || threadBusy || sharedQueue.some(item => item.threadId === threadId) || !state || (!conversation.messages.length && !draft)} className={iconButton}><FontAwesomeIcon icon={faPlus} /></button>
            <button type="button" title="Close agent" aria-label="Close agent" onClick={onClose} className={iconButton}><FontAwesomeIcon icon={faXmark} /></button>
        </header>
        <dialog ref={confirmation} aria-labelledby={discardTitleId} aria-describedby={discardDescriptionId} className="w-[calc(100%-2rem)] max-w-sm rounded-lg border border-neutral-200 bg-white p-6 text-neutral-900 shadow-xl backdrop:bg-black/50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100" onCancel={() => setNeverAsk(false)} onKeyDown={event => {
            if (event.key === 'Escape') {
                event.preventDefault();
                event.stopPropagation();
                setNeverAsk(false);
                confirmation.current?.close();
            }
        }}>
            <h2 id={discardTitleId} className="text-base font-semibold">New conversation?</h2>
            <p id={discardDescriptionId} className="mt-3 text-sm leading-relaxed text-neutral-500 dark:text-neutral-400">This conversation will be discarded forever. This cannot be undone.</p>
            <label className="mt-4 flex items-center gap-2 text-sm">
                <input type="checkbox" checked={neverAsk} onChange={event => setNeverAsk(event.target.checked)} className="accent-cyan-500" />
                Never ask again
            </label>
            <div className="mt-5 flex justify-end gap-3">
                <button type="button" autoFocus onClick={() => { setNeverAsk(false); confirmation.current?.close(); }} className="rounded border border-neutral-300 px-4 py-2 text-sm hover:bg-neutral-100 focus-visible:outline-cyan-600 dark:border-neutral-600 dark:hover:bg-neutral-800">Cancel</button>
                <button type="button" onClick={() => {
                    try { localStorage.setItem(skipDiscardKey, String(neverAsk)); } catch { setNeverAsk(neverAsk); }
                    confirmation.current?.close();
                    void reset();
                }} className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-600 focus-visible:outline-cyan-600">Confirm</button>
            </div>
        </dialog>

        <div ref={conversationLog} className="scrollbar-minimal min-h-0 flex-1 space-y-6 overflow-y-auto overscroll-contain px-5 py-6" role="log" aria-label="Agent conversation" aria-live="polite" onScroll={event => {
            const log = event.currentTarget;
            followMessages.current = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
            setAwayFromBottom(!followMessages.current);
        }}>
            {!state && !error && <p role="status" className="flex items-center gap-2 py-6 text-sm text-neutral-500"><FontAwesomeIcon icon={faCircleNotch} spin /> Connecting...</p>}
            {state?.authenticated && state.configured && !models.length && !error && <p role="status" className="flex items-center gap-2 py-6 text-sm text-neutral-500"><FontAwesomeIcon icon={faCircleNotch} spin /> Loading models...</p>}
            {state && !state.configured && <div className="space-y-3 border-b border-neutral-200 pb-5 text-sm dark:border-neutral-800">
                <h3 className="font-semibold">Agent setup required</h3>
                <details className="text-neutral-500 dark:text-neutral-400">
                    <summary className="cursor-pointer text-sm">Backend configuration</summary>
                    <p className="mt-2 break-words text-xs leading-relaxed">The bundled MCP server is missing. Check the backend installation or remove an outdated <code>VULNSCOUT_MCP_SERVER_PATH</code> override.</p>
                </details>
                <button type="button" onClick={() => { setError(''); setRefresh(value => value + 1); }} className="inline-flex items-center gap-2 text-cyan-700 hover:underline dark:text-cyan-400"><FontAwesomeIcon icon={faArrowRotateRight} /> Check connection</button>
            </div>}
            {state && (!state.authenticated || showConnections) && <div className="space-y-5 py-2 text-sm">
                <div className="border-b border-neutral-200 pb-4 dark:border-neutral-800">
                    <h3 className="text-lg font-semibold">Connect an agent</h3>
                    {state.authenticated && <div className="mt-3 flex items-center justify-between gap-3">
                        <span className="text-xs text-neutral-500">{state.provider
                            ? connectors.find(connector => connector.id === state.provider)?.label
                            : state.login ? `GitHub Copilot · ${state.login}` : 'GitHub Copilot'}</span>
                        {(state.provider || state.token_connected) && <button type="button"
                            disabled={busy || modelBusy || sharedQueue.length > 0}
                            onClick={() => state.provider ? void disconnectProvider() : void signOut()}
                            className="rounded border border-neutral-300 px-3 py-1.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-40 dark:border-neutral-700 dark:text-red-400 dark:hover:bg-red-950">
                            {state.provider ? 'Disconnect provider' : 'Sign out'}
                        </button>}
                    </div>}
                    <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">Step {setupStep} of 3</p>
                    <ol className="mt-4 grid grid-cols-3 gap-2 text-xs">
                        {['Connector', 'Connect', 'Confirm'].map((label, index) => <li key={label} className={index + 1 <= setupStep ? 'font-semibold text-cyan-700 dark:text-cyan-300' : 'text-neutral-500'}><span className="mr-1">{index + 1}.</span>{label}</li>)}
                    </ol>
                </div>
                {setupStep === 1 ? <>
                    <h4 className="font-semibold">Select a connector</h4>
                    <div className="grid gap-2">
                        {connectors.map(({ id, label, description, icon }) => <label key={id} className={`flex cursor-pointer items-start gap-3 rounded border px-3 py-3 transition-colors ${providerChoice === id ? 'border-cyan-600 bg-cyan-50 text-neutral-900 dark:border-cyan-500 dark:bg-cyan-950/40 dark:text-white' : 'border-neutral-300 text-neutral-700 hover:border-cyan-600 dark:border-neutral-700 dark:text-neutral-300'}`}>
                            <input type="radio" name={`agent-connector-${composerId}`} value={id} checked={providerChoice === id} onChange={() => {
                                setProviderChoice(id);
                                setProviderKey('');
                                setProviderUrl('');
                                setShowEndpoint(false);
                                setCheckState('idle');
                            }} className="mt-1 accent-cyan-600" />
                            <img src={icon} alt="" aria-hidden="true" className={`mt-0.5 h-5 w-5 shrink-0 ${id === 'azure' || id === 'anthropic' ? '' : 'dark:invert'}`} />
                            <span className="min-w-0"><span className="block font-medium">{label}</span><span className="mt-1 block text-xs text-neutral-500 dark:text-neutral-400">{description}</span></span>
                        </label>)}
                    </div>
                </> : setupStep === 2 && providerChoice === 'github' ? <>
                    <h4 className="font-semibold">GitHub Copilot</h4>
                    <p className="text-neutral-500 dark:text-neutral-400">{state.authenticated && !state.provider ? 'Your GitHub account is already connected.' : 'Sign in with a GitHub account that has Copilot access.'}</p>
                </> : setupStep === 2 ? <>
                    <h4 className="font-semibold">{connectors.find(connector => connector.id === providerChoice)?.label}</h4>
                    <form id={providerFormId} onSubmit={event => void connectProvider(event)} className="space-y-3">
                        <label className="block space-y-1">API key {providerChoice === 'local' && <span className="text-neutral-500">(optional)</span>}
                            <input aria-label="Provider API key" type="password" autoComplete="off" required={providerChoice !== 'local'} value={providerKey} onChange={event => setProviderKey(event.target.value)} className="w-full rounded border border-neutral-300 bg-white p-2 dark:border-neutral-700 dark:bg-neutral-900" />
                        </label>
                        <button type="button" aria-expanded={showEndpoint} aria-controls={endpointId} onClick={() => setShowEndpoint(value => !value)} className="flex items-center gap-2 text-sm font-medium text-cyan-700 hover:text-cyan-600 dark:text-cyan-400"><FontAwesomeIcon icon={faChevronDown} className={showEndpoint ? 'rotate-180' : ''} />Use custom endpoint URL{(providerChoice === 'azure' || providerChoice === 'local') && ' (required)'}</button>
                        {showEndpoint && <label id={endpointId} className="block space-y-1">API base URL
                            <input aria-label="Provider API base URL" type="url" value={providerUrl} onChange={event => setProviderUrl(event.target.value)} placeholder={providerChoice === 'local' ? 'http://127.0.0.1:11434/v1' : providerChoice === 'azure' ? 'https://your-resource.openai.azure.com/openai/v1/' : 'Default provider endpoint'} className="w-full rounded border border-neutral-300 bg-white p-2 dark:border-neutral-700 dark:bg-neutral-900" />
                        </label>}
                    </form>
                </> : <div className="space-y-4 py-4 text-center">
                    {checkState === 'success' ? <>
                        <FontAwesomeIcon icon={faCircleCheck} className="text-4xl text-green-600" aria-hidden="true" />
                        <h4 className="text-lg font-semibold">Connection verified</h4>
                        <p className="text-neutral-500 dark:text-neutral-400">{connectors.find(connector => connector.id === providerChoice)?.label} is ready.</p>
                    </> : <>
                        <FontAwesomeIcon icon={checkState === 'error' ? faXmark : faCircleNotch} spin={checkState === 'checking'} className="text-3xl text-cyan-600" aria-hidden="true" />
                        <h4 className="font-semibold">{checkState === 'error' ? 'Connection failed' : 'Checking connection...'}</h4>
                        {device && <>
                            <p className="text-neutral-500 dark:text-neutral-400">Enter this code on GitHub to authorize the agent.</p>
                            <div className="flex items-center justify-center gap-2">
                                <code className="select-all rounded border border-neutral-200 bg-neutral-50 px-4 py-3 font-mono text-xl dark:border-neutral-700 dark:bg-neutral-900">{device.user_code}</code>
                                <button type="button" title={copied === 'device' ? 'Copied' : 'Copy code'} aria-label="Copy code" onClick={() => void copy(device.user_code, 'device')} className={iconButton}><FontAwesomeIcon icon={copied === 'device' ? faCheck : faCopy} /></button>
                            </div>
                            <a className="inline-flex min-h-10 items-center gap-2 rounded bg-cyan-700 px-4 py-2 font-semibold text-white hover:bg-cyan-600" href={device.verification_uri} target="_blank" rel="noopener noreferrer">Open GitHub <FontAwesomeIcon icon={faArrowUpRightFromSquare} /></a>
                            <div role="status" className="text-xs text-neutral-500 dark:text-neutral-400">Waiting for approval...</div>
                        </>}
                    </>}
                </div>}
            </div>}
            {ready && conversation.messages.length === 0 && !pendingMessage && <div className="space-y-6 py-6 text-sm">
                <h3 className="text-lg font-semibold leading-snug">What needs your attention?</h3>
                <div className="space-y-3">
                    {prompts.map((prompt, index) => <button key={prompt.label} type="button" disabled={busy || modelBusy || !ready || Boolean(failedQueuedId) || (largeVulnerabilityView && index === 0)} onClick={() => void send(undefined, prompt.message)} className="group flex w-full items-center justify-between gap-3 rounded border border-neutral-300 px-4 py-3 text-left text-neutral-600 hover:border-cyan-600 hover:text-cyan-700 focus-visible:outline-cyan-600 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-cyan-500 dark:hover:text-cyan-400"><span>{prompt.label}</span><FontAwesomeIcon icon={faArrowRight} className="text-xs text-neutral-400 group-hover:text-cyan-600" /></button>)}
                    {largeVulnerabilityView && <p className="text-xs text-neutral-500 dark:text-neutral-400">Filter to 100 or fewer vulnerabilities to summarize the displayed rows.</p>}
                </div>
            </div>}
            {conversation.messages.map((message, index) => <div key={index} className={`min-w-0 ${message.role === 'user' ? 'flex justify-end' : ''}`}>
                <div className={`min-w-0 break-words text-sm leading-7 [overflow-wrap:anywhere] ${message.role === 'user' ? 'max-w-[90%] whitespace-pre-wrap rounded-lg bg-neutral-100 px-4 py-3 dark:bg-neutral-800' : ''}`}>
                    {message.activity && <ActivityLog items={message.activity} />}
                    {message.role === 'assistant' ? <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
                        p: ({ children }) => <p className="mb-3 last:mb-0">{children}</p>,
                        h1: ({ children }) => <h3 className="mb-3 mt-5 text-base font-semibold">{children}</h3>,
                        h2: ({ children }) => <h3 className="mb-3 mt-5 text-base font-semibold">{children}</h3>,
                        h3: ({ children }) => <h4 className="mb-2 mt-4 font-semibold">{children}</h4>,
                        ul: ({ children }) => <ul className="my-3 list-disc space-y-1 pl-5">{children}</ul>,
                        ol: ({ children }) => <ol className="my-3 list-decimal space-y-1 pl-5">{children}</ol>,
                        blockquote: ({ children }) => <blockquote className="my-3 border-l-2 border-neutral-300 pl-4 text-neutral-500 dark:border-neutral-600 dark:text-neutral-400">{children}</blockquote>,
                        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-cyan-700 underline underline-offset-2 dark:text-cyan-400">{children}</a>,
                        code: ({ children }) => <code className="rounded bg-neutral-100 px-1 py-0.5 font-mono text-xs dark:bg-neutral-800">{children}</code>,
                        pre: ({ children }) => <pre className="my-3 max-w-full overflow-x-auto rounded border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-neutral-900 [&_code]:bg-transparent [&_code]:p-0">{children}</pre>,
                        table: ({ children }) => <div tabIndex={0} role="region" aria-label="Response table" className="my-3 max-w-full overflow-x-auto rounded border border-neutral-200 dark:border-neutral-700"><table className="w-full min-w-[360px] border-collapse text-left text-xs leading-5">{children}</table></div>,
                        th: ({ children }) => <th className="border-b border-neutral-200 bg-neutral-50 p-3 font-semibold dark:border-neutral-700 dark:bg-neutral-900">{children}</th>,
                        td: ({ children }) => <td className="border-b border-neutral-200 p-3 align-top dark:border-neutral-800">{children}</td>,
                    }}>{message.content}</ReactMarkdown> : message.content}
                    {message.role === 'assistant' && <button type="button" title={copied === String(index) ? 'Copied' : 'Copy response'} aria-label="Copy response" onClick={() => void copy(message.content, String(index))} className={`${iconButton} mt-2`}><FontAwesomeIcon icon={copied === String(index) ? faCheck : faCopy} className="text-xs" /></button>}
                </div>
            </div>)}
            {pendingMessage && <><div className="flex justify-end"><div className="max-w-[90%] whitespace-pre-wrap break-words rounded-lg bg-neutral-100 px-4 py-3 text-sm leading-7 [overflow-wrap:anywhere] dark:bg-neutral-800">{pendingMessage}</div></div><div><ActivityLog items={activity} pending />{liveReply && <div className="mb-3 whitespace-pre-wrap break-words text-sm leading-7 [overflow-wrap:anywhere]">{liveReply}</div>}<div role="status" className="flex items-center gap-2 text-sm text-neutral-500"><FontAwesomeIcon icon={faCircleNotch} spin />{progress}</div></div></>}
        </div>
        {awayFromBottom && <button type="button" aria-label="Jump to latest message" title="Jump to latest message" onClick={() => { if (conversationLog.current) conversationLog.current.scrollTop = conversationLog.current.scrollHeight; }} className={`${iconButton} mx-auto mb-2 border border-neutral-200 dark:border-neutral-700`}><FontAwesomeIcon icon={faArrowDown} /></button>}
        {(error || conversation.error) && <div className="mx-4 mb-3 flex items-start gap-2 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300"><p role="alert" className="min-w-0 flex-1 break-words leading-relaxed">{error || conversation.error}</p><button type="button" title="Retry connection" aria-label="Retry connection" disabled={busy} onClick={() => { setError(''); setRefresh(value => value + 1); }} className={iconButton}><FontAwesomeIcon icon={faArrowRotateRight} /></button><button type="button" title="Dismiss error" aria-label="Dismiss error" onClick={() => setError('')} className={iconButton}><FontAwesomeIcon icon={faXmark} /></button></div>}

        {state && (!state.authenticated || showConnections) && <div className="flex shrink-0 items-center justify-between gap-3 border-t border-neutral-200 px-4 py-3 dark:border-neutral-800">
            <button type="button" onClick={() => { setDevice(null); setSetupStep(step => step === 3 ? 2 : 1); setCheckState('idle'); setError(''); }} disabled={setupStep === 1 || busy} className="rounded border border-neutral-300 px-4 py-2 text-sm font-semibold hover:bg-neutral-100 disabled:opacity-40 dark:border-neutral-700 dark:hover:bg-neutral-800">Back</button>
            {setupStep === 1 ? <button type="button" onClick={() => setSetupStep(2)} className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-600">Next</button>
                : setupStep === 3 ? <button type="button" onClick={() => { setShowConnections(false); setSetupStep(1); setDevice(null); setError(''); }} disabled={checkState !== 'success'} className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-600 disabled:opacity-50">Start using</button>
                    : providerChoice === 'github' ? <button type="button" onClick={() => state.authenticated && !state.provider ? void verifyGitHub() : void signIn()} disabled={busy} className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-600 disabled:opacity-50">{state.authenticated && !state.provider ? 'Verify GitHub connection' : 'Sign in with GitHub'}</button>
                        : <button type="submit" form={providerFormId} disabled={busy} className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-600 disabled:opacity-50">Verify connection</button>}
        </div>}

        {state?.authenticated && state.provider && !selectedModel && !showConnections && models.length > 0 && <p role="status" className="px-4 py-2 text-xs text-neutral-500 dark:text-neutral-400">Choose a model in the message box to start chatting.</p>}

        {queueOpen && <AgentQueue id={queueId} />}

        {state?.authenticated && state.configured && !showConnections && <form onSubmit={event => void send(event)} className="shrink-0 space-y-3 border-t border-neutral-200 px-4 pb-4 pt-3 dark:border-neutral-800">
            <div className="flex min-w-0 items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
                <FontAwesomeIcon icon={faLocationDot} className="shrink-0" />
                <span className="truncate" title={[pageLabel, scopeLabel].filter(Boolean).join(' / ')}>{pageLabel}{scopeLabel && ` / ${scopeLabel}`}</span>
                {context.view?.visibleVulnerabilityIds && <span className="ml-auto shrink-0 tabular-nums">{context.view.visibleVulnerabilityIds.length} displayed</span>}
            </div>
            {(context.view?.openVulnerabilityId || (context.page === 'vulnerabilities' && Boolean(context.view?.visibleVulnerabilityIds?.length))) && <div className="flex flex-wrap gap-3 text-xs">
                {context.view?.openVulnerabilityId && <button type="button" disabled={busy || modelBusy || !ready || Boolean(failedQueuedId)} onClick={() => void send(undefined, prompts[0].message)} className="inline-flex items-center gap-2 rounded border border-neutral-300 px-3 py-2 text-cyan-700 hover:border-cyan-600 disabled:opacity-50 dark:border-neutral-700 dark:text-cyan-400 dark:hover:border-cyan-500"><FontAwesomeIcon icon={faArrowRight} />Assess vulnerability</button>}
                {context.page === 'vulnerabilities' && !!context.view?.visibleVulnerabilityIds?.length && <button type="button" onClick={() => {
                    if ((context.view?.visibleVulnerabilityIds?.length ?? 0) > 100) {
                        setError('Narrow the table to 100 vulnerabilities or fewer before assessing every displayed row.');
                    } else {
                        setError('');
                        void send(undefined, 'Assess every vulnerability currently displayed in this filtered table. Use the attached list of IDs and current project/variant scope; report the result for each.');
                    }
                }} disabled={busy || modelBusy || !ready || Boolean(failedQueuedId)} className="inline-flex items-center gap-2 rounded border border-neutral-300 px-3 py-2 text-cyan-700 hover:border-cyan-600 disabled:opacity-50 dark:border-neutral-700 dark:text-cyan-400 dark:hover:border-cyan-500"><FontAwesomeIcon icon={faArrowRight} />Assess displayed</button>}
            </div>}
            <label htmlFor={composerId} className="sr-only">Message the agent</label>
            <div className="rounded-lg border border-neutral-300 bg-white p-3 transition-colors focus-within:border-cyan-600 focus-within:ring-1 focus-within:ring-cyan-600 dark:border-neutral-700 dark:bg-neutral-900">
                <textarea ref={composer} id={composerId} rows={2} maxLength={AGENT_MESSAGE_MAX_LENGTH} value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={onKeyDown} disabled={!ready || busy || modelBusy || Boolean(failedQueuedId)} placeholder="Ask about this view..." className="block max-h-40 min-h-14 w-full resize-none bg-transparent text-sm leading-6 outline-none placeholder:text-neutral-400 disabled:opacity-50" />
                <div className="mt-2 flex min-w-0 items-center gap-2">
                    <select aria-label="Agent model" value={selectedModel} onChange={event => void selectModel(event.target.value)} disabled={busy || modelBusy || threadBusy || !models.length} className="min-w-0 flex-1 truncate rounded border-0 bg-transparent py-2 pl-1 pr-6 text-xs font-medium outline-none focus-visible:ring-2 focus-visible:ring-cyan-600 disabled:opacity-50 dark:bg-neutral-900">
                        {!selectedModel && <option value="">Select a model</option>}
                        {!models.length && selectedModel && <option value={selectedModel}>{error ? 'Models unavailable' : 'Loading models...'}</option>}
                        {models.map(model => <option key={model.id} value={model.id}>{model.name}</option>)}
                    </select>
                    {modelBusy && <FontAwesomeIcon icon={faCircleNotch} spin className="text-xs text-neutral-500" title="Switching model" />}
                    <button type="submit" title="Send message" aria-label="Send message" disabled={!draft.trim() || busy || modelBusy || !ready || Boolean(failedQueuedId)} className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-cyan-700 text-white hover:bg-cyan-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600 disabled:bg-neutral-100 disabled:text-neutral-400 dark:disabled:bg-neutral-800 dark:disabled:text-neutral-600"><FontAwesomeIcon icon={pendingMessage ? faCircleNotch : faArrowUp} spin={Boolean(pendingMessage)} /></button>
                </div>
            </div>
            {conversation.messages.length > 0 && <details className="text-xs text-neutral-500 dark:text-neutral-400"><summary className="w-fit cursor-pointer">Conversation usage</summary><div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 tabular-nums"><span>{conversation.usage.cost == null ? 'Cost not reported' : `SDK cost ${conversation.usage.cost.toFixed(4)}`}</span><span>{conversation.usage.input_tokens?.toLocaleString() ?? '—'} input tokens</span><span>{conversation.usage.output_tokens?.toLocaleString() ?? '—'} output tokens</span></div></details>}
        </form>}
    </div>;
}

export default AgentChat;
