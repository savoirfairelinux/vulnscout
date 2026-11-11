import { useSyncExternalStore } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBoxArchive, faCheck, faCircleNotch, faComments, faHourglassHalf, faStop, faTrash, faTriangleExclamation, faXmark } from '@fortawesome/free-solid-svg-icons';
import {
    MAIN_CONVERSATION, clearAgentQueue, clearFinishedConversations, conversationStatus, deleteAgentConversation,
    getAgentConversations, getAgentQueuePaused, removeAgentTask, stopAgentTask, subscribeAgentQueue, type AgentConversation,
    type AgentConversationStatus,
} from '../handlers/agentQueue';
import useAgentQueue from '../hooks/useAgentQueue';
import { agentErrorMessage } from '../handlers/agent';

const sectionTitles: Record<AgentConversationStatus, string> = { failed: 'Needs attention', running: 'Running', queued: 'Waiting', idle: 'Finished' };
const order: AgentConversationStatus[] = ['failed', 'running', 'queued', 'idle'];

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;
const relativeTime = (time: number) => {
    const minutes = Math.round((Date.now() - time) / 60000);
    return minutes < 1 ? 'just now' : minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`;
};

type Props = {
    activeConversationId: string;
    onOpen: (conversationId: string) => void;
    onError?: (message: string) => void;
};

/** Every conversation of the agent chat, like a chat history: the main one, then each AI action by status. */
export default function AgentConversationList({ activeConversationId, onOpen, onError }: Readonly<Props>) {
    const queue = useAgentQueue();
    const conversations = useSyncExternalStore(subscribeAgentQueue, getAgentConversations);
    const queuePaused = useSyncExternalStore(subscribeAgentQueue, getAgentQueuePaused);
    const main = conversations[MAIN_CONVERSATION];
    const actions = Object.values(conversations).filter(item => item.id !== MAIN_CONVERSATION);
    const statusOf = (item: AgentConversation) => conversationStatus(queue, item.id);
    const waitingPosition = (item: AgentConversation) =>
        queue.find(task => task.conversationId === item.id && task.status === 'queued')?.position ?? 0;
    const sourceOf = (item: AgentConversation) => queue.find(task => task.conversationId === item.id)?.source;
    const failed = queue.some(task => task.status === 'failed');
    const mutate = (change: () => Promise<void>) => {
        change().catch(reason => onError?.(agentErrorMessage(reason)));
    };
    const running = queue.filter(task => task.status === 'running').length;
    const waiting = queue.filter(task => task.status === 'queued').length;
    const finished = actions.filter(item => statusOf(item) === 'idle');

    const statusLine = (item: AgentConversation, status: AgentConversationStatus) => [
        sourceOf(item),
        status === 'failed' ? 'failed' : status === 'running' ? 'running' : status === 'queued' ? `waiting · #${waitingPosition(item)}`
            : item.archived ? 'archived' : plural(Math.floor(item.messageCount / 2), 'request'),
    ].filter(Boolean).join(' · ');

    const icon = (item: AgentConversation, status: AgentConversationStatus) => status === 'failed'
        ? <FontAwesomeIcon icon={faTriangleExclamation} className="text-amber-500" />
        : status === 'running' ? <FontAwesomeIcon icon={faCircleNotch} spin className="text-cyan-600" />
        : status === 'queued' ? <FontAwesomeIcon icon={faHourglassHalf} className="text-neutral-500" />
        : item.archived ? <FontAwesomeIcon icon={faBoxArchive} className="text-neutral-400" />
        : <FontAwesomeIcon icon={faCheck} className="text-green-600" />;

    const row = (item: AgentConversation) => {
        const status = statusOf(item);
        const current = item.id === activeConversationId;
        return <li key={item.id} className="group flex items-stretch">
            <button type="button" onClick={() => onOpen(item.id)} aria-current={current ? 'true' : undefined}
                aria-label={`Open conversation ${item.title}`}
                className={`flex min-w-0 flex-1 items-start gap-3 rounded-md px-3 py-2.5 text-left hover:bg-neutral-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-600 dark:hover:bg-neutral-800 ${current ? 'bg-neutral-100 dark:bg-neutral-800' : ''}`}>
                <span className="mt-0.5 flex w-4 shrink-0 justify-center text-xs">{icon(item, status)}</span>
                <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium" title={item.title}>{item.title}</span>
                    <span className="block truncate text-xs text-neutral-500">{statusLine(item, status)}</span>
                </span>
                <span className="shrink-0 text-[11px] text-neutral-400">{relativeTime(item.lastUsed)}</span>
            </button>
            {(status === 'queued' || status === 'failed') && <button type="button" title="Remove from queue" aria-label={`Remove ${item.title} from queue`}
                onClick={() => mutate(async () => {
                    for (const task of queue.filter(task => task.conversationId === item.id && task.status !== 'running')) await removeAgentTask(task.id);
                })}
                className="px-2 text-neutral-400 opacity-60 hover:text-red-600 group-hover:opacity-100"><FontAwesomeIcon icon={faXmark} /></button>}
            {status === 'running' && <button type="button" title="Stop" aria-label={`Stop ${item.title}`}
                onClick={() => mutate(async () => {
                    const running = queue.find(task => task.conversationId === item.id && task.status === 'running');
                    if (running) await stopAgentTask(running.id);
                })}
                className="px-2 text-neutral-400 opacity-60 hover:text-red-600 group-hover:opacity-100"><FontAwesomeIcon icon={faStop} className="text-xs" /></button>}
            {status === 'idle' && <button type="button" title="Delete conversation" aria-label={`Delete conversation ${item.title}`} onClick={() => mutate(() => deleteAgentConversation(item.id))}
                className="px-2 text-neutral-400 opacity-60 hover:text-red-600 group-hover:opacity-100"><FontAwesomeIcon icon={faTrash} className="text-xs" /></button>}
        </li>;
    };

    return <nav aria-label="Conversations" className="flex min-h-0 flex-1 flex-col">
        <div className="flex shrink-0 items-center justify-between gap-3 px-5 pb-2 pt-4 text-xs text-neutral-500">
            <p>{running} running · {waiting} waiting</p>
            {queue.some(task => task.status !== 'running') && <button type="button" onClick={() => mutate(clearAgentQueue)} className="shrink-0 text-cyan-700 hover:underline dark:text-cyan-400">Clear waiting</button>}
        </div>
        {(queuePaused || failed) && <p role="status" className="mx-4 mb-2 flex items-start gap-2 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
            <FontAwesomeIcon icon={faTriangleExclamation} className="mt-0.5" />{queuePaused ? `AI queue paused: ${queuePaused.reason}` : 'A request failed. Open its conversation to retry or remove it.'}</p>}
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-2 pb-4">
            <ul aria-label="Main conversation">
                <li><button type="button" onClick={() => onOpen(MAIN_CONVERSATION)} aria-current={activeConversationId === MAIN_CONVERSATION ? 'true' : undefined}
                    aria-label="Open main conversation"
                    className={`flex w-full items-start gap-3 rounded-md px-3 py-2.5 text-left hover:bg-neutral-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-600 dark:hover:bg-neutral-800 ${activeConversationId === MAIN_CONVERSATION ? 'bg-neutral-100 dark:bg-neutral-800' : ''}`}>
                    <span className="mt-0.5 flex w-4 shrink-0 justify-center text-xs"><FontAwesomeIcon icon={faComments} className="text-cyan-600" /></span>
                    <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium">Main conversation</span>
                        <span className="block truncate text-xs text-neutral-500">{main.messageCount ? plural(Math.floor(main.messageCount / 2), 'message') : 'Ask about the current view'}{conversationStatus(queue, MAIN_CONVERSATION) !== 'idle' && ` · ${conversationStatus(queue, MAIN_CONVERSATION) === 'queued' ? 'waiting' : conversationStatus(queue, MAIN_CONVERSATION)}`}</span>
                    </span>
                </button></li>
            </ul>
            {!actions.length && <p className="px-3 text-xs text-neutral-500">Assess with AI and Review with AI start their own conversations here.</p>}
            {order.map(status => {
                const items = actions.filter(item => statusOf(item) === status)
                    .sort((a, b) => status === 'queued' ? waitingPosition(a) - waitingPosition(b) : b.lastUsed - a.lastUsed);
                return items.length > 0 && <section key={status} aria-label={sectionTitles[status]}>
                    <div className="flex items-center justify-between px-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-neutral-500">
                        <h3>{sectionTitles[status]} <span className="tabular-nums">({items.length})</span></h3>
                        {status === 'idle' && finished.length > 0 && <button type="button" onClick={() => mutate(clearFinishedConversations)} className="normal-case tracking-normal text-cyan-700 hover:underline dark:text-cyan-400">Delete all</button>}
                    </div>
                    <ul>{items.map(row)}</ul>
                </section>;
            })}
        </div>
    </nav>;
}
