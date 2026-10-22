import { useSyncExternalStore } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleNotch, faXmark } from '@fortawesome/free-solid-svg-icons';
import { clearAgentQueue, getAgentQueue, removeAgentTask, retryAgentTask, subscribeAgentQueue } from '../handlers/agentQueue';

const labels = { assess: 'Assess', review: 'Review', message: 'Message' };

export default function AgentQueue({ id }: Readonly<{ id: string }>) {
    const queue = useSyncExternalStore(subscribeAgentQueue, getAgentQueue);
    const failed = queue.some(item => item.status === 'failed');
    return <section id={id} aria-label="Queued AI actions" className="mx-4 mb-3 shrink-0 overflow-hidden rounded-lg border border-neutral-300 dark:border-neutral-700 dark:bg-neutral-900">
        <div className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
            <span className="font-semibold">AI queue · {queue.filter(item => item.status === 'queued').length} queued</span>
            <button type="button" disabled={!queue.some(item => item.status !== 'running')} onClick={clearAgentQueue} className="text-cyan-700 disabled:opacity-40 dark:text-cyan-400">Clear all</button>
        </div>
        {failed && <p role="status" className="px-3 py-2 text-sm">Queue paused. Retry or remove the failed action to continue.</p>}
        {!queue.length && <p className="px-3 py-3 text-sm text-neutral-500">No AI requests queued.</p>}
        <ol className="scrollbar-minimal max-h-60 overflow-y-auto">
            {queue.map((item, index) => <li key={item.id} className="flex items-start gap-3 border-t border-neutral-200 px-3 py-2 dark:border-neutral-800">
                <span className="mt-1 text-xs tabular-nums">{item.status === 'running' ? <FontAwesomeIcon icon={faCircleNotch} spin /> : index + 1}</span>
                <div className="min-w-0 flex-1">
                    <p className="truncate text-sm" title={`${labels[item.kind]} ${item.title}`}><span className="font-semibold text-cyan-700 dark:text-cyan-300">{labels[item.kind]}</span> {item.title}</p>
                    <p className="text-xs text-neutral-500">{item.source} · {item.status}</p>
                    {item.detail && <p className="truncate text-xs text-neutral-500" title={item.detail}>{item.detail}</p>}
                    {item.error && <p className="mt-1 text-xs text-red-700 dark:text-red-300">{item.error}</p>}
                    {item.status === 'failed' && <button type="button" onClick={() => retryAgentTask(item.id)} className="mt-1 text-sm font-semibold text-cyan-700 dark:text-cyan-400">Retry failed action</button>}
                </div>
                {item.status !== 'running' && <button type="button" aria-label={`Remove ${labels[item.kind].toLowerCase()} ${item.title} from queue`} title="Remove from queue" onClick={() => removeAgentTask(item.id)} className="p-1 text-neutral-500 hover:text-red-600"><FontAwesomeIcon icon={faXmark} /></button>}
            </li>)}
        </ol>
    </section>;
}
