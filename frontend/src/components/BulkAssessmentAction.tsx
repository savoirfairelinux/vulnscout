import { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleNotch, faWandMagicSparkles } from '@fortawesome/free-solid-svg-icons';
import AgentChat, { type QueuedAgentMessage } from './AgentChat';
import type { Vulnerability } from '../handlers/vulnerabilities';
import type { AgentContext } from '../types/agent';
import { buildAiAssessmentMessages, loadAiAssessmentTargets } from '../helpers/aiAssessment';
import { enqueueAgentMessages } from '../handlers/agentQueue';
import useAgentQueue from '../hooks/useAgentQueue';

type BulkMessage = QueuedAgentMessage & { vulnerabilityId: string };
type Props = {
    vulnerabilities: Vulnerability[];
    selectedVulns: string[];
    context: AgentContext;
    disabled?: boolean;
    onError: (message: string) => void;
    onPrepare: () => void;
};

/** The owning bar keys this component by scope; selections do not discard a conversation. */
export default function BulkAssessmentAction({ vulnerabilities, selectedVulns, context, disabled, onError, onPrepare }: Readonly<Props>) {
    const [threadId] = useState(() => crypto.randomUUID());
    const preparation = useRef<AbortController | null>(null);
    const [preparing, setPreparing] = useState(false);
    const [mounted, setMounted] = useState(false);
    const [open, setOpen] = useState(false);
    const queue = useAgentQueue(threadId);
    const running = queue.find(item => item.status === 'running');
    const selectionKey = JSON.stringify([...selectedVulns].sort());
    const activeIds = new Set(queue.flatMap(item => item.context.view?.selectedVulnerabilityIds ?? []));
    const selectionActive = selectedVulns.length > 0 && selectedVulns.every(id => activeIds.has(id));
    const selectionRunning = selectionActive && running?.context.view?.selectedVulnerabilityIds?.some(id => selectedVulns.includes(id));

    useEffect(() => {
        preparation.current?.abort();
        setPreparing(false);
        return () => preparation.current?.abort();
    }, [selectionKey]);

    const assess = async () => {
        if (preparation.current && !preparation.current.signal.aborted) return;
        const controller = new AbortController();
        preparation.current = controller;
        setPreparing(true);
        onPrepare();
        try {
            const selected = selectedVulns.filter(id => !activeIds.has(id)).map(id => {
                const vulnerability = vulnerabilities.find(item => item.id === id);
                if (!vulnerability) throw new Error(`Selected vulnerability ${id} is no longer available. Refresh the table and try again.`);
                return vulnerability;
            });
            const messages: BulkMessage[][] = [];
            // Bound compatibility lookups instead of issuing one concurrent request per selected row.
            let next = 0;
            await Promise.all(Array.from({ length: Math.min(4, selected.length) }, async () => {
                while (next < selected.length) {
                    const index = next++;
                    const vulnerability = selected[index];
                    const targets = await loadAiAssessmentTargets(vulnerability, context, controller.signal);
                    let actions: Omit<QueuedAgentMessage, 'id'>[];
                    try {
                        actions = buildAiAssessmentMessages(vulnerability.id, targets);
                    } catch (error) {
                        throw new Error(`${vulnerability.id}: ${error instanceof Error ? error.message : 'Unable to prepare assessment.'} Open its details to refine the package selection.`);
                    }
                    messages[index] = actions.map(message => ({
                        ...message, id: crypto.randomUUID(), key: `assess:${vulnerability.id}`,
                        vulnerabilityId: vulnerability.id,
                        title: `${vulnerability.id} · ${message.title}`,
                        context: { ...context, view: { ...context.view, selectedVulnerabilityIds: [vulnerability.id], selectionCount: 1 } },
                    }));
                }
            }));
            if (controller.signal.aborted) return;
            enqueueAgentMessages(messages.flat(), context, threadId, 'Bulk assessment chat');
            setMounted(true);
            setOpen(true);
        } catch (error) {
            if (!controller.signal.aborted) {
                onError(error instanceof Error ? error.message : 'Unable to prepare AI assessments. Try again.');
                controller.abort();
            }
        } finally {
            if (preparation.current === controller) {
                preparation.current = null;
                setPreparing(false);
            }
        }
    };

    return <>
        <button
            type="button"
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/10 px-3 py-1.5 text-sm font-semibold text-cyan-50 transition-colors hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-40"
            disabled={disabled || !selectedVulns.length || preparing || selectionActive}
            aria-label={`Assess with AI${preparing ? ' (preparing)' : selectionRunning ? ' (running)' : selectionActive ? ' (queued)' : ''}`}
            aria-controls={mounted ? 'bulk-assessment-agent-panel' : undefined}
            aria-busy={preparing || Boolean(selectionRunning)}
            onClick={() => void assess()}
        >
            <FontAwesomeIcon icon={preparing || selectionRunning ? faCircleNotch : faWandMagicSparkles} spin={preparing || Boolean(selectionRunning)} />
            {preparing ? 'Preparing AI assessments…' : selectionRunning ? 'Assess with AI · Running…' : selectionActive ? 'Assess with AI · Queued' : 'Assess with AI'}
        </button>
        {mounted && <aside id="bulk-assessment-agent-panel" hidden={!open} aria-label="Bulk AI assessment chat"
            className="fixed inset-y-0 right-0 z-50 w-full border-l border-neutral-700 bg-white shadow-2xl sm:w-[min(480px,100%)]">
            <AgentChat threadId={threadId} active={open}
                context={{ ...context, view: { selectedVulnerabilityIds: [...activeIds], selectionCount: activeIds.size } }}
                onClose={() => setOpen(false)}
            />
        </aside>}
    </>;
}
