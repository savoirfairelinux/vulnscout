import { useEffect, useRef, useState } from 'react';
import type { Vulnerability } from '../handlers/vulnerabilities';
import type { AgentContext, QueuedAgentMessage } from '../types/agent';
import { buildAiAssessmentMessages, bulkAssessmentKeyPrefix, loadAiAssessmentTargets } from '../helpers/aiAssessment';
import { agentActionState, enqueueAgentMessages, openAgentChat } from '../handlers/agentQueue';
import useAgentQueue from '../hooks/useAgentQueue';
import AgentActionButton from './AgentActionButton';

const BULK_SOURCE = 'Vulnerability selection';

type Props = {
    vulnerabilities: Vulnerability[];
    selectedVulns: string[];
    context: AgentContext;
    disabled?: boolean;
    onError: (message: string) => void;
    onPrepare: () => void;
};

/** Queues one agent conversation per selected vulnerability and opens the chat; the owning bar keys this component by scope. */
export default function BulkAssessmentAction({ vulnerabilities, selectedVulns, context, disabled, onError, onPrepare }: Readonly<Props>) {
    const preparation = useRef<AbortController | null>(null);
    const [preparing, setPreparing] = useState(false);
    // Scope the dedupe key so the same CVE can still be assessed from another table scope.
    const keyPrefix = bulkAssessmentKeyPrefix(context);
    const agentQueue = useAgentQueue();
    const queue = agentQueue.filter(item => item.key.startsWith(keyPrefix));
    const selectionKey = JSON.stringify([...selectedVulns].sort());
    const activeIds = new Set(queue.flatMap(item => item.context.view?.selectedVulnerabilityIds ?? []));
    const selectionActive = selectedVulns.length > 0 && selectedVulns.every(id => activeIds.has(id));
    const selectionState = selectionActive ? agentActionState(agentQueue, item => item.key.startsWith(keyPrefix) &&
        (item.context.view?.selectedVulnerabilityIds?.some(id => selectedVulns.includes(id)) ?? false)) : undefined;

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
            const messages: QueuedAgentMessage[][] = [];
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
                        ...message, id: crypto.randomUUID(), key: `${keyPrefix}${vulnerability.id}`,
                        title: `${vulnerability.id} · ${message.title}`,
                        context: { ...context, view: { ...context.view, selectedVulnerabilityIds: [vulnerability.id], selectionCount: 1 } },
                    }));
                }
            }));
            if (controller.signal.aborted) return;
            const queued = messages.flat();
            enqueueAgentMessages(queued, context, BULK_SOURCE, 'per-action');
            openAgentChat(queued[0]?.id);
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

    return <AgentActionButton
        state={selectionState}
        label="Assess with AI"
        onRun={() => void assess()}
        disabled={disabled || !selectedVulns.length}
        title="Assess each selected vulnerability with AI in its own conversation"
        preparing={preparing ? 'Preparing AI assessments…' : undefined}
        className="inline-flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/10 px-3 py-1.5 text-sm font-semibold text-cyan-50 transition-colors hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-40"
    />;
}
