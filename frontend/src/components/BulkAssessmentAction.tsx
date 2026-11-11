import { useEffect, useRef, useState } from 'react';
import type { Vulnerability } from '../handlers/vulnerabilities';
import type { AgentAction, AgentContext } from '../types/agent';
import { bulkAssessmentKeyPrefix, loadAiAssessmentTargets } from '../helpers/aiAssessment';
import { ACTIONS_PER_REQUEST, agentActionState, enqueueAgentActions, openAgentChat } from '../handlers/agentQueue';
import useAgentQueue from '../hooks/useAgentQueue';
import { agentErrorMessage } from '../handlers/agent';
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
    const activeIds = new Set(queue.flatMap(item => item.context?.view?.selectedVulnerabilityIds ?? []));
    const selectionActive = selectedVulns.length > 0 && selectedVulns.every(id => activeIds.has(id));
    const selectionState = selectionActive ? agentActionState(agentQueue, item => item.key.startsWith(keyPrefix) &&
        (item.context?.view?.selectedVulnerabilityIds?.some(id => selectedVulns.includes(id)) ?? false)) : undefined;

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
            const actions: AgentAction[] = [];
            // Bound compatibility lookups instead of issuing one concurrent request per selected row.
            let next = 0;
            await Promise.all(Array.from({ length: Math.min(4, selected.length) }, async () => {
                while (next < selected.length) {
                    const index = next++;
                    const vulnerability = selected[index];
                    const targets = await loadAiAssessmentTargets(vulnerability, context, controller.signal);
                    actions[index] = {
                        kind: 'assess', vuln_id: vulnerability.id, targets, key: `${keyPrefix}${vulnerability.id}`,
                        context: { ...context, view: { ...context.view, selectedVulnerabilityIds: [vulnerability.id], selectionCount: 1 } },
                    };
                }
            }));
            if (controller.signal.aborted) return;
            let first: string | undefined;
            for (let start = 0; start < actions.length; start += ACTIONS_PER_REQUEST) {
                // Stopped by a selection change or unmount: keep what was accepted, submit no more.
                if (controller.signal.aborted) return;
                const batch = actions.slice(start, start + ACTIONS_PER_REQUEST);
                let submitted;
                try {
                    submitted = await enqueueAgentActions(batch, { conversation: 'per-action', source: BULK_SOURCE, context });
                } catch (error) {
                    if (!(error instanceof Error) || error instanceof TypeError) throw new Error(agentErrorMessage(error));
                    const message = error.message;
                    const subject = batch.length === 1 && batch[0].kind === 'assess' ? `${batch[0].vuln_id}: ` : '';
                    throw new Error(`${subject}${message} Open its details to refine the package selection.`);
                }
                first ??= submitted.requests[0]?.id ?? submitted.skipped[0]?.request_id;
            }
            if (controller.signal.aborted) return;
            openAgentChat(selectedVulns.length > 1 ? undefined : first, selectedVulns.length > 1 ? 'conversations' : 'chat');
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
        openView={selectedVulns.length > 1 ? 'conversations' : 'chat'}
        label="Assess with AI"
        onRun={() => void assess()}
        disabled={disabled || !selectedVulns.length}
        title="Assess each selected vulnerability with AI in its own conversation"
        preparing={preparing ? 'Preparing AI assessments…' : undefined}
        className="inline-flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/10 px-3 py-1.5 text-sm font-semibold text-cyan-50 transition-colors hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-40"
    />;
}
