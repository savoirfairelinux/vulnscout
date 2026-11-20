import { useEffect, useRef, type RefObject } from 'react';
import { AGENT_WRITE_EVENT, type AgentWriteDetail } from '../types/agent';

const detailOf = (event: Event): AgentWriteDetail => {
    const detail = (event as CustomEvent<Partial<AgentWriteDetail> | null>).detail;
    const tools = Array.isArray(detail?.tools) ? detail.tools : detail?.tool ? [detail.tool] : [];
    return { tool: detail?.tool ?? tools[tools.length - 1], tools };
};

const merge = (first: AgentWriteDetail, next: AgentWriteDetail): AgentWriteDetail => {
    const tools = [...first.tools.filter(tool => !next.tools.includes(tool)), ...next.tools];
    return { tool: next.tool ?? first.tool, tools };
};

/**
 * Runs `refresh` on each (already coalesced) agent write announcement, always with the latest
 * `refresh`. When `refresh` returns a promise, announcements arriving before it settles do not start
 * overlapping reloads: they are merged into a single rerun once the running one is done.
 */
export default function useAgentWriteRefresh(
    refresh: (detail: AgentWriteDetail, announcedRevision?: number | null) => unknown,
    revision?: RefObject<number>,
) {
    const refreshRef = useRef(refresh);
    useEffect(() => { refreshRef.current = refresh; });
    useEffect(() => {
        let active = true;
        let running = false;
        let queued: { detail: AgentWriteDetail; announcedRevision?: number | null } | null = null;
        const run = (detail: AgentWriteDetail, announcedRevision?: number | null) => {
            running = true;
            let result: unknown;
            try {
                result = revision ? refreshRef.current(detail, announcedRevision) : refreshRef.current(detail);
            } catch {
                result = undefined;
            }
            void Promise.resolve(result).catch(() => undefined).then(() => {
                running = false;
                if (!active || !queued) return;
                const next = queued;
                queued = null;
                run(next.detail, next.announcedRevision);
            });
        };
        const onWrite = (event: Event) => {
            const detail = detailOf(event);
            const announcedRevision = revision?.current;
            if (running) queued = { detail: queued ? merge(queued.detail, detail) : detail, announcedRevision };
            else run(detail, announcedRevision);
        };
        window.addEventListener(AGENT_WRITE_EVENT, onWrite);
        return () => {
            active = false;
            window.removeEventListener(AGENT_WRITE_EVENT, onWrite);
        };
    }, [revision]);
}
