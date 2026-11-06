import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import RefreshVulnerabilityData from './RefreshVulnerabilityData';
import MessageBanner from './MessageBanner';
import type { Vulnerability } from '../handlers/vulnerabilities';
import { getSnapshot, refreshProgressOf, subscribe } from '../handlers/operationStore';
import { vulnerabilityRefreshSources } from '../helpers/refreshSources';

type Props = {
    vulnerabilities: Vulnerability[];
    projectId?: string;
    variantId?: string;
    getRefreshVulnerabilities: () => Promise<Vulnerability[]>;
    onRefreshComplete?: () => void;
};

export default function RefreshControls(props: Readonly<Props>) {
    const { onRefreshComplete } = props;
    const operations = useSyncExternalStore(subscribe, getSnapshot);
    const [banner, setBanner] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
    const [sourceBanners, setSourceBanners] = useState<Record<string, { message: string; type: 'success' | 'error' }>>({});
    const previous = useRef(new Map<string, { phase: string; started_at?: string; active: boolean }>());
    const progress = Object.fromEntries(vulnerabilityRefreshSources.map(({ source }) => [
        source, operations.some(operation => operation.op_id === `refresh:${source}`) ? refreshProgressOf(source) : null,
    ]));
    const active = vulnerabilityRefreshSources.flatMap(({ source, label }) => {
        const current = progress[source];
        return current?.in_progress ? [`${label} ${current.current}/${current.total}`] : [];
    });

    useEffect(() => {
        vulnerabilityRefreshSources.forEach(({ source, label }) => {
            const current = operations.some(operation => operation.op_id === `refresh:${source}`) ? refreshProgressOf(source) : null;
            if (!current) return;
            if (current.in_progress) setSourceBanners(previous => {
                if (!previous[source]) return previous;
                const next = { ...previous };
                delete next[source];
                return next;
            });
            const prev = previous.current.get(source);
            const finished = current.phase === 'completed' || current.phase === 'cancelled' || current.phase === 'error';
            if (prev && !current.in_progress && finished &&
                (prev.active || prev.phase !== current.phase || prev.started_at !== current.started_at)) {
                onRefreshComplete?.();
                const cancelled = current.phase === 'cancelled';
                const failed = current.phase === 'error';
                const noun = source === 'ghsa' ? 'advisories' : 'CVEs';
                const count = cancelled ? (current.current > 0 ? ` (${current.current}/${current.total} ${noun})` : '')
                    : (current.total > 0 ? ` (${current.total} ${noun})` : '');
                setSourceBanners(previous => ({ ...previous, [source]: {
                    message: `${label} refresh ${failed ? `failed: ${current.message}` : cancelled ? `cancelled${count}` : `complete${count}`}`,
                    type: cancelled || failed ? 'error' : 'success',
                } }));
            }
            previous.current.set(source, { phase: current.phase, started_at: current.started_at, active: current.in_progress });
        });
    }, [operations, onRefreshComplete]);

    const messages = [...Object.values(sourceBanners), ...(banner ? [banner] : [])];
    const clearBanners = () => { setBanner(null); setSourceBanners({}); };

    return <div className="space-y-3">
        <RefreshVulnerabilityData {...props}
            nvdProgress={progress.nvd} epssProgress={progress.epss} ghsaProgress={progress.ghsa} euvdProgress={progress.euvd}
            triggerBanner={(message, type) => setBanner({ message, type })} hideBanner={clearBanners} />
        {active.length > 0 && <p role="status">{active.join(' · ')}</p>}
        <MessageBanner message={messages.map(item => item.message).join(' · ')}
            type={messages.some(item => item.type === 'error') ? 'error' : 'success'}
            isVisible={messages.length > 0} onClose={clearBanners} />
    </div>;
}
