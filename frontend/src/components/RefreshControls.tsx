import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
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
    toolbar?: ReactNode;
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
    const action = <RefreshVulnerabilityData {...props}
        nvdProgress={progress.nvd} epssProgress={progress.epss} ghsaProgress={progress.ghsa} euvdProgress={progress.euvd}
        triggerBanner={(message, type) => setBanner({ message, type })} hideBanner={clearBanners} />;

    return <div className="space-y-3">
        <MessageBanner message={messages.map(item => item.message).join(' · ')}
            type={messages.some(item => item.type === 'error') ? 'error' : 'success'}
            isVisible={messages.length > 0} onClose={clearBanners} />
        {props.toolbar ? <header className="rounded-md p-2 bg-sky-800 text-white w-full flex items-center gap-2 flex-wrap">
            {props.toolbar}
            <div className="ml-auto min-w-0">{action}</div>
        </header> : action}
    </div>;
}
