import { useState, useSyncExternalStore } from 'react';
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
    const operations = useSyncExternalStore(subscribe, getSnapshot);
    const [banner, setBanner] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
    const progress = Object.fromEntries(vulnerabilityRefreshSources.map(({ source }) => [
        source, operations.some(operation => operation.op_id === `refresh:${source}`) ? refreshProgressOf(source) : null,
    ]));

    const clearBanners = () => setBanner(null);
    const action = <RefreshVulnerabilityData {...props}
        nvdProgress={progress.nvd} epssProgress={progress.epss} ghsaProgress={progress.ghsa} euvdProgress={progress.euvd}
        triggerBanner={(message, type) => setBanner({ message, type })} hideBanner={clearBanners} />;

    return <div className="space-y-3">
        <MessageBanner message={banner?.message ?? ''}
            type={banner?.type ?? 'success'}
            isVisible={banner !== null} onClose={clearBanners} />
        {props.toolbar ? <header className="rounded-md p-2 bg-sky-800 text-white w-full flex items-center gap-2 flex-wrap">
            {props.toolbar}
            <div className="ml-auto min-w-0">{action}</div>
        </header> : action}
    </div>;
}
