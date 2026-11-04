import { useEffect, useState } from 'react';
import ModalShell from './ModalShell';
import DependencyExplorer from './DependencyExplorer';
import { listDependencies } from '../handlers/dependencies';
import type { DependencyDocument } from '../handlers/dependencies';

type Props = {
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
    operation?: string;
    dataRevision?: number;
    packageId: string;
    onClose: () => void;
};

// Opening several packages of the same scope reuses one graph download until the data changes.
let cachedGraph: { key: string; request: Promise<DependencyDocument[]> } | undefined;

function loadGraph(key: string, load: () => Promise<DependencyDocument[]>): Promise<DependencyDocument[]> {
    if (cachedGraph?.key !== key) {
        const request = load();
        request.catch(() => { if (cachedGraph?.request === request) cachedGraph = undefined; });
        cachedGraph = { key, request };
    }
    return cachedGraph.request;
}

export default function DependencyModal({ variantId, projectId, variantIds, compareVariantId, operation, dataRevision,
    packageId, onClose }: Readonly<Props>) {
    const [documents, setDocuments] = useState<DependencyDocument[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');
    const scopeKey = JSON.stringify([variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision]);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        loadGraph(scopeKey, () => listDependencies(variantId, projectId, variantIdsKey?.split(','), compareVariantId, operation))
            .then(result => { if (!cancelled) setDocuments(result); })
            .catch(() => { if (!cancelled) setError('Unable to load dependencies'); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [scopeKey, variantId, projectId, variantIdsKey, compareVariantId, operation, retry]);

    return <ModalShell isOpen title="Package dependencies" size="fullscreen" onClose={onClose}
        testId="dependency-modal" contentClassName="dark flex flex-1 flex-col min-h-0">
        <DependencyExplorer key={scopeKey} documents={documents} focusedPackageId={packageId}
            loading={loading} error={error} onRetry={() => setRetry(value => value + 1)} />
    </ModalShell>;
}
