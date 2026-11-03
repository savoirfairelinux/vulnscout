import { useEffect, useState } from 'react';
import ModalShell from './ModalShell';
import CompilerMetadata from './CompilerMetadata';
import { filterCompilerDocuments, listCompilerMetadata } from '../handlers/dependencies';
import type { CompilerDocument } from '../handlers/dependencies';

type Props = {
    packageId: string;
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
    operation?: string;
    dataRevision?: number;
    sources: string[];
    sbomDocuments: string[];
    onClose: () => void;
};

function CompilerMetadataModal({ packageId, variantId, projectId, variantIds, compareVariantId, operation,
    dataRevision, sources, sbomDocuments, onClose }: Readonly<Props>) {
    const [documents, setDocuments] = useState<CompilerDocument[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        listCompilerMetadata(false, variantId, projectId, variantIdsKey?.split(','), compareVariantId, operation, packageId)
            .then(result => { if (!cancelled) setDocuments(result); })
            .catch(() => { if (!cancelled) setError('Unable to load compiler flags and defines'); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [packageId, variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision, retry]);
    const visible = filterCompilerDocuments(documents, sources, sbomDocuments);
    return <ModalShell isOpen title={`Compiler flags and defines: ${packageId}`} onClose={onClose} size="large">
        {loading ? <p role="status">Loading compiler flags and defines...</p>
            : error ? <div role="alert">{error} <button type="button" onClick={() => setRetry(value => value + 1)}>Retry</button></div>
                : visible.length ? <CompilerMetadata documents={visible} packageId={packageId} />
                    : <p>No compiler flags or defines recorded for the selected scope.</p>}
    </ModalShell>;
}

export default CompilerMetadataModal;
