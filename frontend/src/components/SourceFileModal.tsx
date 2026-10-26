import { useEffect, useMemo, useState } from 'react';
import Packages, { hasCompilationEvidence, type SourceFile } from '../handlers/packages';
import ModalShell, { ModalButton } from './ModalShell';

type Props = {
    packageId: string;
    variantId?: string;
    projectId?: string;
    variantIds?: string[];
    compareVariantId?: string;
    operation?: string;
    dataRevision?: number;
    onClose: () => void;
};

export default function SourceFileModal({ packageId, variantId, projectId, variantIds, compareVariantId,
    operation, dataRevision, onClose }: Readonly<Props>) {
    const [files, setFiles] = useState<SourceFile[]>([]);
    const [complete, setComplete] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        setFiles([]);
        setSearch('');
        Packages.sourceFiles(packageId, variantId, projectId, variantIdsKey?.split(','), compareVariantId, operation)
            .then(result => {
                if (!cancelled) {
                    setFiles(result.files);
                    setComplete(result.complete);
                }
            })
            .catch(reason => {
                if (!cancelled) setError(reason instanceof Error ? reason.message : 'Unable to load recorded files');
            })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [packageId, variantId, projectId, variantIdsKey, compareVariantId, operation, dataRevision, retry]);
    const visible = useMemo(() => files.filter(file =>
        `${file.path} ${file.document_name}`.toLowerCase().includes(search.toLowerCase())), [files, search]);

    return <ModalShell isOpen title={`Recorded Files: ${packageId}`} size="wide" onClose={onClose}
        testId="source-file-modal">
        <div className="space-y-4 p-4 text-neutral-200">
            {loading && <p role="status">Loading recorded files...</p>}
            {error && <div role="alert">
                <p>{error}</p>
                <ModalButton onClick={() => setRetry(value => value + 1)}>Retry</ModalButton>
            </div>}
            {!loading && !error && <>
                <p>Recorded files: {files.length}; compiled source files: {files.filter(hasCompilationEvidence).length}.</p>
                <p className="text-sm text-neutral-400">
                    Recorded files may include source code, patches, licenses, and configuration files.
                    Listing alone does not prove compilation or inclusion in the final firmware.
                    {!complete && ' Evidence is incomplete or unproven; compiled-source CVE refinement is disabled.'}
                </p>
                <input aria-label="Filter recorded files" value={search} onChange={event => setSearch(event.target.value)}
                    placeholder="Filter by path or SBOM document" className="w-full rounded bg-neutral-800 p-2" />
                {files.length === 0 && <p>No files are recorded for this package in the selected SBOMs.</p>}
                {files.length > 0 && visible.length === 0 && <p>No recorded files match this filter.</p>}
                <div className="space-y-2">
                    {visible.map(file => <details key={`${file.document_id}:${file.spdx_id}`}
                        className="rounded border border-neutral-700 p-3">
                        <summary className="cursor-pointer break-all">
                            <span className="font-mono">{file.path}</span>
                            <span className="ml-3 text-sm text-cyan-300">
                                {hasCompilationEvidence(file) ? 'Build input'
                                    : file.builds.length > 0 ? 'Recipe input (not compilation)' : 'Listed only'}
                            </span>
                        </summary>
                        <dl className="mt-3 space-y-1 break-all text-sm">
                            <dt className="font-semibold">SBOM document</dt><dd>{file.document_name}</dd>
                            <dt className="font-semibold">Variant</dt><dd>{file.variant_name}</dd>
                            <dt className="font-semibold">Import scan</dt><dd>{file.scan_id}</dd>
                            <dt className="font-semibold">SPDX ID</dt><dd>{file.spdx_id}</dd>
                        </dl>
                        <h3 className="mt-3 font-semibold">Parsed file properties</h3>
                        <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
                            {JSON.stringify(file.properties, null, 2)}
                        </pre>
                        <h3 className="mt-3 font-semibold">Build associations</h3>
                        <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
                            {JSON.stringify(file.builds, null, 2)}
                        </pre>
                    </details>)}
                </div>
            </>}
        </div>
    </ModalShell>;
}
