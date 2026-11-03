import { useEffect, useMemo, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFileLines, faMagnifyingGlass } from '@fortawesome/free-solid-svg-icons';
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

type EvidenceFilter = 'all' | 'compiled' | 'build' | 'listed';

const fileKey = (file: SourceFile) => JSON.stringify([
    file.document_id, file.spdx_id, file.variant_id, file.scan_id,
]);

function evidenceKind(file: SourceFile): Exclude<EvidenceFilter, 'all'> {
    return hasCompilationEvidence(file) ? 'compiled' : file.builds.length > 0 ? 'build' : 'listed';
}

function EvidenceBadge({ kind }: Readonly<{ kind: Exclude<EvidenceFilter, 'all'> }>) {
    const styles = {
        compiled: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
        build: 'border-amber-800 bg-amber-950/60 text-amber-200',
        listed: 'border-neutral-600 bg-neutral-800 text-neutral-300',
    };
    const labels = { compiled: 'Compilation recorded', build: 'Other build input', listed: 'Listed only' };
    return <span className={`inline-flex rounded border px-2 py-0.5 text-xs ${styles[kind]}`}>{labels[kind]}</span>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function propertyLabel(key: string): string {
    const label = key.replace(/^software_/, '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ');
    return label.charAt(0).toUpperCase() + label.slice(1);
}

function PropertyValue({ value }: Readonly<{ value: unknown }>) {
    if (value === null || value === undefined || value === '') return <span className="text-neutral-500">Not recorded</span>;
    if (Array.isArray(value)) {
        return value.length > 0
            ? <ul className="space-y-2">{value.map((item, index) =>
                <li key={index}><PropertyValue value={item} /></li>)}</ul>
            : <span className="text-neutral-500">None recorded</span>;
    }
    if (isRecord(value)) {
        return <dl className="space-y-2">{Object.entries(value).map(([key, item]) =>
            <div key={key}>
                <dt className="text-xs text-neutral-400">{propertyLabel(key)}</dt>
                <dd className="whitespace-pre-wrap break-all"><PropertyValue value={item} /></dd>
            </div>)}</dl>;
    }
    return <>{String(value)}</>;
}

function FileDetails({ file }: Readonly<{ file: SourceFile }>) {
    const hashes = [file.properties.verifiedUsing, file.properties.checksums]
        .flatMap(value => Array.isArray(value) ? value.filter(isRecord) : []);
    const properties = Object.entries(file.properties).filter(([key]) =>
        !['name', 'fileName', 'spdxId', 'SPDXID', 'type', 'verifiedUsing', 'checksums', 'creationInfo'].includes(key));

    return <section aria-label="File details" className="min-w-0 space-y-6 p-4 lg:p-6">
        <div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
                <h3 className="text-lg font-semibold text-white">{file.path.split('/').pop() || file.path}</h3>
                <EvidenceBadge kind={evidenceKind(file)} />
            </div>
            <p className="break-all font-mono text-sm text-neutral-300">{file.path}</p>
        </div>
        <dl className="grid gap-4 rounded-lg border border-neutral-700 bg-neutral-950/40 p-4 text-sm sm:grid-cols-2">
            <div><dt className="text-neutral-400">SBOM document</dt><dd className="mt-1 break-all">{file.document_name}</dd></div>
            <div><dt className="text-neutral-400">Variant</dt><dd className="mt-1 break-all">{file.variant_name}</dd></div>
        </dl>
        <section aria-label="File hashes" className="space-y-3">
            <h4 className="font-semibold text-white">Hashes</h4>
            {hashes.length > 0 ? <dl className="space-y-3">{hashes.map((hash, index) => <div key={index}>
                <dt className="text-xs font-semibold uppercase text-neutral-400"><PropertyValue value={hash.algorithm} /></dt>
                <dd className="mt-1 break-all rounded bg-neutral-950/60 p-2 font-mono text-xs">
                    <PropertyValue value={hash.hashValue ?? hash.checksumValue} />
                </dd>
            </div>)}</dl> : <p className="text-sm text-neutral-400">No hashes recorded.</p>}
        </section>
        <section aria-label="Build evidence" className="space-y-3">
            <h4 className="font-semibold text-white">Build evidence</h4>
            <p className="text-sm text-neutral-400">
                {evidenceKind(file) === 'compiled'
                    ? 'A compiler target records this file as an input. This does not prove inclusion in the final firmware.'
                    : evidenceKind(file) === 'build'
                        ? 'This file is an input to a build task, such as a recipe or packaging step. Compilation is not proven.'
                        : 'The SBOM lists this file, but no build task links it to compilation.'}
            </p>
            {file.builds.map((build, index) => {
                const parameters = Array.isArray(build.parameters) ? build.parameters : [];
                return <div key={index} className="space-y-3 rounded-lg border border-neutral-700 p-4 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                        <span className="break-all font-semibold" title={typeof build.spdx_id === 'string' ? build.spdx_id : undefined}>
                            {typeof build.spdx_id === 'string' ? build.spdx_id.split('/').pop() : `Build task ${index + 1}`}
                        </span>
                        <EvidenceBadge kind={build.compiled === true ? 'compiled' : 'build'} />
                    </div>
                    <dl className="space-y-3">
                        {typeof build.build_type === 'string' && <div>
                            <dt className="text-xs text-neutral-400">Build type</dt>
                            <dd className="break-all">{build.build_type}</dd>
                        </div>}
                        {typeof build.document_name === 'string' && <div>
                            <dt className="text-xs text-neutral-400">SBOM document</dt>
                            <dd className="break-all">{build.document_name}</dd>
                        </div>}
                        <div>
                            <dt className="mb-1 text-xs text-neutral-400">Outputs</dt>
                            <dd>{Array.isArray(build.outputs) && build.outputs.length > 0
                                ? <ul className="space-y-1">{build.outputs.map((output, outputIndex) =>
                                    <li key={outputIndex} className="break-all font-mono text-xs"
                                        title={typeof output === 'string' ? output : undefined}>
                                        {typeof output === 'string' ? output.split('/').pop() || output : <PropertyValue value={output} />}
                                    </li>)}</ul>
                                : <span className="text-neutral-400">No outputs recorded.</span>}</dd>
                        </div>
                    </dl>
                    {parameters.length > 0 && <details className="border-t border-neutral-700 pt-3">
                        <summary className="cursor-pointer text-cyan-300">Build parameters ({parameters.length})</summary>
                        <dl className="mt-3 space-y-3">{parameters.map((parameter, parameterIndex) => <div key={parameterIndex}>
                            <dt className="mb-1 break-all text-xs text-neutral-400">
                                {isRecord(parameter) && typeof parameter.key === 'string' ? parameter.key : `Parameter ${parameterIndex + 1}`}
                            </dt>
                            <dd className="whitespace-pre-wrap break-all font-mono text-xs">
                                <PropertyValue value={isRecord(parameter) && 'value' in parameter ? parameter.value : parameter} />
                            </dd>
                        </div>)}</dl>
                    </details>}
                </div>;
            })}
        </section>
        <section aria-label="File properties" className="space-y-3">
            <h4 className="font-semibold text-white">File properties</h4>
            {properties.length > 0 ? <dl className="space-y-4 text-sm">{properties.map(([key, value]) => <div key={key}>
                <dt className="mb-1 text-neutral-400">{propertyLabel(key)}</dt>
                <dd className="whitespace-pre-wrap break-all"><PropertyValue value={value} /></dd>
            </div>)}</dl> : <p className="text-sm text-neutral-400">No additional properties recorded.</p>}
        </section>
        <details className="rounded-lg border border-neutral-700 p-4 text-sm">
            <summary className="cursor-pointer font-semibold">Technical identifiers and original data</summary>
            <dl className="my-4 space-y-3">
                <div><dt className="text-neutral-400">Import scan</dt><dd className="break-all font-mono text-xs">{file.scan_id}</dd></div>
                <div><dt className="text-neutral-400">SPDX ID</dt><dd className="break-all font-mono text-xs">{file.spdx_id}</dd></div>
            </dl>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-neutral-950/60 p-3 text-xs">
                {JSON.stringify({ properties: file.properties, builds: file.builds }, null, 2)}
            </pre>
        </details>
    </section>;
}

export default function SourceFileModal({ packageId, variantId, projectId, variantIds, compareVariantId,
    operation, dataRevision, onClose }: Readonly<Props>) {
    const [files, setFiles] = useState<SourceFile[]>([]);
    const [complete, setComplete] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');
    const [evidence, setEvidence] = useState<EvidenceFilter>('all');
    const [documentId, setDocumentId] = useState('');
    const [selectedKey, setSelectedKey] = useState('');
    const [retry, setRetry] = useState(0);
    const variantIdsKey = variantIds?.join(',');
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        setFiles([]);
        setSearch('');
        setEvidence('all');
        setDocumentId('');
        setSelectedKey('');
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
    const documents = useMemo(() => [...new Map(files.map(file => [
        file.document_id, file.document_name,
    ])).entries()].sort(([, left], [, right]) => left.localeCompare(right)), [files]);
    const visible = useMemo(() => files.filter(file =>
        `${file.path} ${file.document_name} ${file.variant_name}`.toLowerCase().includes(search.trim().toLowerCase())
        && (evidence === 'all' || evidenceKind(file) === evidence)
        && (!documentId || file.document_id === documentId))
        .sort((left, right) => left.path.localeCompare(right.path)
            || left.document_name.localeCompare(right.document_name)
            || left.variant_name.localeCompare(right.variant_name)), [files, search, evidence, documentId]);
    const selected = visible.find(file => fileKey(file) === selectedKey) ?? visible[0];
    const compiledCount = new Set(files.filter(hasCompilationEvidence).map(file => file.path)).size;
    const hasFilters = search !== '' || evidence !== 'all' || documentId !== '';
    const resetFilters = () => { setSearch(''); setEvidence('all'); setDocumentId(''); };
    const controlClass = 'rounded-md border border-neutral-600 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 '
        + 'focus:outline-none focus:ring-2 focus:ring-cyan-500';

    return <ModalShell isOpen title={`Recorded Files: ${packageId}`} size="fullscreen" onClose={onClose}
        subtitle="Explore file provenance and distinguish compilation evidence from listed or recipe inputs."
        icon={<FontAwesomeIcon icon={faFileLines} className="text-cyan-400" />}
        testId="source-file-modal" contentClassName="flex flex-1 flex-col min-h-0">
        <div className="flex flex-col text-neutral-200 lg:min-h-0 lg:flex-1">
            {loading && <p role="status" className="m-auto p-8 text-neutral-400">Loading recorded files...</p>}
            {error && <div role="alert" className="m-auto space-y-4 p-8 text-center">
                <h3 className="font-semibold">Unable to load recorded files</h3>
                <p className="text-sm text-red-300">{error}</p>
                <ModalButton onClick={() => setRetry(value => value + 1)}>Retry</ModalButton>
            </div>}
            {!loading && !error && <>
                <div className="mb-4 flex shrink-0 flex-wrap gap-x-8 gap-y-2 text-sm">
                    <p><strong className="text-xl text-white">{files.length}</strong> recorded files</p>
                    <p><strong className="text-xl text-emerald-300">{compiledCount}</strong> compiled source paths</p>
                    <p><strong className="text-xl text-white">{documents.length}</strong> SBOM documents</p>
                </div>
                <p className={`mb-4 shrink-0 rounded-lg border p-3 text-sm ${complete
                    ? 'border-neutral-700 bg-neutral-800/50 text-neutral-300'
                    : 'border-amber-800/60 bg-amber-950/30 text-amber-200'}`}>
                    {complete
                        ? 'Compiler build records prove which sources were compiled, so CVE matching can skip advisories whose affected files were not compiled. Recorded files may still include patches, licenses, and configuration, and none of this proves inclusion in firmware.'
                        : 'Compilation of these files is not proven, so they are not used to dismiss CVEs: an advisory matches whether or not its affected files appear here. Only compiler build records (Zephyr West SPDX 3) prove compilation; recipe inputs and source lists, including Yocto SPDX_INCLUDE_COMPILED_SOURCES output, do not.'}
                </p>
                {files.length === 0 ? <p className="m-auto p-8 text-neutral-400">
                    No files are recorded for this package in the selected SBOMs.
                </p> : <>
                    <div className="mb-3 flex shrink-0 flex-wrap items-end gap-3">
                        <label className="min-w-[12rem] flex-1">
                            <span className="mb-1 block text-xs text-neutral-400">Search files</span>
                            <span className="relative block">
                                <FontAwesomeIcon icon={faMagnifyingGlass} className="pointer-events-none absolute left-3 top-3 text-neutral-500" />
                                <input aria-label="Filter recorded files" value={search}
                                    onChange={event => setSearch(event.target.value)} placeholder="Path, document, or variant..."
                                    className={`w-full pl-9 ${controlClass}`} />
                            </span>
                        </label>
                        <label>
                            <span className="mb-1 block text-xs text-neutral-400">Build evidence</span>
                            <select aria-label="Filter by build evidence" value={evidence}
                                onChange={event => {
                                    const value = event.target.value;
                                    if (value === 'all' || value === 'compiled' || value === 'build' || value === 'listed') setEvidence(value);
                                }} className={controlClass}>
                                <option value="all">All evidence</option>
                                <option value="compiled">Compilation recorded</option>
                                <option value="build">Other build input</option>
                                <option value="listed">Listed only</option>
                            </select>
                        </label>
                        <label className="min-w-0 max-w-full">
                            <span className="mb-1 block text-xs text-neutral-400">SBOM document</span>
                            <select aria-label="Filter by SBOM document" value={documentId}
                                onChange={event => setDocumentId(event.target.value)} className={`max-w-full ${controlClass}`}>
                                <option value="">All documents</option>
                                {documents.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
                            </select>
                        </label>
                        {hasFilters && <ModalButton onClick={resetFilters}>Clear filters</ModalButton>}
                    </div>
                    <p role="status" className="mb-3 shrink-0 text-xs text-neutral-400">
                        Showing {visible.length} of {files.length} file records
                    </p>
                    {visible.length === 0 ? <div className="m-auto space-y-3 p-8 text-center">
                        <p>No recorded files match these filters.</p>
                        <ModalButton onClick={resetFilters}>Reset filters</ModalButton>
                    </div> : <div className="grid shrink-0 rounded-lg border border-neutral-700 lg:min-h-0 lg:flex-1 lg:shrink lg:grid-cols-[minmax(18rem,2fr)_minmax(0,3fr)] lg:overflow-hidden">
                        <div className="max-h-56 overflow-y-auto border-b border-neutral-700 lg:max-h-none lg:border-b-0 lg:border-r">
                            <ul aria-label="Recorded files">
                                {visible.map(file => <li key={fileKey(file)}>
                                    <button type="button" aria-label={`Inspect ${file.path} in ${file.document_name} (${file.variant_name})`}
                                        aria-pressed={selected && fileKey(selected) === fileKey(file)}
                                        onClick={() => setSelectedKey(fileKey(file))}
                                        className={`w-full border-b border-neutral-800 p-4 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-500 ${selected && fileKey(selected) === fileKey(file)
                                            ? 'bg-cyan-950/50 shadow-[inset_3px_0_0_0] shadow-cyan-400'
                                            : 'hover:bg-neutral-800'}`}>
                                        <span className="mb-2 block break-all font-mono text-sm text-neutral-100">{file.path}</span>
                                        <span className="flex flex-wrap items-center gap-2">
                                            <EvidenceBadge kind={evidenceKind(file)} />
                                            <span className="break-all text-xs text-neutral-400">{file.document_name} / {file.variant_name}</span>
                                        </span>
                                    </button>
                                </li>)}
                            </ul>
                        </div>
                        <div key={selected && fileKey(selected)} className="min-w-0 lg:overflow-y-auto">
                            {selected && <FileDetails file={selected} />}
                        </div>
                    </div>}
                </>}
            </>}
        </div>
    </ModalShell>;
}
