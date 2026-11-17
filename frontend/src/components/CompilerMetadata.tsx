import type { DependencyDocument } from '../handlers/dependencies';

function CompilerMetadata({ documents, packageId }: Readonly<{
    documents: Pick<DependencyDocument, 'id' | 'source_name' | 'variant_name' | 'build_targets'>[];
    packageId: string;
}>) {
    const sources = documents.flatMap(document => (document.build_targets ?? [])
        .filter(target => target.package_ids.includes(packageId))
        .map(target => ({ document, target })));
    if (!sources.length) return null;
    return <div className="text-sm">
        <p>Declared by the Zephyr SBOM, grouped by build target and language.</p>
        {sources.map(({ document, target }) => <section key={`${document.id}:${target.id}`}
            aria-label={`Build target ${target.name}`} className="my-2 rounded border border-neutral-600 p-3">
            <h3 className="font-semibold">Build target: {target.name}</h3>
            <p className="break-all text-neutral-400">{target.id}</p>
            <p>Source: {document.source_name} · Variant: {document.variant_name}</p>
            {target.languages.map(language => <section key={language.language} aria-label={`Language ${language.language}`}>
                <h4 className="mt-2 font-semibold">Language: {language.language}</h4>
                {(['flags', 'defines'] as const).map(kind => <div key={kind}>
                    <p>{kind === 'flags' ? 'Compiler flags' : 'Compiler defines'}</p>
                    {language[kind].length ? language[kind].map((value, index) =>
                        <pre key={index} className="my-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-neutral-900 p-2">
                            <code>{value}</code>
                        </pre>) : <p className="text-neutral-400">Not recorded</p>}
                </div>)}
            </section>)}
        </section>)}
    </div>;
}

export default CompilerMetadata;
