import type { PackageVersionMetadata } from '../helpers/packageVersions';
import { versionEvidenceTitle } from '../helpers/packageVersions';

function SourceRevision({ source_revision: revision, revision_conflict: conflict, version_evidence }: Readonly<
    PackageVersionMetadata
>) {
    const title = versionEvidenceTitle({ version_evidence });
    if (conflict) return <span title={title} className="text-amber-300">Conflicting metadata</span>;
    if (!revision) return <span className="text-neutral-500">—</span>;

    return <span title={`${revision}${title ? `\n${title}` : ''}`} className="font-mono">
        {revision.slice(0, 12)}
    </span>;
}

export default SourceRevision;
