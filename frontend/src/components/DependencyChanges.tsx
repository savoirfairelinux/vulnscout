import type { DependencyChanges as Changes } from '../handlers/scans';

const unavailable: Record<Exclude<Changes['status'], 'available'>, string> = {
    no_previous_import: 'This is the first import in this variant.',
    incomparable_scope: 'The preceding import has a different SBOM document scope.',
    not_recorded: 'Dependency snapshots were not recorded for one or both imports. Reimport the same SBOM scope twice to establish a baseline.',
    not_applicable: 'Dependency comparison applies only to SBOM imports.',
};

export default function DependencyChanges({ changes }: { changes?: Changes }) {
    const reason = changes && changes.status !== 'available'
        ? unavailable[changes.status]
        : 'Dependency snapshots are unavailable.';

    return (
        <section aria-label="Dependency relationships" className="space-y-2 border-t border-gray-600 pt-4">
            <h3 className="font-semibold">Dependency relationships</h3>
            {changes?.status === 'available' ? (
                <>
                    <p className="text-sm text-gray-400">
                        Package-pair links compared with the preceding import in this variant; independent of package changes.
                    </p>
                    {(['added', 'removed'] as const).map(kind => (
                        <details key={kind} className="rounded border border-gray-600 p-2">
                            <summary className={kind === 'added' ? 'text-green-400 cursor-pointer' : 'text-red-400 cursor-pointer'}>
                                {kind === 'added' ? 'Added relationships' : 'Removed relationships'} ({changes[`${kind}_count`]?.toLocaleString()})
                            </summary>
                            <ul className="max-h-64 overflow-auto text-sm font-mono">
                                {(changes[kind] ?? []).map(edge => (
                                    <li key={`${edge.dependent.package_id}:${edge.dependency.package_id}`} className="py-1">
                                        {edge.dependent.package_name}@{edge.dependent.package_version || '—'}
                                        {' → '}
                                        {edge.dependency.package_name}@{edge.dependency.package_version || '—'}
                                    </li>
                                ))}
                            </ul>
                        </details>
                    ))}
                </>
            ) : (
                <p className="text-sm text-gray-400">
                    No comparable dependency baseline. {reason}
                    {' '}No relationship additions or removals can be inferred.
                </p>
            )}
        </section>
    );
}
