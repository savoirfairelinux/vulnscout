import type { AssessmentTargetPair } from '../handlers/assessments';
import type { Variant } from '../handlers/variant';
import { formatPkgId } from '../helpers/pkgId';

type Props = {
    variants: Variant[];
    packages: string[];
    variantPackageMap: Record<string, string[]>;
    selectedTargets: AssessmentTargetPair[];
    onChange: (targets: AssessmentTargetPair[]) => void;
};

const pairKey = (variantId: string, pkg: string) => JSON.stringify([variantId, pkg]);

/** Select exact observed (variant, package) pairs without implying a cross-product. */
export default function TargetPairSelector({
    variants, packages, variantPackageMap, selectedTargets, onChange,
}: Readonly<Props>) {
    const selectedKeys = new Set(selectedTargets.flatMap(target =>
        target.variant_id ? [pairKey(target.variant_id, target.package)] : []
    ));

    const compatibleKeys = variants.flatMap(variant => packages.flatMap(pkg =>
        (variantPackageMap[variant.id] ?? []).includes(pkg)
            ? [pairKey(variant.id, pkg)]
            : []
    ));

    const emit = (nextKeys: Set<string>) => {
        onChange(variants.flatMap(variant => packages.flatMap(packageId =>
            nextKeys.has(pairKey(variant.id, packageId))
                ? [{ variant_id: variant.id, package: packageId }]
                : []
        )));
    };

    const setKeys = (keys: string[], checked: boolean) => {
        const nextKeys = new Set(selectedKeys);
        for (const key of keys) {
            if (checked) nextKeys.add(key);
            else nextKeys.delete(key);
        }
        emit(nextKeys);
    };

    const allSelected = (keys: string[]) =>
        keys.length > 0 && keys.every(key => selectedKeys.has(key));

    return (
        <div className="mt-3 rounded-lg border border-gray-600 bg-gray-800/40 p-3">
            <div className="mb-3 flex items-start justify-between gap-3">
                <div>
                    <p className="text-sm font-medium text-gray-200">Apply to exact targets:</p>
                    <p className="text-xs text-gray-400">
                        Select each valid variant and package pair independently.
                    </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                    <span className="text-xs text-gray-400">{selectedKeys.size} selected</span>
                    <button
                        type="button"
                        disabled={compatibleKeys.length === 0}
                        onClick={() => setKeys(compatibleKeys, true)}
                        className="rounded border border-blue-500/60 px-2 py-1 text-xs text-blue-200 hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                        Select all
                    </button>
                    <button
                        type="button"
                        disabled={selectedKeys.size === 0}
                        onClick={() => emit(new Set())}
                        className="rounded border border-gray-600 px-2 py-1 text-xs text-gray-300 hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                        Deselect all
                    </button>
                </div>
            </div>
            <div className="overflow-x-auto rounded border border-gray-700">
                <table className="w-full border-collapse text-sm">
                    <thead className="bg-gray-900/50 text-gray-300">
                        <tr>
                            <th className="sticky left-0 bg-gray-900 px-3 py-2 text-left font-medium">Variant</th>
                            {packages.map(pkg => {
                                const packageKeys = variants.flatMap(variant =>
                                    (variantPackageMap[variant.id] ?? []).includes(pkg)
                                        ? [pairKey(variant.id, pkg)]
                                        : []
                                );
                                const selected = allSelected(packageKeys);
                                return (
                                    <th key={pkg} className="min-w-36 px-3 py-2 text-center font-medium">
                                        <div className="font-mono">{formatPkgId(pkg)}</div>
                                        <button
                                            type="button"
                                            disabled={packageKeys.length === 0}
                                            onClick={() => setKeys(packageKeys, !selected)}
                                            aria-label={`${selected ? 'Deselect' : 'Select'} all for package ${formatPkgId(pkg)}`}
                                            className="mt-1 text-xs font-normal text-cyan-300 hover:text-cyan-200 disabled:cursor-not-allowed disabled:text-gray-600"
                                        >
                                            {selected ? 'Deselect column' : 'Select column'}
                                        </button>
                                    </th>
                                );
                            })}
                        </tr>
                    </thead>
                    <tbody>
                        {variants.map(variant => {
                            const variantKeys = packages.flatMap(pkg =>
                                (variantPackageMap[variant.id] ?? []).includes(pkg)
                                    ? [pairKey(variant.id, pkg)]
                                    : []
                            );
                            const rowSelected = allSelected(variantKeys);
                            return (<tr key={variant.id} className="border-t border-gray-700">
                                <th className="sticky left-0 bg-gray-800 px-3 py-2 text-left font-medium text-gray-200">
                                    <div>{variant.name}</div>
                                    <button
                                        type="button"
                                        disabled={variantKeys.length === 0}
                                        onClick={() => setKeys(variantKeys, !rowSelected)}
                                        aria-label={`${rowSelected ? 'Deselect' : 'Select'} all for variant ${variant.name}`}
                                        className="mt-1 text-xs font-normal text-cyan-300 hover:text-cyan-200 disabled:cursor-not-allowed disabled:text-gray-600"
                                    >
                                        {rowSelected ? 'Deselect row' : 'Select row'}
                                    </button>
                                </th>
                                {packages.map(pkg => {
                                    const compatible = (variantPackageMap[variant.id] ?? []).includes(pkg);
                                    const selected = selectedKeys.has(pairKey(variant.id, pkg));
                                    return (
                                        <td key={pkg} className="px-3 py-2 text-center">
                                            <label
                                                className={[
                                                    'inline-flex min-w-24 items-center justify-center gap-2 rounded border px-2 py-1.5 transition-colors',
                                                    selected
                                                        ? 'border-blue-400 bg-blue-500/20 text-blue-100'
                                                        : 'border-gray-600 bg-gray-700/60 text-gray-300',
                                                    compatible
                                                        ? 'cursor-pointer hover:border-gray-400'
                                                        : 'cursor-not-allowed opacity-35',
                                                ].join(' ')}
                                                title={compatible
                                                    ? `Apply to ${variant.name} and ${formatPkgId(pkg)}`
                                                    : 'This package is not available in this variant'}
                                            >
                                                <input
                                                    type="checkbox"
                                                    aria-label={`${variant.name} / ${formatPkgId(pkg)}`}
                                                    checked={selected}
                                                    disabled={!compatible}
                                                    onChange={event => setKeys(
                                                        [pairKey(variant.id, pkg)], event.target.checked)}
                                                    className="h-4 w-4 accent-blue-500"
                                                />
                                                <span>{compatible ? (selected ? 'Selected' : 'Select') : 'Unavailable'}</span>
                                            </label>
                                        </td>
                                    );
                                })}
                            </tr>);
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
