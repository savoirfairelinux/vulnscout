import type { Package, VulnCounts } from "../handlers/packages";
import { createColumnHelper, Row } from '@tanstack/react-table'
import { useMemo, useState, useRef, useEffect, useCallback } from "react";
import TableGeneric from "../components/TableGeneric";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faC, faCircleQuestion, faCircleInfo, faBook } from '@fortawesome/free-solid-svg-icons';
import { useDocUrl } from '../helpers/useDocUrl';
import { extractSupplierName } from '../helpers/pkgId';
import { formatSourceName, getOriginalSourceName } from '../helpers/sourceNames';
import type { Vulnerability } from '../handlers/vulnerabilities';
import Vulnerabilities from '../handlers/vulnerabilities';
import MessageBanner from '../components/MessageBanner';

type Props = {
    packages: Package[];
    vulnerabilities?: Vulnerability[];
    onShowVulns?: (packageId: string, matchingVulnerabilityIds?: string[]) => void;
    onLoadOutdatedPackages?: () => Promise<Package[]>;
};

const addVulnCounts = (counts: VulnCounts, ignore: string[]) => {
    return Object.keys(counts).reduce((acc, key) => {
        if (!ignore.includes(key)) {
            acc += counts[key]
        }
        return acc
    }, 0)
}

const sortVunerabilitiesFn = (rowA: Row<Package>, rowB: Row<Package>, ignore: string[]) => {
    const vulnsA = addVulnCounts(rowA.original.vulnerabilities, ignore)
    const vulnsB = addVulnCounts(rowB.original.vulnerabilities, ignore)
    return vulnsA - vulnsB
}

const fuseKeys = ['id', 'name', 'version', 'cpe', 'purl']

function TablePackages({ packages, vulnerabilities = [], onShowVulns, onLoadOutdatedPackages }: Readonly<Props>) {
    const docUrl = useDocUrl("interactive-mode.html#sbom-table");
    const [search, setSearch] = useState<string>('');
    const [selectedSources, setSelectedSources] = useState<string[]>([]);
    const [selectedSbomDocs, setSelectedSbomDocs] = useState<string[]>([]);
    const [selectedSuppliers, setSelectedSuppliers] = useState<string[]>([]);
    const [showOnlyOutdated, setShowOnlyOutdated] = useState(false);
    const [packagesWithOutdated, setPackagesWithOutdated] = useState<Package[] | null>(null);
    const [outdatedLoading, setOutdatedLoading] = useState(false);
    const [outdatedLoadError, setOutdatedLoadError] = useState('');
    const [matchCondition, setMatchCondition] = useState('');
    const [matchingVulnerabilityIds, setMatchingVulnerabilityIds] = useState<string[] | null>(null);
    const [matchConditionError, setMatchConditionError] = useState('');
    // Track variants the user has explicitly unchecked. All variants (including
    // any discovered later) are considered selected unless present here, which
    // avoids a first-render flash where variant rows briefly disappear.
    const [deselectedVariants, setDeselectedVariants] = useState<string[]>([]);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [showMatchConditionHelper, setShowMatchConditionHelper] = useState(false);
    const tableRef = useRef<HTMLDivElement>(null); // ref to table container to allow adjustment of filter box height
    const searchInputRef = useRef<HTMLInputElement>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const shortcutDropdownRef = useRef<HTMLDivElement>(null);
    const searchHelperButtonRef = useRef<HTMLButtonElement>(null);
    const searchHelperDropdownRef = useRef<HTMLDivElement>(null);
    const matchConditionHelperButtonRef = useRef<HTMLButtonElement>(null);
    const matchConditionHelperDropdownRef = useRef<HTMLDivElement>(null);

    const keyboardShortcuts = [
        { key: '/', description: 'Focus search bar' },
        { key: '↑ / ↓', description: 'Navigate focused table row' },
        { key: 'Home / End', description: 'Navigate to first/last table row' },
    ];

    const searchSyntaxHelp = [
        { syntax: 'term', description: 'Match rows containing term' },
        { syntax: 'term1 term2', description: 'AND: both terms must match' },
        { syntax: 'term1 | term2', description: 'OR: either term matches' },
        { syntax: '-term', description: 'NOT: exclude rows with term' },
        { syntax: 'only:text', description: 'Show only packages whose name contains text (e.g. only:native)' },
    ];

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 550, { maxWait: 2500 });

    useEffect(() => {
        const handleKeyPress = (event: KeyboardEvent) => {
            // Only trigger if not typing in an input/textarea
            if (event.target instanceof HTMLInputElement ||
                event.target instanceof HTMLTextAreaElement) {
                return;
            }

            // Bind "/" to focus search input
            if (event.key === "/") {
                event.preventDefault();
                searchInputRef.current?.focus();
            }
        };

        document.addEventListener('keydown', handleKeyPress);
        return () => document.removeEventListener('keydown', handleKeyPress);
    }, []);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (
                shortcutDropdownRef.current &&
                shortcutButtonRef.current &&
                !shortcutDropdownRef.current.contains(event.target as Node) &&
                !shortcutButtonRef.current.contains(event.target as Node)
            ) {
                setShowShortcutHelper(false);
            }
            if (
                searchHelperDropdownRef.current &&
                searchHelperButtonRef.current &&
                !searchHelperDropdownRef.current.contains(event.target as Node) &&
                !searchHelperButtonRef.current.contains(event.target as Node)
            ) {
                setShowSearchHelper(false);
            }
            if (
                matchConditionHelperDropdownRef.current &&
                matchConditionHelperButtonRef.current &&
                !matchConditionHelperDropdownRef.current.contains(event.target as Node) &&
                !matchConditionHelperButtonRef.current.contains(event.target as Node)
            ) {
                setShowMatchConditionHelper(false);
            }
        };

        if (showShortcutHelper || showSearchHelper || showMatchConditionHelper) {
            document.addEventListener('mousedown', handleClickOutside);
        }

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showShortcutHelper, showSearchHelper, showMatchConditionHelper]);

    const sources_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        for (const source of pkg.source) {
            if (source != '' && !acc.includes(source))
                acc.push(source)
        }
        return acc;
    }, []), [packages])

    const sources_display_list = useMemo(
        () => sources_list.map(formatSourceName),
        [sources_list]
    );

    const hasSupplierInfo = useMemo(() => packages.some(pkg => !!pkg.supplier), [packages]);

    const defaultVisibleColumns = useMemo(() => {
        const cols = ['Name', 'Version', 'Vulnerabilities', 'Variants', 'Sources'];
        if (hasSupplierInfo) cols.splice(cols.indexOf('Vulnerabilities'), 0, 'Supplier');
        return cols;
    }, [hasSupplierInfo]);

    const [visibleColumns, setVisibleColumns] = useState<string[]>(defaultVisibleColumns);

    const matchingVulnerabilityCounts = useMemo(() => {
        const counts = new Map<string, number>();
        if (matchingVulnerabilityIds === null) return counts;

        const matchingIds = new Set(matchingVulnerabilityIds);
        vulnerabilities
            .filter(vulnerability => matchingIds.has(vulnerability.id))
            .forEach(vulnerability => {
                vulnerability.packages_current.forEach(packageId => {
                    counts.set(packageId, (counts.get(packageId) ?? 0) + 1);
                });
            });
        return counts;
    }, [matchingVulnerabilityIds, vulnerabilities]);

    const sbom_docs_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        for (const doc of pkg.sbom_documents) {
            if (doc !== '' && !acc.includes(doc))
                acc.push(doc);
        }
        return acc.sort();
    }, []), [packages])

    const suppliers_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        const name = extractSupplierName(pkg.supplier);
        if (name !== '' && !acc.includes(name))
            acc.push(name);
        return acc.sort();
    }, []), [packages])

    const variants_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        for (const variant of pkg.variants) {
            if (variant !== '' && !acc.includes(variant))
                acc.push(variant);
        }
        return acc.sort();
    }, []), [packages])

    // All variants are checked by default; a variant only leaves the selection
    // once the user explicitly unchecks it. Deriving the selection during render
    // (instead of populating it from an effect) prevents a first-render flash.
    const selectedVariants = useMemo(
        () => variants_list.filter(v => !deselectedVariants.includes(v)),
        [variants_list, deselectedVariants]
    );
    const setSelectedVariants = useCallback((values: string[]) => {
        setDeselectedVariants(variants_list.filter(v => !values.includes(v)));
    }, [variants_list]);

    // Matched IDs are a snapshot of a server-side evaluation; drop them whenever
    // the vulnerability data changes so the filter never shows stale results.
    useEffect(() => {
        setMatchingVulnerabilityIds(null);
        setMatchConditionError('');
    }, [vulnerabilities]);

    useEffect(() => {
        if (!showOnlyOutdated || packagesWithOutdated !== null || !onLoadOutdatedPackages) return;
        let cancelled = false;
        setOutdatedLoading(true);
        setOutdatedLoadError('');
        onLoadOutdatedPackages()
            .then(loaded => {
                if (!cancelled) setPackagesWithOutdated(loaded);
            })
            .catch(() => {
                if (!cancelled) setOutdatedLoadError('Unable to load outdated findings');
            })
            .finally(() => {
                if (!cancelled) setOutdatedLoading(false);
            });
        return () => { cancelled = true; };
    }, [showOnlyOutdated, packagesWithOutdated, onLoadOutdatedPackages]);

    const applyMatchCondition = async () => {
        const condition = matchCondition.trim();
        if (!condition) {
            setMatchingVulnerabilityIds(null);
            setMatchConditionError('');
            return;
        }
        setMatchConditionError('');
        try {
            setMatchingVulnerabilityIds(await Vulnerabilities.matchCondition(condition, vulnerabilities));
        } catch (error) {
            setMatchingVulnerabilityIds(null);
            setMatchConditionError(error instanceof Error ? error.message : 'Unable to evaluate match condition');
        }
    };

    const resetFilters = () => {
        setSearch('');
        setSelectedSources([]);
        setSelectedSbomDocs([]);
        setSelectedSuppliers([]);
        setSelectedVariants(variants_list);
        setMatchCondition('');
        setMatchingVulnerabilityIds(null);
        setMatchConditionError('');
        setShowOnlyOutdated(false);
        setVisibleColumns(defaultVisibleColumns);
    }

    const columnDisplayNames = useMemo(() => ({
        'name': 'Name',
        'version': 'Version',
        'cpe': 'CPE',
        'purl': 'PURL',
        'supplier': 'Supplier',
        'vulnerabilities': 'Vulnerabilities',
        'variants': 'Variants',
        'source': 'Sources',
        'actions': 'Actions',
    }), []);

    const allColumns = useMemo(() => {
        const columnHelper = createColumnHelper<Package>()
        return [
            columnHelper.accessor('name', {
                id: 'name',
                header: () => <div className="flex items-center justify-center">Name</div>,
                cell: info => (
                    <div className="flex items-center justify-center gap-2 h-full text-center">
                        <span>{info.getValue()}</span>
                        {info.row.original.outdated && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-900 text-amber-200">Outdated</span>
                        )}
                    </div>
                ),
                footer: info => <div className="flex items-center justify-center h-full">{`Total: ${info.table.getRowCount()}`}</div>,
                size: 300
            }),
            columnHelper.accessor('version', {
                id: 'version',
                header: () => <div className="flex items-center justify-center">Version</div>,
                cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
                size: 80
            }),
            columnHelper.accessor('cpe', {
                id: 'cpe',
                header: () => <div className="flex items-center justify-center">CPE</div>,
                cell: info => {
                    const cpeList = info.getValue();
                    if (!cpeList || cpeList.length === 0) return <div className="flex items-center justify-center h-full text-neutral-500">—</div>;
                    return (
                        <div className="flex items-center justify-center h-full">
                            <div className="flex flex-col gap-1 justify-center min-w-0 w-full">
                                {cpeList.map((c: string, i: number) => (
                                    <span key={i} title={c} className="block px-2 py-0.5 rounded-full text-xs font-mono bg-sky-900 text-sky-300 max-w-full truncate">{c}</span>
                                ))}
                            </div>
                        </div>
                    );
                },
                enableSorting: false,
                size: 200
            }),
            columnHelper.accessor('purl', {
                id: 'purl',
                header: () => <div className="flex items-center justify-center">PURL</div>,
                cell: info => {
                    const purls = info.getValue();
                    if (!purls || purls.length === 0) return <div className="flex items-center justify-center h-full text-neutral-500">—</div>;
                    return (
                        <div className="flex items-center justify-center h-full">
                            <div className="flex flex-col gap-1 justify-center min-w-0 w-full">
                                {purls.map((p: string, i: number) => (
                                    <span key={i} title={p} className="block px-2 py-0.5 rounded-full text-xs font-mono bg-cyan-900 text-cyan-300 max-w-full truncate">{p}</span>
                                ))}
                            </div>
                        </div>
                    );
                },
                enableSorting: false,
                size: 200
            }),
            columnHelper.accessor('supplier', {
                id: 'supplier',
                header: () => <div className="flex items-center justify-center">Supplier</div>,
                cell: info => {
                    const supplier = info.getValue();
                    if (!supplier) return (
                        <div className="flex items-center justify-center h-full text-neutral-500">—</div>
                    );
                    return (
                        <div className="flex items-center justify-center h-full text-center text-sm" title={supplier}>
                            {extractSupplierName(supplier)}
                        </div>
                    );
                },
                size: 200,
            }),
            columnHelper.accessor(
            row => row.vulnerabilities,
            {
                id: 'vulnerabilities',
                header: () => <div className="flex items-center justify-center">Vulnerabilities</div>,
                cell: info => {
                const value = info.getValue();
                const matchedCount = matchingVulnerabilityCounts.get(info.row.original.id);
                return (
                    <div className="flex items-center justify-center gap-1 h-full text-center">
                    {matchingVulnerabilityIds !== null ? (
                        <span
                            className="inline-flex items-center rounded-full bg-amber-200 px-2.5 py-0.5 text-xs font-medium text-amber-900 dark:bg-amber-700 dark:text-amber-100"
                            title={`${matchedCount ?? 0} vulnerabilities match this condition`}
                            aria-label={`${matchedCount ?? 0} vulnerabilities match this condition`}
                        >
                            <span className="mr-1.5 inline-flex items-center rounded-full bg-amber-100 px-1.5 py-0.5 font-semibold text-amber-800 dark:bg-amber-900 dark:text-amber-300">
                                <FontAwesomeIcon icon={faC} aria-hidden="true" />
                            </span>
                            {matchedCount ?? 0}
                        </span>
                    ) : <span>{addVulnCounts(value, [])}</span>}
                    </div>
                );
                },
                sortingFn: (a, b) => sortVunerabilitiesFn(a, b, []),
                size: 50
            }
            ),
            columnHelper.accessor('variants', {
                id: 'variants',
                header: () => <div className="flex items-center justify-center">Variants</div>,
                cell: info => (
                    <div className="flex items-center justify-center h-full">
                        <div className="flex flex-wrap gap-1 justify-center">
                            {info.getValue().map((name: string) => (
                                <span key={name} className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-900 text-green-300">
                                    {name}
                                </span>
                            ))}
                        </div>
                    </div>
                ),
                enableSorting: false,
                size: 120
            }),
            columnHelper.accessor('source', {
                id: 'source',
                header: () => <div className="flex items-center justify-center">Sources</div>,
                cell: info => (
                    <div className="flex items-center justify-center h-full text-center">
                        {info.getValue()?.map(formatSourceName).join(', ')}
                    </div>
                ),
                enableSorting: false
            }),
            columnHelper.accessor('sbom_documents', {
                header: () => <div className="flex items-center justify-center">SBOM Source File</div>,
                cell: info => {
                    const docs = info.getValue();
                    if (!docs || docs.length === 0)
                        return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">—</span></div>;
                    return (
                        <div className="flex flex-wrap gap-1 items-center justify-center h-full">
                            {docs.map(doc => (
                                <span key={doc} className="bg-gray-600 text-gray-200 text-xs px-1.5 py-0.5 rounded font-mono">
                                    {doc}
                                </span>
                            ))}
                        </div>
                    );
                },
                enableSorting: false,
                size: 220,
            }),
            columnHelper.accessor(row => row, {
                id: 'actions',
                header: 'Actions',
                cell: info => (
                    <div className="flex items-center justify-center h-full">
                        <button
                            className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
                            onClick={() => {
                                const packageRow = info.getValue();
                                const packageId = packageRow.id;
                                if (matchingVulnerabilityIds) {
                                    onShowVulns?.(packageId, matchingVulnerabilityIds);
                                } else if (packageRow.findingVulnerabilityIds?.length) {
                                    onShowVulns?.(packageId, packageRow.findingVulnerabilityIds);
                                } else {
                                    onShowVulns?.(packageId);
                                }
                            }}
                            >
                            Show Vulnerabilities
                        </button>
                    </div>
                ),
                enableSorting: false,
                minSize: 10,
                size: 10
            })
        ]
    }, [onShowVulns, matchingVulnerabilityIds, matchingVulnerabilityCounts]);

    const columns = useMemo(() => {
        return allColumns.filter(col => {
            const colId = col.id as string;
            if (colId === 'actions') return true;
            const displayName = columnDisplayNames[colId as keyof typeof columnDisplayNames];
            return displayName && visibleColumns.includes(displayName);
        });
    }, [allColumns, visibleColumns, columnDisplayNames]);

    const filteredPackages = useMemo(() => {
        const availablePackages = showOnlyOutdated
            ? (packagesWithOutdated ?? packages)
            : packages;
        let matchedPackageIds: Set<string> | null = null;
        if (matchingVulnerabilityIds !== null) {
            const matchingIds = new Set(matchingVulnerabilityIds);
            matchedPackageIds = new Set(vulnerabilities
                .filter(vulnerability => matchingIds.has(vulnerability.id))
                .flatMap(vulnerability => vulnerability.packages_current));
        }
        return availablePackages.filter((el) => {
            if (showOnlyOutdated ? !el.outdated : el.outdated) return false;
            if (matchedPackageIds && !matchedPackageIds.has(el.id)) return false;
            if (selectedSources.length && !selectedSources.some(src => el.source.includes(src))) {
                return false;
            }
            if (selectedSbomDocs.length && !selectedSbomDocs.some(doc => el.sbom_documents.includes(doc))) {
                return false;
            }
            if (selectedSuppliers.length && !selectedSuppliers.includes(extractSupplierName(el.supplier))) {
                return false;
            }
            if (el.variants.length && !selectedVariants.some(variant => el.variants.includes(variant))) {
                return false;
            }
            return true;
        });
    }, [packages, packagesWithOutdated, onLoadOutdatedPackages, vulnerabilities, showOnlyOutdated, matchingVulnerabilityIds, selectedSources, selectedSbomDocs, selectedSuppliers, selectedVariants]);

    return (<>
        {showOnlyOutdated && outdatedLoading && (
            <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40" role="status" aria-live="polite">
                <div className="flex flex-col items-center gap-3 text-white">
                    <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin" aria-hidden="true"></div>
                    <span className="text-sm font-semibold">Loading outdated packages…</span>
                </div>
            </div>
        )}
        {matchConditionError && (
            <MessageBanner
                type="error"
                message={matchConditionError}
                isVisible={true}
                onClose={() => setMatchConditionError('')}
            />
        )}
                {outdatedLoadError && (
                    <MessageBanner
                        type="error"
                        message={outdatedLoadError}
                        isVisible={true}
                        onClose={() => setOutdatedLoadError('')}
                    />
                )}
        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input ref={searchInputRef} onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by package name, version, ..." />

            <div className="relative">
                <button
                    ref={searchHelperButtonRef}
                    aria-label="search syntax helper"
                    title="View search syntax"
                    type="button"
                    className="text-white hover:text-blue-300 transition-colors"
                    onClick={() => setShowSearchHelper(!showSearchHelper)}
                >
                    <FontAwesomeIcon icon={faCircleQuestion} />
                </button>
                {showSearchHelper && (
                    <div
                        ref={searchHelperDropdownRef}
                        className="absolute left-0 top-full mt-1 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-4 z-50 w-[400px] text-sm"
                    >
                        <h3 className="font-bold text-white mb-3">Search Syntax</h3>
                        <div className="space-y-2">
                            {searchSyntaxHelp.map((item, index) => (
                                <div key={index} className="flex justify-between gap-4">
                                    <code className="text-cyan-300 min-w-[100px]">{item.syntax}</code>
                                    <span className="text-gray-100">{item.description}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            <label htmlFor="sbom-match-condition" className="ml-2">Match condition</label>
            <input
                id="sbom-match-condition"
                value={matchCondition}
                onChange={event => setMatchCondition(event.target.value)}
                onKeyDown={event => { if (event.key === 'Enter') void applyMatchCondition(); }}
                className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[260px]"
                placeholder="cvss >= 7 and pending"
                aria-invalid={matchConditionError ? 'true' : 'false'}
            />
            <div className="relative">
                <button
                    ref={matchConditionHelperButtonRef}
                    aria-label="match condition help"
                    aria-expanded={showMatchConditionHelper}
                    aria-controls="match-condition-help"
                    title="View match condition help"
                    type="button"
                    className="text-white hover:text-blue-300 transition-colors"
                    onClick={() => setShowMatchConditionHelper(!showMatchConditionHelper)}
                >
                    <FontAwesomeIcon icon={faCircleInfo} />
                </button>
                {showMatchConditionHelper && (
                    <div
                        id="match-condition-help"
                        ref={matchConditionHelperDropdownRef}
                        className="absolute right-0 top-full mt-1 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-4 z-50 w-[360px] text-sm"
                    >
                        <h3 className="font-bold text-white mb-2">Match condition</h3>
                        <div className="space-y-2 text-gray-100">
                            <p>Filter packages by vulnerability facts. Press Enter to apply the condition.</p>
                            <p><code className="text-cyan-300">field operator value</code> with <code className="text-cyan-300">==</code>, <code className="text-cyan-300">!=</code>, <code className="text-cyan-300">&lt;</code>, <code className="text-cyan-300">&gt;</code>, <code className="text-cyan-300">&lt;=</code>, or <code className="text-cyan-300">&gt;=</code>. Combine conditions with <code className="text-cyan-300">and</code>, <code className="text-cyan-300">or</code>, <code className="text-cyan-300">not</code>, and parentheses.</p>
                            <p>Facts: <code className="text-cyan-300">cvss</code>, <code className="text-cyan-300">cvss_min</code>, <code className="text-cyan-300">epss</code>, <code className="text-cyan-300">effort</code>, <code className="text-cyan-300">effort_min</code>, <code className="text-cyan-300">effort_max</code>, <code className="text-cyan-300">fixed</code>, <code className="text-cyan-300">ignored</code>, <code className="text-cyan-300">affected</code>, <code className="text-cyan-300">pending</code>, and <code className="text-cyan-300">new</code>.</p>
                            <p>Examples: <code className="text-cyan-300">cvss &gt;= 7 and pending</code>; <code className="text-cyan-300">epss &gt;= 10% or fixed</code>.</p>
                        </div>
                    </div>
                )}
            </div>

            <FilterOption
                label="Columns"
                options={[
                    'Name',
                    'Version',
                    'CPE',
                    'PURL',
                    'Supplier',
                    'Vulnerabilities',
                    'Variants',
                    'Sources',
                ]}
                selected={visibleColumns}
                setSelected={setVisibleColumns}
            />

            {hasSupplierInfo && (
                <FilterOption
                    label="Supplier"
                    options={suppliers_list}
                    selected={selectedSuppliers}
                    setSelected={setSelectedSuppliers}
                />
            )}

            <FilterOption
                label="Source"
                options={sources_display_list}
                selected={selectedSources.map(formatSourceName)}
                setSelected={(displayNames) => setSelectedSources(displayNames.map(getOriginalSourceName))}
            />

            <FilterOption
                label="SBOM Source File"
                options={sbom_docs_list}
                selected={selectedSbomDocs}
                setSelected={setSelectedSbomDocs}
            />

            {variants_list.length > 0 && (
                <FilterOption
                    label="Variants"
                    options={variants_list}
                    selected={selectedVariants}
                    setSelected={setSelectedVariants}
                />
            )}

            <ToggleSwitch
                enabled={showOnlyOutdated}
                setEnabled={setShowOnlyOutdated}
                label="Outdated"
            />

            <div className="ml-auto flex items-center gap-2 relative">
                <button
                    ref={shortcutButtonRef}
                    aria-label="shortcut helper"
                    title="View keyboard shortcuts"
                    type="button"
                    className="text-white hover:text-blue-300 transition-colors"
                    onClick={() => setShowShortcutHelper(!showShortcutHelper)}
                >
                    <FontAwesomeIcon icon={faCircleQuestion} />
                </button>
                <a
                    href={docUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="documentation"
                    title="Open documentation"
                    className="text-white hover:text-blue-300 transition-colors"
                >
                    <FontAwesomeIcon icon={faBook} />
                </a>
                {showShortcutHelper && (
                    <div
                        ref={shortcutDropdownRef}
                        className="absolute top-full mt-1 right-0 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-4 z-50 w-[400px] text-sm"
                    >
                        <h3 className="font-bold text-white mb-3">Keyboard Shortcuts</h3>
                        <div className="space-y-2 text-gray-100">
                            {keyboardShortcuts.map((shortcut, index) => (
                                <div key={index} className="flex justify-between">
                                    <span className="font-semibold text-cyan-300">{shortcut.key}</span>
                                    <span>{shortcut.description}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <button
                    onClick={resetFilters}
                    className="bg-sky-900 hover:bg-sky-950 px-3 py-1 rounded text-white border border-sky-700"
                >
                    Reset Filters
                </button>
            </div>
        </div>

        <div ref={tableRef}>
            <TableGeneric fuseKeys={fuseKeys} forAllValues={(pkg) => [pkg.name]} search={search} columns={columns} data={filteredPackages} estimateRowHeight={57} />
        </div>
    </>);
}

export default TablePackages;
