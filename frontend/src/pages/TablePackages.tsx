import type { Package, VulnCounts, Severities } from "../handlers/packages";
import { createColumnHelper, Row } from '@tanstack/react-table'
import { useMemo, useState, useRef, useEffect } from "react";
import SeverityTag from "../components/SeverityTag";
import TableGeneric from "../components/TableGeneric";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";
import Popup from "../components/Popup";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion } from '@fortawesome/free-solid-svg-icons';

type Props = {
    packages: Package[];
    onShowVulns?: (packageId: string) => void;
};

const addVulnCounts = (counts: VulnCounts, ignore: string[]) => {
    return Object.keys(counts).reduce((acc, key) => {
        if (!ignore.includes(key)) {
            acc += counts[key]
        }
        return acc
    }, 0)
}

const highestSeverity = (severities: Severities, ignore: string[]) => {
    return Object.keys(severities).reduce((acc, key) => {
        if (!ignore.includes(key)) {
            if (severities[key].index > acc.index) {
                return severities[key]
            }
        }
        return acc
    }, {label: 'NONE', index: 0})
}

const sortVunerabilitiesFn = (rowA: Row<Package>, rowB: Row<Package>, ignore: string[]) => {
    const vulnsA = addVulnCounts(rowA.original.vulnerabilities, ignore)
    const vulnsB = addVulnCounts(rowB.original.vulnerabilities, ignore)
    return vulnsA - vulnsB
}

const fuseKeys = ['id', 'name', 'version', 'cpe', 'purl']

function CpeCell({ version, cpe }: { version: string; cpe?: string[] }) {
    const [showCpeBox, setShowCpeBox] = useState(false);
    const buttonRef = useRef<HTMLSpanElement>(null);
    
    return (
        <div className="flex items-center justify-center h-full text-center gap-1">
            <span>{version}</span>
            {cpe && cpe.length > 0 && (
                <>
                    <span 
                        ref={buttonRef}
                        className="cursor-pointer text-blue-400 hover:text-blue-300 px-2 py-0.5 bg-blue-900/30 border border-blue-500/40 rounded text-xs font-semibold" 
                        onClick={() => setShowCpeBox(!showCpeBox)}
                    >
                        CPE
                    </span>
                    <Popup
                        isOpen={showCpeBox}
                        onClose={() => setShowCpeBox(false)}
                        anchorRef={buttonRef}
                        className="!text-base whitespace-normal"
                    >
                        <div className="flex flex-col gap-2">
                            {cpe.map((cpeStr, index) => (
                                <div key={index} className="flex items-center gap-2">
                                    <span className="text-base">{cpeStr}</span>
                                </div>
                            ))}
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setShowCpeBox(false);
                                }}
                                className="text-gray-400 hover:text-white self-end text-base"
                            >
                                ✕
                            </button>
                        </div>
                    </Popup>
                </>
            )}
        </div>
    );
}

function TablePackages({ packages, onShowVulns }: Readonly<Props>) {
    const [showSeverity, setShowSeverity] = useState(false);
    const [search, setSearch] = useState<string>('');
    const [selectedSources, setSelectedSources] = useState<string[]>([]);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const tableRef = useRef<HTMLDivElement>(null); // ref to table container to allow adjustment of filter box height
    const searchInputRef = useRef<HTMLInputElement>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const shortcutDropdownRef = useRef<HTMLDivElement>(null);

    const keyboardShortcuts = [
        { key: '/', description: 'Focus search bar' },
        { key: '↑ / ↓', description: 'Navigate focused table row' },
        { key: 'Home / End', description: 'Navigate to first/last table row' },
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
        };

        if (showShortcutHelper) {
            document.addEventListener('mousedown', handleClickOutside);
        }

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showShortcutHelper]);

    const sources_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        for (const source of pkg.source) {
            if (source != '' && !acc.includes(source))
                acc.push(source)
        }
        return acc;
    }, []), [packages])

    const resetFilters = () => {
        setSearch('');
        setSelectedSources([]);
        setShowSeverity(false);
    }

    const columns = useMemo(() => {
        const columnHelper = createColumnHelper<Package>()
        return [
            columnHelper.accessor('name', {
                header: () => <div className="flex items-center justify-center">Name</div>,
                cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
                footer: info => <div className="flex items-center justify-center h-full">{`Total: ${info.table.getRowCount()}`}</div>
            }),
            columnHelper.accessor('version', {
                header: () => <div className="flex items-center justify-center">Version</div>,
                cell: info => {
                    const version = info.getValue();
                    const cpe = info.row.original.cpe;
                    return <CpeCell version={version} cpe={cpe} />;
                }
            }),
            columnHelper.accessor(
            row => ({ counts: row.vulnerabilities, severity: row.maxSeverity }),
            {
                id: 'vulnerabilities',
                header: () => <div className="flex items-center justify-center">Vulnerabilities</div>,
                cell: info => {
                const value = info.getValue();
                return (
                    <div className="flex items-center justify-center gap-1 h-full text-center">
                    <span>{addVulnCounts(value.counts, [])}</span>
                    {showSeverity && <SeverityTag severity={highestSeverity(value.severity, []).label} />}
                    </div>
                );
                },
                sortingFn: (a, b) => sortVunerabilitiesFn(a, b, [])
            }
            ),
            columnHelper.accessor('source', {
                header: () => <div className="flex items-center justify-center">Sources</div>,
                cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue()?.join(', ')}</div>,
                enableSorting: false
            }),
            columnHelper.accessor(row => row, {
                header: 'Actions',
                cell: info => (
                    <div className="flex items-center justify-center h-full">
                        <button
                            className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
                            onClick={() => onShowVulns?.(info.getValue().id)}
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
    }, [showSeverity, onShowVulns]);

    const filteredPackages = useMemo(() => {
        return packages.filter((el) => {
            if (selectedSources.length && !selectedSources.some(src => el.source.includes(src))) {
                return false;
            }

            return true;
        });
    }, [packages, selectedSources]);

    return (<>
        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input ref={searchInputRef} onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by package name, version, ..." />

            <FilterOption
                label="Source"
                options={sources_list}
                selected={selectedSources}
                setSelected={setSelectedSources}
            />

            <div className="ml-4">
                <ToggleSwitch
                    enabled={showSeverity}
                    setEnabled={setShowSeverity}
                    label="Severity"
                />
            </div>

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
            <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredPackages} estimateRowHeight={57} />
        </div>
    </>);
}

export default TablePackages;
