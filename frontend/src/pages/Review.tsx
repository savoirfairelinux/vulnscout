import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import TableGeneric from "../components/TableGeneric";
import Assessments from "../handlers/assessments";
import type { Assessment } from "../handlers/assessments";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion, faCircleInfo, faFileExport, faFileImport } from '@fortawesome/free-solid-svg-icons';

type Props = {
    variantId?: string;
};

const columnHelper = createColumnHelper<Assessment>();

function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
    }) + " " + d.toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
    });
}

function Review({ variantId }: Readonly<Props>) {
    const [assessments, setAssessments] = useState<Assessment[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [search, setSearch] = useState<string>('');
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedJustifications, setSelectedJustifications] = useState<string[]>([]);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [importStatus, setImportStatus] = useState<string | null>(null);
    const searchInputRef = useRef<HTMLInputElement>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const shortcutDropdownRef = useRef<HTMLDivElement>(null);
    const searchHelperButtonRef = useRef<HTMLButtonElement>(null);
    const searchHelperDropdownRef = useRef<HTMLDivElement>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);

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
    ];

    useEffect(() => {
        setLoading(true);
        setError(null);
        Assessments.listReview(variantId)
            .then(data => {
                setAssessments(data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setError("Failed to load review assessments");
                setLoading(false);
            });
    }, [variantId]);

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 550, { maxWait: 2500 });

    useEffect(() => {
        const handleKeyPress = (event: KeyboardEvent) => {
            if (event.target instanceof HTMLInputElement ||
                event.target instanceof HTMLTextAreaElement) {
                return;
            }
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
        };
        if (showShortcutHelper || showSearchHelper) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showShortcutHelper, showSearchHelper]);

    const statusList = useMemo(() => {
        const set = new Set<string>();
        for (const a of assessments) {
            if (a.simplified_status) set.add(a.simplified_status);
        }
        return [...set].sort();
    }, [assessments]);

    const justificationList = useMemo(() => {
        const set = new Set<string>();
        for (const a of assessments) {
            if (a.justification) set.add(a.justification.replace(/_/g, " "));
        }
        return [...set].sort();
    }, [assessments]);

    const resetFilters = () => {
        setSearch('');
        setSelectedStatuses([]);
        setSelectedJustifications([]);
    };

    const handleExportReview = useCallback(() => {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/export", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        window.open(url.toString(), '_blank');
    }, [variantId]);

    const handleImportReview = useCallback(() => {
        fileInputRef.current?.click();
    }, []);

    const handleFileSelected = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/import", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        setImportStatus("Importing...");
        fetch(url.toString(), { method: 'POST', body: formData, mode: 'cors' })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    setImportStatus(`Imported ${data.imported} assessment(s)`);
                    // Reload the assessments list
                    Assessments.listReview(variantId).then(setAssessments);
                } else {
                    setImportStatus(`Error: ${data.error || 'Unknown error'}`);
                }
                setTimeout(() => setImportStatus(null), 4000);
            })
            .catch(err => {
                console.error(err);
                setImportStatus("Import failed");
                setTimeout(() => setImportStatus(null), 4000);
            })
            .finally(() => {
                // Reset file input so the same file can be re-selected
                if (fileInputRef.current) fileInputRef.current.value = '';
            });
    }, [variantId]);

    const columns = useMemo(() => [
        columnHelper.accessor("vuln_id", {
            header: () => <div className="flex items-center justify-center">Vulnerability</div>,
            size: 180,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="font-mono text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
        columnHelper.accessor("packages", {
            header: () => <div className="flex items-center justify-center">SBOM Affected</div>,
            size: 220,
            cell: info => {
                const pkgs = info.getValue();
                if (!pkgs || pkgs.length === 0) return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">—</span></div>;
                return (
                    <div className="flex flex-wrap gap-1 items-center justify-center h-full">
                        {pkgs.map(p => (
                            <span key={p} className="bg-gray-600 text-gray-200 text-xs px-1.5 py-0.5 rounded font-mono">
                                {p}
                            </span>
                        ))}
                    </div>
                );
            },
        }),
        columnHelper.accessor("simplified_status", {
            header: () => <div className="flex items-center justify-center">Status</div>,
            size: 150,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <code>{info.getValue()}</code>
                </div>
            ),
        }),
        columnHelper.accessor("justification", {
            header: () => <div className="flex items-center justify-center">Justification</div>,
            size: 180,
            cell: info => {
                const val = info.getValue();
                return (
                    <div className="flex items-center justify-center h-full">
                        {val
                            ? <span className="text-sm">{val.replace(/_/g, " ")}</span>
                            : <span className="text-gray-500 italic">—</span>}
                    </div>
                );
            },
        }),
        columnHelper.accessor("workaround", {
            header: () => <div className="flex items-center justify-center">Workaround</div>,
            size: 250,
            cell: info => {
                const val = info.getValue();
                return (
                    <div className="flex items-center justify-center h-full">
                        {val
                            ? <span className="text-sm line-clamp-2">{val}</span>
                            : <span className="text-gray-500 italic">—</span>}
                    </div>
                );
            },
        }),
        columnHelper.accessor("impact_statement", {
            header: () => <div className="flex items-center justify-center">Impact</div>,
            size: 250,
            cell: info => {
                const val = info.getValue();
                return (
                    <div className="flex items-center justify-center h-full">
                        {val
                            ? <span className="text-sm line-clamp-2">{val}</span>
                            : <span className="text-gray-500 italic">—</span>}
                    </div>
                );
            },
        }),
        columnHelper.accessor("status_notes", {
            header: () => <div className="flex items-center justify-center">Notes</div>,
            size: 250,
            cell: info => {
                const val = info.getValue();
                return (
                    <div className="flex items-center justify-center h-full">
                        {val
                            ? <span className="text-sm line-clamp-2">{val}</span>
                            : <span className="text-gray-500 italic">—</span>}
                    </div>
                );
            },
        }),
        columnHelper.accessor("timestamp", {
            header: () => <div className="flex items-center justify-center">Assessment Date</div>,
            size: 160,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm text-gray-300">{formatDate(info.getValue())}</span>
                </div>
            ),
        }),
    ], []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="text-center py-10 text-red-400">
                <p>{error}</p>
            </div>
        );
    }

    if (assessments.length === 0) {
        return (
            <div className="text-center py-10 text-gray-400">
                <p className="text-lg">No handmade assessments found</p>
                <p className="text-sm mt-2">
                    Assessments created directly in VulnScout (not imported from SBOM documents) will appear here.
                </p>
            </div>
        );
    }

    const filteredAssessments = assessments.filter((a) => {
        if (selectedStatuses.length && !selectedStatuses.includes(a.simplified_status)) {
            return false;
        }
        if (selectedJustifications.length && !(a.justification && selectedJustifications.includes(a.justification.replace(/_/g, " ")))) {
            return false;
        }
        return true;
    });

    return (
        <div>
            <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
                <div>Search</div>
                <input ref={searchInputRef} onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by vulnerability, package, status, ..." />

                <div className="relative">
                    <button
                        ref={searchHelperButtonRef}
                        aria-label="search syntax helper"
                        title="View search syntax"
                        type="button"
                        className="text-white hover:text-blue-300 transition-colors"
                        onClick={() => setShowSearchHelper(!showSearchHelper)}
                    >
                        <FontAwesomeIcon icon={faCircleInfo} />
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

                <FilterOption
                    label="Status"
                    options={statusList}
                    selected={selectedStatuses}
                    setSelected={setSelectedStatuses}
                />

                <FilterOption
                    label="Justification"
                    options={justificationList}
                    selected={selectedJustifications}
                    setSelected={setSelectedJustifications}
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

                    <button
                        onClick={handleImportReview}
                        className="bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5"
                        title="Import assessments from an OpenVEX file"
                    >
                        <FontAwesomeIcon icon={faFileImport} />
                        Import Review
                    </button>
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".json,application/json"
                        className="hidden"
                        onChange={handleFileSelected}
                    />

                    <button
                        onClick={handleExportReview}
                        className="bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5"
                        title="Export review assessments as OpenVEX"
                    >
                        <FontAwesomeIcon icon={faFileExport} />
                        Export Review
                    </button>
                </div>
            </div>

            {importStatus && (
                <div className="mb-3 px-3 py-2 rounded bg-green-900/50 border border-green-600 text-green-300 text-sm">
                    {importStatus}
                </div>
            )}

            <div className="mb-3 flex items-center justify-between">
                <h2 className="text-lg font-bold text-gray-200">
                    Review Assessments
                    <span className="ml-2 text-sm font-normal text-gray-400">
                        ({filteredAssessments.length} handmade assessment{filteredAssessments.length !== 1 ? "s" : ""})
                    </span>
                </h2>
            </div>
            <TableGeneric<Assessment>
                columns={columns}
                data={filteredAssessments}
                search={search}
                fuseKeys={["vuln_id", "packages", "simplified_status", "status_notes", "justification", "workaround"]}
                estimateRowHeight={50}
                hasPagination={true}
            />
        </div>
    );
}

export default Review;
