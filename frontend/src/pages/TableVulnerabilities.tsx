import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import type { Facets } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import type { NVDProgress } from "../handlers/nvd_progress";
import type { EPSSProgress } from "../handlers/epss_progress";
import Vulnerabilities from "../handlers/vulnerabilities";
import { createColumnHelper, SortingFn, RowSelectionState, Row, Table, SortingState } from '@tanstack/react-table'
import { useMemo, useState, useEffect, useCallback, useRef } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import MultiEditBar from "../components/MultiEditBar";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";

import MessageBanner from "../components/MessageBanner";
import NVDProgressHandler from "../handlers/nvd_progress";
import EPSSProgressHandler from "../handlers/epss_progress";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTimes, faFilter, faCaretDown, faCircleQuestion, faSync, faCircleInfo } from '@fortawesome/free-solid-svg-icons';
import RangeSlider from "../components/RangeSlider";

type Props = {
    variantId?: string;
    projectId?: string;
    /** Origin variant when compare mode is active */
    baseVariantId?: string;
    /** 'difference' or 'intersection' when compare mode is active */
    compareOperation?: string;
    filterLabel?: "Source" | "Severity" | "Status" | "Package";
    filterValue?: string;
};

const dt_options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    timeZoneName: 'shortOffset'
};

const sortSeverityFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const vulnsA = rowA.original.severity.severity.toUpperCase()
    const vulnsB = rowB.original.severity.severity.toUpperCase()
    return SEVERITY_ORDER.indexOf(vulnsA) - SEVERITY_ORDER.indexOf(vulnsB)
}

const sortSeverityByScoreFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const scoreA = rowA.original.severity.max_score || 0;
    const scoreB = rowB.original.severity.max_score || 0;
    return scoreA - scoreB;
}

const sortStatusFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const indexA = ['unknown', 'Pending Assessment', 'Exploitable', 'Not affected', 'Fixed'].indexOf(rowA.original.simplified_status)
    const indexB = ['unknown', 'Pending Assessment', 'Exploitable', 'Not affected', 'Fixed'].indexOf(rowB.original.simplified_status)
    return indexA - indexB
}

const sortAttackVectorFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const av_A = [...(new Set(
        rowA.original.severity.cvss.map(cvss => cvss.attack_vector)
    ))]
    const av_B = [...(new Set(
        rowB.original.severity.cvss.map(cvss => cvss.attack_vector)
    ))]
    const priorities = [undefined, 'PHYSICAL', 'LOCAL', 'ADJACENT', 'NETWORK']
    const indexA = Math.max(...av_A.map(a => priorities.indexOf(a)))
    const indexB = Math.max(...av_B.map(b => priorities.indexOf(b)))
    return indexA - indexB
}

const fuseKeys = [
    'id',
    'packages',
    'texts.content'
]

type PublishedDateFilterProps = {
    filterType: string;
    dateValue: string;
    daysValue: string;
    dateFrom: string;
    dateTo: string;
    setFilterType: (value: string) => void;
    setDateValue: (value: string) => void;
    setDaysValue: (value: string) => void;
    setDateFrom: (value: string) => void;
    setDateTo: (value: string) => void;
    nvdProgress: NVDProgress | null;
};

function PublishedDateFilter({
    filterType, dateValue, daysValue, dateFrom, dateTo,
    setFilterType, setDateValue, setDaysValue, setDateFrom, setDateTo,
    nvdProgress
}: Readonly<PublishedDateFilterProps>) {
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);

    const isDisabled = !nvdProgress || nvdProgress.in_progress || nvdProgress.phase !== 'completed';
    const hasActiveFilter = filterType !== '' && (dateValue || daysValue || (dateFrom && dateTo));

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };

        if (isOpen) {
            document.addEventListener("mousedown", handleClickOutside);
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [isOpen]);

    const clearFilters = () => {
        setFilterType('');
        setDateValue('');
        setDaysValue('');
        setDateFrom('');
        setDateTo('');
    };

    return (
        <div ref={dropdownRef} className="ml-4 relative inline-block text-left">
            <button
                onClick={() => !isDisabled && setIsOpen(!isOpen)}
                disabled={isDisabled}
                className={`py-1 px-2 rounded flex items-center gap-1 ${
                    isDisabled
                        ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                        : isOpen
                        ? 'bg-sky-950'
                        : 'bg-sky-900 hover:bg-sky-950'
                } text-white`}
                title={isDisabled ? 'NVD sync in progress' : 'Filter by published date'}
            >
                Published Date
                {hasActiveFilter && <span className="ml-1 bg-sky-700 px-1 rounded text-xs">✓</span>}
                <FontAwesomeIcon icon={faCaretDown} />
            </button>

            {isOpen && (
                <div className="absolute mt-1 w-72 bg-sky-900 text-white border border-sky-800 rounded-md shadow-lg z-50">
                    <div className="p-3 space-y-3">
                        <div>
                            <label htmlFor="published-date-filter-type" className="block text-sm font-semibold mb-1">Filter Type:</label>
                            <select
                                id="published-date-filter-type"
                                value={filterType}
                                onChange={(e) => {
                                    setFilterType(e.target.value);
                                    setDateValue('');
                                    setDaysValue('');
                                    setDateFrom('');
                                    setDateTo('');
                                }}
                                className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                            >
                                <option value="">Select filter type...</option>
                                <option value="is">Is</option>
                                <option value=">=">On or after</option>
                                <option value="<=">On or before</option>
                                <option value="between">Between</option>
                                <option value="days_ago">Less than X days ago</option>
                            </select>
                        </div>

                        {filterType === 'is' && (
                            <div>
                                <label htmlFor="published-date-is" className="block text-sm font-semibold mb-1">Date:</label>
                                <input
                                    id="published-date-is"
                                    type="date"
                                    value={dateValue}
                                    onChange={(e) => setDateValue(e.target.value)}
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {filterType === '>=' && (
                            <div>
                                <label htmlFor="published-date-gte" className="block text-sm font-semibold mb-1">On or after:</label>
                                <input
                                    id="published-date-gte"
                                    type="date"
                                    value={dateValue}
                                    onChange={(e) => setDateValue(e.target.value)}
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {filterType === '<=' && (
                            <div>
                                <label htmlFor="published-date-lte" className="block text-sm font-semibold mb-1">On or before:</label>
                                <input
                                    id="published-date-lte"
                                    type="date"
                                    value={dateValue}
                                    onChange={(e) => setDateValue(e.target.value)}
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {filterType === 'between' && (
                            <>
                                <div>
                                    <label htmlFor="published-date-from" className="block text-sm font-semibold mb-1">From:</label>
                                    <input
                                        id="published-date-from"
                                        type="date"
                                        value={dateFrom}
                                        onChange={(e) => setDateFrom(e.target.value)}
                                        className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                    />
                                </div>
                                <div>
                                    <label htmlFor="published-date-to" className="block text-sm font-semibold mb-1">To:</label>
                                    <input
                                        id="published-date-to"
                                        type="date"
                                        value={dateTo}
                                        onChange={(e) => setDateTo(e.target.value)}
                                        className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                    />
                                </div>
                            </>
                        )}

                        {filterType === 'days_ago' && (
                            <div>
                                <label htmlFor="published-date-days" className="block text-sm font-semibold mb-1">Number of days:</label>
                                <input
                                    id="published-date-days"
                                    type="number"
                                    min="1"
                                    value={daysValue}
                                    onChange={(e) => setDaysValue(e.target.value)}
                                    placeholder="e.g., 30"
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {hasActiveFilter && (
                            <button
                                onClick={clearFilters}
                                className="w-full px-2 py-1 text-sm bg-red-700 hover:bg-red-800 text-white rounded"
                            >
                                Clear Filter
                            </button>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
const SEVERITY_RANGE_MIN = 0;
const SEVERITY_RANGE_MAX = 10;

function TableVulnerabilities ({ variantId, projectId, filterLabel, filterValue, baseVariantId, compareOperation }: Readonly<Props>) {

    const [pageItems, setPageItems] = useState<Vulnerability[]>([]);
    const [serverTotal, setServerTotal] = useState(0);
    const [facets, setFacets] = useState<Facets>({ severities: [], statuses: [], sources: [], attack_vectors: [], first_scan_dates: [] });
    const [page, setPage] = useState(0); // 0-indexed
    const [pageSize, setPageSize] = useState(50);
    const [serverSorting, setServerSorting] = useState<SortingState>([]);
    const [isLoadingVulns, setIsLoadingVulns] = useState(false);
    const [modalVuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
    const [modalVulnSnapshot, setModalVulnSnapshot] = useState<Vulnerability[]>([]);
    const [isEditing, setIsEditing] = useState<boolean>(false);
    const [search, setSearch] = useState<string>('');
    const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedSources, setSelectedSources] = useState<string[]>([]);
    const [selectedPackages, setSelectedPackages] = useState<string[]>([]);
    const [publishedDateFilterType, setPublishedDateFilterType] = useState<string>('');
    const [publishedDateValue, setPublishedDateValue] = useState<string>('');
    const [publishedDaysValue, setPublishedDaysValue] = useState<string>('');
    const [publishedDateFrom, setPublishedDateFrom] = useState<string>('');
    const [publishedDateTo, setPublishedDateTo] = useState<string>('');
    const [nvdProgress, setNvdProgress] = useState<NVDProgress | null>(null);
    const [epssProgress, setEpssProgress] = useState<EPSSProgress | null>(null);
    const [selectedRows, setSelectedRows] = useState<RowSelectionState>({});
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);
    const [searchFilteredData, setSearchFilteredData] = useState<Vulnerability[]>([]);
    const [visibleColumns, setVisibleColumns] = useState<string[]>([
        'ID', 'Severity', 'EPSS Score', 'SBOM Affected', 'Variants', 'Status', 'Last Updated', 'Published Date'
    ]);
    const [focusedRowIndex, setFocusedRowIndex] = useState<number | null>(null);

    const [showCustomSeverityFilter, setShowCustomSeverityFilter] = useState<boolean>(false);
    const [severityRange, setSeverityRange] = useState<{ min: number; max: number }>({ min: SEVERITY_RANGE_MIN, max: SEVERITY_RANGE_MAX });
    const [showCustomEpssFilter, setShowCustomEpssFilter] = useState<boolean>(false);
    const [epssRange, setEpssRange] = useState<{ min: number; max: number }>({ min: 0, max: 100 });
    const [selectedAttackVectors, setSelectedAttackVectors] = useState<string[]>([]);
    const [selectedFirstScanDates, setSelectedFirstScanDates] = useState<string[]>([]);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [showMoreFilters, setShowMoreFilters] = useState(false);

    const searchInputRef = useRef<HTMLInputElement>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const shortcutDropdownRef = useRef<HTMLDivElement>(null);
    const searchHelperButtonRef = useRef<HTMLButtonElement>(null);
    const searchHelperDropdownRef = useRef<HTMLDivElement>(null);
    const moreFiltersRef = useRef<HTMLDivElement>(null);

    const keyboardShortcuts = [
        { key: '/', description: 'Focus search bar' },
        { key: 'e', description: 'Edit focused vulnerability' },
        { key: 'v', description: 'View vulnerability details' },
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
        if (!filterLabel || !filterValue) return;
        if (filterLabel === "Source") setSelectedSources([filterValue]);
        if (filterLabel === "Severity") setSelectedSeverities([filterValue]);
        if (filterLabel === "Status") setSelectedStatuses([filterValue]);
        if (filterLabel === "Package") setSelectedPackages([filterValue]);
    }, [filterLabel, filterValue]);

    // Fetch a page of vulnerabilities with server-side filtering/sorting
    const abortRef = useRef<AbortController | null>(null);

    const fetchPage = useCallback((requestedPage?: number) => {
        abortRef.current?.abort();
        const controller = new AbortController();
        abortRef.current = controller;

        setIsLoadingVulns(true);
        const compareVariantId = baseVariantId ? variantId : undefined;
        const effectiveVariantId = baseVariantId || variantId;

        const sortCol = serverSorting[0];
        Vulnerabilities.listPaginated({
            variantId: effectiveVariantId,
            projectId,
            compareVariantId,
            operation: compareOperation,
            page: (requestedPage ?? page) + 1, // API is 1-indexed
            pageSize,
            sortBy: sortCol?.id,
            sortDir: sortCol ? (sortCol.desc ? 'desc' : 'asc') : undefined,
            search: search || undefined,
            severity: selectedSeverities.length ? selectedSeverities : undefined,
            simplifiedStatus: selectedStatuses.length ? selectedStatuses : undefined,
            foundBy: selectedSources.length ? selectedSources : undefined,
            packages: selectedPackages.length ? selectedPackages : undefined,
            epssMin: showCustomEpssFilter ? epssRange.min : undefined,
            epssMax: showCustomEpssFilter ? epssRange.max : undefined,
            severityMin: showCustomSeverityFilter ? severityRange.min : undefined,
            severityMax: showCustomSeverityFilter ? severityRange.max : undefined,
            attackVector: selectedAttackVectors.length ? selectedAttackVectors : undefined,
            publishedDateFilter: publishedDateFilterType || undefined,
            publishedDateValue: publishedDateValue || undefined,
            publishedDateFrom: publishedDateFrom || undefined,
            publishedDateTo: publishedDateTo || undefined,
            publishedDaysValue: publishedDaysValue || undefined,
            firstScanDate: selectedFirstScanDates.length ? selectedFirstScanDates : undefined,
            signal: controller.signal,
        })
            .then(res => {
                setPageItems(res.items);
                setServerTotal(res.total);
                setFacets(res.facets);
            })
            .catch(err => { if (err.name !== 'AbortError') console.error('Failed to load vulnerabilities', err); })
            .finally(() => setIsLoadingVulns(false));
    }, [variantId, projectId, baseVariantId, compareOperation, page, pageSize,
        serverSorting, search, selectedSeverities, selectedStatuses, selectedSources,
        selectedPackages, showCustomEpssFilter, epssRange, showCustomSeverityFilter,
        severityRange, selectedAttackVectors, publishedDateFilterType,
        publishedDateValue, publishedDateFrom, publishedDateTo, publishedDaysValue,
        selectedFirstScanDates]);

    // Re-fetch when any dependency changes
    useEffect(() => { fetchPage(); }, [fetchPage]);

    // Reset to page 0 when filters change (but not when page itself changes)
    const filterDepsRef = useRef<string>('');
    useEffect(() => {
        const key = JSON.stringify([
            search, selectedSeverities, selectedStatuses, selectedSources,
            selectedPackages, showCustomEpssFilter, epssRange,
            showCustomSeverityFilter, severityRange, selectedAttackVectors,
            publishedDateFilterType, publishedDateValue, publishedDateFrom,
            publishedDateTo, publishedDaysValue, selectedFirstScanDates,
        ]);
        if (filterDepsRef.current && filterDepsRef.current !== key) {
            setPage(0);
        }
        filterDepsRef.current = key;
    }, [search, selectedSeverities, selectedStatuses, selectedSources,
        selectedPackages, showCustomEpssFilter, epssRange,
        showCustomSeverityFilter, severityRange, selectedAttackVectors,
        publishedDateFilterType, publishedDateValue, publishedDateFrom,
        publishedDateTo, publishedDaysValue, selectedFirstScanDates]);

    const appendAssessment = useCallback((added: Assessment) => {
        setPageItems(prev => Vulnerabilities.append_assessment(prev, added));
    }, []);

    const appendCVSS = useCallback((vulnId: string, vector: string): CVSS | null => {
        const cvss = Vulnerabilities.calculate_cvss_from_vector(vector) ?? null;
        if (cvss !== null) {
            setPageItems(prev => Vulnerabilities.append_cvss(prev, vulnId, cvss));
        }
        return cvss;
    }, []);

    const patchVuln = useCallback((vulnId: string, replace_vuln: Vulnerability) => {
        setPageItems(prev => prev.map(v => v.id === vulnId ? replace_vuln : v));
    }, []);

    // Fetch NVD progress on mount and periodically
    useEffect(() => {
        const fetchNvdProgress = async () => {
            try {
                const progress = await NVDProgressHandler.getProgress();
                setNvdProgress(progress);
            } catch (error) {
                console.error('Failed to fetch NVD progress:', error);
            }
        };

        fetchNvdProgress();
        const interval = setInterval(fetchNvdProgress, 5000); // Poll every 5 seconds

        return () => clearInterval(interval);
    }, []);

    // Fetch EPSS progress on mount and periodically
    useEffect(() => {
        const fetchEpssProgress = async () => {
            try {
                const progress = await EPSSProgressHandler.getProgress();
                setEpssProgress(progress);
            } catch (error) {
                console.error('Failed to fetch EPSS progress:', error);
            }
        };

        fetchEpssProgress();
        const interval = setInterval(fetchEpssProgress, 5000); // Poll every 5 seconds

        return () => clearInterval(interval);
    }, []);

    const triggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 750, { maxWait: 5000 });

    const updateCustomSeverityFilter = debounce((value: { min: number; max: number }) => {
        setSeverityRange(value);
    }, 750, { maxWait: 5000 });

    const updateCustomEpssFilter = debounce((value: { min: number; max: number }) => {
        setEpssRange(value);
    }, 750, { maxWait: 5000 });

    const attack_vector_list = useMemo(() => {
        const order = ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'];
        return [...facets.attack_vectors].sort((a, b) => order.indexOf(a) - order.indexOf(b));
    }, [facets.attack_vectors]);

    // Build list of distinct first-scan timestamps from facets
    const availableFirstScanDates = useMemo(() => {
        return facets.first_scan_dates;
    }, [facets.first_scan_dates]);

    const formatScanDate = useCallback((ts: number) => {
        const d = new Date(ts);
        return d.toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
        }) + ' ' + d.toLocaleTimeString(undefined, {
            hour: '2-digit',
            minute: '2-digit',
            timeZoneName: 'short',
        });
    }, []);

    const sources_list = useMemo(() => facets.sources, [facets.sources])

    const sources_display_list = useMemo(
        () =>
            sources_list.map(source =>
                source === 'openvex'
                    ? 'OpenVex'
                    : source === 'local_user_data'
                    ? 'Local User Data'
                    : source === 'yocto'
                    ? 'Yocto'
                    : source === 'grype'
                    ? 'Grype'
                    : source === 'cyclonedx'
                    ? 'CycloneDx'
                    : source === 'spdx3'
                    ? 'SPDX3'
                    : source
            ),
        [sources_list]
    );

    const formatSourceName = (source: string) =>
        source === 'openvex'
            ? 'OpenVex'
            : source === 'local_user_data'
            ? 'Local User Data'
            : source === 'yocto'
            ? 'Yocto'
            : source === 'grype'
            ? 'Grype'
            : source === 'cyclonedx'
            ? 'CycloneDx'
            : source === 'spdx3'
            ? 'SPDX3'
            : source;

    const getOriginalSourceName = (displayName: string) =>
        displayName === 'OpenVex'
            ? 'openvex'
            : displayName === 'Yocto'
            ? 'yocto'
            : displayName === 'Local User Data'
            ? 'local_user_data'
            : displayName === 'Grype'
            ? 'grype'
            : displayName === 'CycloneDx'
            ? 'cyclonedx'
            : displayName === 'SPDX3'
            ? 'spdx3'
            : displayName;

    const handleEditClick = useCallback((vuln: Vulnerability) => {
        const index = searchFilteredData.findIndex(v => v.id === vuln.id);
        setModalVuln(vuln);
        setModalVulnIndex(index >= 0 ? index : undefined);
        setModalVulnSnapshot([...searchFilteredData]); // Capture snapshot at modal open time
    }, [searchFilteredData]);

    const columnDisplayNames = useMemo(() => ({
        'select-checkbox': 'Select',
        'id': 'ID',
        'severity.severity': 'Severity',
        'epss': 'EPSS Score',
        'packages': 'SBOM Affected',
        'variants': 'Variants',
        'severity': 'Attack Vector',
        'simplified_status': 'Status',
        'effort.likely': 'Estimated Effort',
        'assessments': 'Last Updated',
        'published': 'Published Date',
        'first_scan_date': 'First Scan Date',
        'found_by': 'Sources',
        'actions': 'Actions'
    }), []);

    const allColumns = useMemo(() => {
        const columnHelper = createColumnHelper<Vulnerability>()
        return [
            {
            id: 'select-checkbox',
                cell: ({ row }: { row: Row<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    <input
                        type="checkbox"
                        title={row.getIsSelected() ? "Unselect" : "Select"}
                        checked={row.getIsSelected()}
                        disabled={!row.getCanSelect()}
                        onChange={row.getToggleSelectedHandler()}
                    />
                    </div>
                ),
                header: ({ table }: { table: Table<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    <input
                        type="checkbox"
                        title={table.getIsAllRowsSelected() ? "Unselect all" : "Select all"}
                        checked={table.getIsAllRowsSelected()}
                        onChange={table.getToggleAllRowsSelectedHandler()}
                    />
                    </div>
                ),
                footer: ({ table }: { table: Table<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    {table.getSelectedRowModel().rows.length || ''}
                    </div>
                ),
                minSize: 10,
                size: 10,
                maxSize: 40
            },
            columnHelper.accessor('id', {
                id: 'id',
                header: () => <div className="flex items-center justify-center">ID</div>,
                cell: info => (
                    <div
                        className="flex items-center justify-center w-full h-full text-center cursor-pointer hover:bg-slate-700 hover:text-blue-300 transition-colors p-4"
                        onClick={() => {
                            const vuln = info.row.original;
                            const index = searchFilteredData.findIndex(v => v.id === vuln.id);
                            setModalVuln(vuln);
                            setModalVulnIndex(index >= 0 ? index : undefined);
                            setModalVulnSnapshot([...searchFilteredData]); // Capture snapshot at modal open time
                            setIsEditing(false);
                        }}
                        title="Click to view details"
                    >
                        {info.getValue()}
                    </div>
                ),
                sortDescFirst: true,
                footer: (info) => <div className="flex items-center justify-center">{`Total: ${info.table.getRowCount()}`}</div>,
                size: 170
            }),
            columnHelper.accessor(row => showCustomSeverityFilter ? row.severity.max_score : row.severity.severity, {
            id: 'severity.severity',
            header: () => (
                <div className="flex flex-col items-center justify-center">
                Severity {showCustomSeverityFilter ? 'Score' : ''}
                {showCustomSeverityFilter && <div>{severityRange.min} to {severityRange.max}</div>}
                </div>
            ),
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                    {!showCustomSeverityFilter ? (
                        <SeverityTag severity={info.getValue()?.toString() || 'N/A'} />
                    ) : (
                        <div>{info.getValue() || 'N/A'}</div>
                    )}
                </div>
            ),
            sortingFn: showCustomSeverityFilter ?  sortSeverityByScoreFn : sortSeverityFn,
            sortDescFirst: true,
            size: 40,
            }),
            columnHelper.accessor('epss', {
            id: 'epss',
            header: () => {
                const loading = epssProgress?.in_progress ?? false;
                const pct = epssProgress && epssProgress.total > 0
                    ? Math.round((epssProgress.current / epssProgress.total) * 100)
                    : 0;
                return (
                    <div className="flex flex-col items-center justify-center gap-0.5">
                        <span>EPSS Score</span>
                        {loading && (
                            <span className="flex items-center gap-1 text-xs text-amber-400 font-normal">
                                <FontAwesomeIcon icon={faSync} className="text-[10px]" />
                                {pct}%
                            </span>
                        )}
                    </div>
                );
            },
            cell: info => {
                const epss = info.getValue();
                const fetching = epssProgress?.in_progress && (!epss.score || epss.score === 0);
                return (
                <div className="flex flex-col items-center justify-center h-full text-center">
                    {fetching ? (
                        <span className="text-xs text-gray-500 italic">fetching…</span>
                    ) : epss.score !== undefined && epss.score !== 0 ? (
                        <>{(epss.score * 100).toFixed(2)}%</>
                    ) : null}
                </div>
                );
            },
            sortingFn: (rowA, rowB) => (rowA.original.epss?.score || 0.0) - (rowB.original.epss?.score || 0.0),
            size: 50,
            }),
            columnHelper.accessor('packages_current', {
            id: 'packages',
            header: () => <div className="flex items-center justify-center">SBOM Affected</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().map(p => p.split('+git')[0]).join(', ')}</div>,
            enableSorting: false,
            size: 255
            }),
            columnHelper.accessor('severity', {
            id: 'severity',
            header: () => <div className="flex items-center justify-center">Attack Vector</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">
                {[...(new Set(info.getValue().cvss.map(cvss => cvss.attack_vector).filter(av => av != undefined)))]?.join(', ')}
            </div>,
            enableSorting: true,
            sortingFn: sortAttackVectorFn,
            size: 100
            }),
            columnHelper.accessor('simplified_status', {
            id: 'simplified_status',
            header: () => <div className="flex items-center justify-center">Status</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center"><code>{info.renderValue()}</code></div>,
            sortingFn: sortStatusFn,
            size: 130
            }),
            columnHelper.accessor('effort.likely', {
            id: 'effort.likely',
            header: () => <div className="flex items-center justify-center">Estimated Effort</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().formatHumanShort()}</div>,
            enableSorting: true,
            sortingFn: (rowA, rowB) => rowA.original.effort.likely.total_seconds - rowB.original.effort.likely.total_seconds,
            size: 100
            }),
            columnHelper.accessor('assessments', {
            id: 'assessments',
            header: () => <div className="flex items-center justify-center">Last Updated</div>,
            cell: info => {
                const assessments = info.getValue();
                if (!assessments || assessments.length === 0) {
                    return <div className="flex items-center justify-center h-full text-center text-gray-400">No assessment</div>;
                }

                // Find the most recent update time across all assessments
                const mostRecentTime = assessments.reduce((latest, assessment) => {
                    const assessmentTime = new Date(assessment.last_update || assessment.timestamp);
                    return assessmentTime > latest ? assessmentTime : latest;
                }, new Date(0));

                // Format the date using the same format as VulnModal
                const formattedDate = mostRecentTime.getTime() > 0 ?
                    mostRecentTime.toLocaleString(undefined, dt_options) : 'No assessment';

                return (
                    <div className="flex items-center justify-center h-full text-center text-sm">
                        {formattedDate}
                    </div>
                );
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const getLatestAssessmentTime = (assessments: Assessment[]) => {
                    if (!assessments || assessments.length === 0) return 0;
                    return assessments.reduce((latest, assessment) => {
                        const assessmentTime = new Date(assessment.last_update || assessment.timestamp).getTime();
                        return assessmentTime > latest ? assessmentTime : latest;
                    }, 0);
                };

                return getLatestAssessmentTime(rowA.original.assessments) - getLatestAssessmentTime(rowB.original.assessments);
            },
            size: 140
            }),
            columnHelper.accessor('published', {
            id: 'published',
            header: () => {
                const loading = nvdProgress?.in_progress ?? false;
                const pct = nvdProgress && nvdProgress.total > 0
                    ? Math.round((nvdProgress.current / nvdProgress.total) * 100)
                    : 0;
                return (
                    <div className="flex flex-col items-center justify-center gap-0.5">
                        <span>Published Date</span>
                        {loading && (
                            <span className="flex items-center gap-1 text-xs text-amber-400 font-normal">
                                <FontAwesomeIcon icon={faSync} className="text-[10px]" />
                                {pct}%
                            </span>
                        )}
                    </div>
                );
            },
            cell: info => {
                const published = info.getValue();
                const fetching = nvdProgress?.in_progress && !published;
                if (fetching) {
                    return <div className="flex items-center justify-center h-full text-center"><span className="text-xs text-gray-500 italic">fetching…</span></div>;
                }
                if (!published) {
                    return <div className="flex items-center justify-center h-full text-center text-gray-400">Unknown</div>;
                }
                const publishedDate = new Date(published);
                const formattedDate = publishedDate.toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric'
                });
                return (
                    <div className="flex items-center justify-center h-full text-center text-sm">
                        {formattedDate}
                    </div>
                );
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const dateA = rowA.original.published ? new Date(rowA.original.published).getTime() : 0;
                const dateB = rowB.original.published ? new Date(rowB.original.published).getTime() : 0;
                return dateA - dateB;
            },
            size: 90
            }),
            columnHelper.accessor('first_scan_date', {
            id: 'first_scan_date',
            header: () => <div className="flex items-center justify-center">First Scan Date</div>,
            cell: info => {
                const scanDate = info.getValue();
                if (!scanDate) {
                    return <div className="flex items-center justify-center h-full text-center text-gray-400">Unknown</div>;
                }
                const date = new Date(scanDate);
                const formattedDate = date.toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                }) + ' ' + date.toLocaleTimeString(undefined, {
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZoneName: 'short',
                });
                return (
                    <div className="flex items-center justify-center h-full text-center text-sm">
                        {formattedDate}
                    </div>
                );
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const dateA = rowA.original.first_scan_date ? new Date(rowA.original.first_scan_date).getTime() : 0;
                const dateB = rowB.original.first_scan_date ? new Date(rowB.original.first_scan_date).getTime() : 0;
                return dateA - dateB;
            },
            size: 110
            }),
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
            columnHelper.accessor('found_by', {
            id: 'found_by',
            header: () => <div className="flex items-center justify-center">Sources</div>,
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                    {info.renderValue()
                        ?.map((source: string) =>
                            source === 'openvex'
                                ? 'OpenVex'
                                : source === 'local_user_data'
                                ? 'Local User Data'
                                : source === 'yocto'
                                ? 'Yocto'
                                : source === 'grype'
                                ? 'Grype'
                                : source === 'cyclonedx'
                                ? 'CycloneDx'
                                : source === 'spdx3'
                                ? 'SPDX3'
                                : source
                        )
                        .join(', ')}
                </div>
            ),
            enableSorting: false
            }),
            columnHelper.accessor(row => row, {
                id: 'actions',
                header: 'Actions',
                cell: info => (
                    <div className="flex items-center justify-center h-full">
                    <button
                        className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
                        onClick={() => {
                          const vuln = info.getValue();
                          handleEditClick(vuln);
                          setIsEditing(true);
                      }}
                    >
                        Edit
                    </button>

                    </div>
                ),
                enableSorting: false,
                minSize: 20,
                size: 20
            })
        ]
    }, [handleEditClick, searchFilteredData, showCustomSeverityFilter, severityRange, nvdProgress, epssProgress]);

    const columns = useMemo(() => {
        return allColumns.filter(col => {
            const colId = col.id as string;
            if (colId === 'select-checkbox' || colId === 'actions') return true;
            const displayName = columnDisplayNames[colId as keyof typeof columnDisplayNames];
            return displayName && visibleColumns.includes(displayName);
        });
    }, [allColumns, visibleColumns, columnDisplayNames]);

    const selectedVulns = useMemo(() => {
        return Object.entries(selectedRows).flatMap(([id, selected]) => selected ? [id] : [])
    }, [selectedRows])

    const handleModalNavigation = (newIndex: number) => {
        if (newIndex >= 0 && newIndex < modalVulnSnapshot.length) {
            setModalVuln(modalVulnSnapshot[newIndex]);
            setModalVulnIndex(newIndex);
        }
    };

    function resetFilters() {
        setSearch('');
        setSelectedSources([]);
        setSelectedSeverities([]);
        setSelectedStatuses([]);
        setSelectedPackages([]);
        setPublishedDateFilterType('');
        setPublishedDateValue('');
        setPublishedDaysValue('');
        setPublishedDateFrom('');
        setPublishedDateTo('');
        setSelectedRows({});
        setVisibleColumns(['ID', 'Severity', 'EPSS Score', 'SBOM Affected', 'Variants', 'Status', 'Last Updated', 'Published Date']);
        setShowCustomSeverityFilter(false);
        setSeverityRange({ min: SEVERITY_RANGE_MIN, max: SEVERITY_RANGE_MAX });
        setShowCustomEpssFilter(false);
        setEpssRange({ min: 0, max: 100 });
        setSelectedAttackVectors([]);
        setSelectedFirstScanDates([]);
    }

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

            // Bind "e" to edit focused vulnerability
            if (event.key === "e" && focusedRowIndex !== null) {
                event.preventDefault();
                if (focusedRowIndex >= 0 && focusedRowIndex < searchFilteredData.length) {
                    const vulnToEdit = searchFilteredData[focusedRowIndex];
                    handleEditClick(vulnToEdit);
                    setIsEditing(true);
                }
            }

            // Bind "v" to view focused vulnerability details
            if (event.key === "v" && focusedRowIndex !== null) {
                event.preventDefault();
                if (focusedRowIndex >= 0 && focusedRowIndex < searchFilteredData.length) {
                    const vuln = searchFilteredData[focusedRowIndex];
                    const index = searchFilteredData.findIndex(v => v.id === vuln.id);
                    setModalVuln(vuln);
                    setModalVulnIndex(index >= 0 ? index : undefined);
                    setModalVulnSnapshot([...searchFilteredData]);
                    setIsEditing(false);
                }
            }
        };

        document.addEventListener('keydown', handleKeyPress);
        return () => document.removeEventListener('keydown', handleKeyPress);
    }, [focusedRowIndex, searchFilteredData, handleEditClick]);

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

    // Close "More Filters" on click outside
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (moreFiltersRef.current && !moreFiltersRef.current.contains(event.target as Node)) {
                setShowMoreFilters(false);
            }
        };
        if (showMoreFilters) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [showMoreFilters]);



    return (<>
        {isLoadingVulns && (
            <div className="flex items-center justify-center h-32 text-white text-sm">Loading vulnerabilities…</div>
        )}
        {!isLoadingVulns && bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}

        <div className={isLoadingVulns ? 'hidden' : undefined}>
        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2 flex-wrap">
            <div>Search</div>
            <input ref={searchInputRef} onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by ID, packages, description, ..." />

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
                label="Columns"
                options={[
                    'ID',
                    'Severity',
                    'EPSS Score',
                    'SBOM Affected',
                    'Variants',
                    'Attack Vector',
                    'Status',
                    'Estimated Effort',
                    'Last Updated',
                    'Published Date',
                    'First Scan Date',
                    'Sources'
                ]}
                selected={visibleColumns}
                setSelected={setVisibleColumns}
            />

            <FilterOption
                label="Source"
                options={sources_display_list}
                selected={selectedSources.map(formatSourceName)}
                setSelected={(displayNames) => setSelectedSources(displayNames.map(getOriginalSourceName))}
            />

            <FilterOption
                label="Severity"
                options={[...facets.severities].sort((a, b) =>
                    SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(b.toLowerCase()) - SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(a.toLowerCase())
                )}
                selected={selectedSeverities}
                setSelected={setSelectedSeverities}
                CustomFilterComponent={() => (
                    <RangeSlider
                        min={SEVERITY_RANGE_MIN}
                        max={SEVERITY_RANGE_MAX}
                        initialMin={severityRange.min}
                        initialMax={severityRange.max}
                        step={0.1}
                        onChange={updateCustomSeverityFilter}
                    />
                )}
                customFilterName="by score"
                showCustomFilterComponent={showCustomSeverityFilter}
                setShowCustomFilterComponent={setShowCustomSeverityFilter}
            />

            <FilterOption
                label="Status"
                options={facets.statuses}
                selected={selectedStatuses}
                setSelected={setSelectedStatuses}
            />

            {/* Published Date Filter Dropdown */}
            <PublishedDateFilter
                filterType={publishedDateFilterType}
                dateValue={publishedDateValue}
                daysValue={publishedDaysValue}
                dateFrom={publishedDateFrom}
                dateTo={publishedDateTo}
                setFilterType={setPublishedDateFilterType}
                setDateValue={setPublishedDateValue}
                setDaysValue={setPublishedDaysValue}
                setDateFrom={setPublishedDateFrom}
                setDateTo={setPublishedDateTo}
                nvdProgress={nvdProgress}
            />

            {/* More Filters dropdown — EPSS Range, Attack Vector, First Scan Date */}
            <div ref={moreFiltersRef} className="ml-1 relative inline-block text-left">
                <button
                    onClick={() => setShowMoreFilters(!showMoreFilters)}
                    className={`py-1 px-2 rounded flex items-center gap-1 ${
                        showMoreFilters ? 'bg-sky-950' : 'bg-sky-900 hover:bg-sky-950'
                    } text-white`}
                    title="More filters"
                >
                    <FontAwesomeIcon icon={faFilter} />
                    More
                    {(showCustomEpssFilter || selectedAttackVectors.length > 0 || selectedFirstScanDates.length > 0) && (
                        <span className="ml-1 bg-sky-700 px-1 rounded text-xs">✓</span>
                    )}
                    <FontAwesomeIcon icon={faCaretDown} />
                </button>

                {showMoreFilters && (
                    <div className="absolute mt-1 w-80 bg-sky-900 text-white border border-sky-800 rounded-md shadow-lg z-50 max-h-[70vh] overflow-y-auto">
                        <div className="p-3 space-y-4">

                            {/* EPSS Range Filter */}
                            <div>
                                <div className="flex items-center gap-2 mb-2">
                                    <input
                                        type="checkbox"
                                        id="epss-range-filter"
                                        checked={showCustomEpssFilter}
                                        onChange={() => setShowCustomEpssFilter(!showCustomEpssFilter)}
                                        className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                    />
                                    <label htmlFor="epss-range-filter" className="text-sm font-semibold">EPSS Range (%)</label>
                                </div>
                                {showCustomEpssFilter && (
                                    <div className="ml-2">
                                        <RangeSlider
                                            min={0}
                                            max={100}
                                            initialMin={epssRange.min}
                                            initialMax={epssRange.max}
                                            step={0.5}
                                            onChange={updateCustomEpssFilter}
                                        />
                                    </div>
                                )}
                            </div>

                            <hr className="border-sky-700" />

                            {/* Attack Vector Filter */}
                            <div>
                                <div className="text-sm font-semibold mb-2">Attack Vector</div>
                                <div className="space-y-1 ml-2">
                                    {attack_vector_list.map(av => (
                                        <label key={av} className="flex items-center space-x-2">
                                            <input
                                                type="checkbox"
                                                checked={selectedAttackVectors.includes(av)}
                                                onChange={() => {
                                                    if (selectedAttackVectors.includes(av)) {
                                                        setSelectedAttackVectors(selectedAttackVectors.filter(v => v !== av));
                                                    } else {
                                                        setSelectedAttackVectors([...selectedAttackVectors, av]);
                                                    }
                                                }}
                                                className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                            />
                                            <span>{av.charAt(0) + av.slice(1).toLowerCase()}</span>
                                        </label>
                                    ))}
                                    {attack_vector_list.length === 0 && (
                                        <span className="text-xs text-gray-400 italic">No attack vectors available</span>
                                    )}
                                </div>
                            </div>

                            <hr className="border-sky-700" />

                            {/* First Scan Date Filter */}
                            <div>
                                <div className="text-sm font-semibold mb-2">First Scan Date</div>
                                <div className="ml-2 space-y-1">
                                    {availableFirstScanDates.length === 0 ? (
                                        <span className="text-xs text-gray-400 italic">No scan dates available</span>
                                    ) : (
                                        availableFirstScanDates.map(ts => {
                                            const key = String(ts);
                                            return (
                                                <label key={key} className="flex items-center space-x-2">
                                                    <input
                                                        type="checkbox"
                                                        checked={selectedFirstScanDates.includes(key)}
                                                        onChange={() => {
                                                            if (selectedFirstScanDates.includes(key)) {
                                                                setSelectedFirstScanDates(selectedFirstScanDates.filter(d => d !== key));
                                                            } else {
                                                                setSelectedFirstScanDates([...selectedFirstScanDates, key]);
                                                            }
                                                        }}
                                                        className="form-checkbox text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                                    />
                                                    <span className="text-sm">{formatScanDate(ts)}</span>
                                                </label>
                                            );
                                        })
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Package indicator (no dropdown, just display) */}
            {selectedPackages.length > 0 && (
                <div className="flex items-center gap-1 bg-sky-900 px-2 py-1 rounded text-white border border-sky-700">
                    <span className="font-semibold">Package:</span>
                    <span>{selectedPackages.join(', ')}</span>
                    <button
                        className="ml-1 text-white hover:text-red-400"
                        title="Clear package filter"
                        onClick={() => setSelectedPackages([])}
                    >
                        <FontAwesomeIcon icon={faTimes} />
                    </button>
                </div>
            )}

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

        <MultiEditBar
            vulnerabilities={pageItems}
            selectedVulns={selectedVulns}
            resetVulns={() => setSelectedRows({})}
            appendAssessment={appendAssessment}
            patchVuln={patchVuln}
            triggerBanner={triggerBanner}
            hideBanner={closeBanner}
            variantId={variantId}
            baseVariantId={baseVariantId}
            compareOperation={compareOperation}
        />

        <TableGeneric
            fuseKeys={fuseKeys}
            hoverField="texts"
            columns={columns}
            tableHeight={
                selectedVulns.length >= 1 ?
                (bannerVisible ?
                    'calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px - 64px)' :
                    'calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px)') :
                (bannerVisible ?
                    'calc(100vh - 44px - 64px - 48px - 16px - 8px - 64px)' :
                    'calc(100vh - 44px - 64px - 48px - 16px - 8px)')
            }
            data={pageItems}
            estimateRowHeight={66}
            selected={selectedRows}
            updateSelected={setSelectedRows}
            onFilteredDataChange={setSearchFilteredData}
            onFocusedRowChange={setFocusedRowIndex}
            serverPagination={{
                page,
                pageSize,
                total: serverTotal,
                onPageChange: setPage,
                onPageSizeChange: (size: number) => { setPageSize(size); setPage(0); },
            }}
            onSortingChange={setServerSorting}
        />

        {modalVuln != undefined && <VulnModal
            vuln={modalVuln}
            isEditing={isEditing}
            onClose={() => {
                setModalVuln(undefined);
                setModalVulnIndex(undefined);
                setModalVulnSnapshot([]);
                setIsEditing(false);
            }}
            appendAssessment={appendAssessment}
            appendCVSS={appendCVSS}
            patchVuln={patchVuln}
            vulnerabilities={modalVulnSnapshot}
            currentIndex={modalVulnIndex}
            onNavigate={handleModalNavigation}
            variantId={variantId}
        ></VulnModal>}
        </div>
    </>)
}

export default TableVulnerabilities;
