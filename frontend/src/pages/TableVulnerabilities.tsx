import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import type { NVDProgress } from "../handlers/nvd_progress";
import { createColumnHelper, SortingFn, RowSelectionState, Row, Table } from '@tanstack/react-table'
import { useMemo, useState, useEffect, useCallback, useRef } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import MultiEditBar from "../components/MultiEditBar";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";
import MessageBanner from "../components/MessageBanner";
import NVDProgressHandler from "../handlers/nvd_progress";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTimes, faCaretDown } from '@fortawesome/free-solid-svg-icons';

type Props = {
    vulnerabilities: Vulnerability[];
    appendAssessment: (added: Assessment) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
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

const fuseKeys = ['id', 'aliases', 'related_vulnerabilities', 'packages', 'simplified_status', 'status', 'texts.content']

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
                            <label className="block text-sm font-semibold mb-1">Filter Type:</label>
                            <select
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
                                <label className="block text-sm font-semibold mb-1">Date:</label>
                                <input
                                    type="date"
                                    value={dateValue}
                                    onChange={(e) => setDateValue(e.target.value)}
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {filterType === '>=' && (
                            <div>
                                <label className="block text-sm font-semibold mb-1">On or after:</label>
                                <input
                                    type="date"
                                    value={dateValue}
                                    onChange={(e) => setDateValue(e.target.value)}
                                    className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                />
                            </div>
                        )}

                        {filterType === '<=' && (
                            <div>
                                <label className="block text-sm font-semibold mb-1">On or before:</label>
                                <input
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
                                    <label className="block text-sm font-semibold mb-1">From:</label>
                                    <input
                                        type="date"
                                        value={dateFrom}
                                        onChange={(e) => setDateFrom(e.target.value)}
                                        className="w-full px-2 py-1 text-sm bg-sky-800 text-white rounded border border-sky-600 focus:outline-none focus:border-sky-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-semibold mb-1">To:</label>
                                    <input
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
                                <label className="block text-sm font-semibold mb-1">Number of days:</label>
                                <input
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

function TableVulnerabilities ({ vulnerabilities, filterLabel, filterValue, appendAssessment, appendCVSS, patchVuln }: Readonly<Props>) {

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
    const [selectedRows, setSelectedRows] = useState<RowSelectionState>({});
    const [hideFixed, setHideFixed] = useState<boolean>(false);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);
    const [searchFilteredData, setSearchFilteredData] = useState<Vulnerability[]>([]);
    const [visibleColumns, setVisibleColumns] = useState<string[]>([
        'ID', 'Severity', 'EPSS Score', 'Packages Affected', 'Status', 'Last Updated'
    ]);

    useEffect(() => {
        if (!filterLabel || !filterValue) return;
        if (filterLabel === "Source") setSelectedSources([filterValue]);
        if (filterLabel === "Severity") setSelectedSeverities([filterValue]);
        if (filterLabel === "Status") setSelectedStatuses([filterValue]);
        if (filterLabel === "Package") setSelectedPackages([filterValue]);
    }, [filterLabel, filterValue]);

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

    const sources_list = useMemo(() => vulnerabilities.reduce((acc: string[], vuln) => {
        vuln.found_by.forEach(source => {
            if (!acc.includes(source) && source != '')
                acc.push(source)
        });
        return acc;
    }, []), [vulnerabilities])

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
        'packages': 'Packages Affected',
        'severity': 'Attack Vector',
        'simplified_status': 'Status',
        'effort.likely': 'Estimated Effort',
        'assessments': 'Last Updated',
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
            columnHelper.accessor('severity.severity', {
            id: 'severity.severity',
            header: () => (
                <div className="flex items-center justify-center">
                Severity
                </div>
            ),
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                <SeverityTag severity={info.getValue()} />
                </div>
            ),
            sortingFn: sortSeverityFn,
            sortDescFirst: true,
            size: 40,
            }),
            columnHelper.accessor('epss', {
            id: 'epss',
            header: () => <div className="flex items-center justify-center">EPSS Score</div>,
            cell: info => {
                const epss = info.getValue();
                return (
                <div className="flex flex-col items-center justify-center h-full text-center">
                    {epss.score !== undefined && epss.score !== 0 &&  <>
                    {(epss.score * 100).toFixed(2)}%
                    </>}
                </div>
                );
            },
            sortingFn: (rowA, rowB) => (rowA.original.epss?.score || 0.0) - (rowB.original.epss?.score || 0.0),
            size: 50,
            }),
            columnHelper.accessor('packages', {
            id: 'packages',
            header: () => <div className="flex items-center justify-center">Packages Affected</div>,
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
    }, [handleEditClick, searchFilteredData]);

    const columns = useMemo(() => {
        return allColumns.filter(col => {
            const colId = col.id as string;
            if (colId === 'select-checkbox' || colId === 'actions') return true;
            const displayName = columnDisplayNames[colId as keyof typeof columnDisplayNames];
            return displayName && visibleColumns.includes(displayName);
        });
    }, [allColumns, visibleColumns, columnDisplayNames]);

    const dataToDisplay = useMemo(() => {
        return vulnerabilities.filter((el) => {
            if (selectedSeverities.length && !selectedSeverities.includes(el.severity.severity)) return false;
            if (selectedStatuses.length && !selectedStatuses.includes(el.simplified_status)) return false;
            if (selectedSources.length && !selectedSources.some(src => el.found_by.includes(src))) return false;
            if (selectedPackages.length && !selectedPackages.some(pkg => el.packages.includes(pkg))) return false;
            
            // Published date filter
            if (publishedDateFilterType && el.published) {
                const publishedDate = new Date(el.published);
                const today = new Date();
                
                switch (publishedDateFilterType) {
                    case 'is':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            if (publishedDate.toDateString() !== targetDate.toDateString()) return false;
                        }
                        break;
                    case '>=':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            targetDate.setHours(0, 0, 0, 0);
                            if (publishedDate < targetDate) return false;
                        }
                        break;
                    case '<=':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            targetDate.setHours(23, 59, 59, 999);
                            if (publishedDate > targetDate) return false;
                        }
                        break;
                    case 'between':
                        if (publishedDateFrom && publishedDateTo) {
                            const fromDate = new Date(publishedDateFrom);
                            const toDate = new Date(publishedDateTo);
                            fromDate.setHours(0, 0, 0, 0);
                            toDate.setHours(23, 59, 59, 999);
                            if (publishedDate < fromDate || publishedDate > toDate) return false;
                        }
                        break;
                    case 'days_ago':
                        if (publishedDaysValue) {
                            const daysAgo = parseInt(publishedDaysValue);
                            if (!isNaN(daysAgo)) {
                                const cutoffDate = new Date(today);
                                cutoffDate.setDate(cutoffDate.getDate() - daysAgo);
                                cutoffDate.setHours(0, 0, 0, 0);
                                if (publishedDate < cutoffDate) return false;
                            }
                        }
                        break;
                }
            } else if (publishedDateFilterType && !el.published) {
                // If filter is active but vulnerability has no published date, filter it out
                return false;
            }
            
            return true;
        });
    }, [vulnerabilities, selectedSeverities, selectedStatuses, selectedSources, selectedPackages, publishedDateFilterType, publishedDateValue, publishedDaysValue, publishedDateFrom, publishedDateTo]);

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
        setHideFixed(false);
        setVisibleColumns(['ID', 'Severity', 'EPSS Score', 'Packages Affected', 'Status', 'Last Updated']);
    }

    const handleHideFixedToggle = (enabled: boolean) => {
        setHideFixed(enabled);
        if (enabled) {
            const allStatuses = Array.from(new Set(vulnerabilities.map(v => v.simplified_status)));
            const statusesExceptFixed = allStatuses.filter(status => status !== 'Fixed');
            setSelectedStatuses(statusesExceptFixed);
        } else {
            setSelectedStatuses([]);
        }
    };

    const handleStatusChange = (newStatuses: string[]) => {
        setSelectedStatuses(newStatuses);
        if (newStatuses.includes('Fixed') && hideFixed) {
            setHideFixed(false);
        }
    };

    return (<>
        {bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}

        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by ID, packages, description, ..." />

            <FilterOption
                label="Columns"
                options={[
                    'ID',
                    'Severity',
                    'EPSS Score',
                    'Packages Affected',
                    'Attack Vector',
                    'Status',
                    'Estimated Effort',
                    'Last Updated',
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
                options={Array.from(new Set(vulnerabilities.map(v => v.severity.severity))).sort((a, b) =>
                    SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(b.toLowerCase()) - SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(a.toLowerCase())
                )}
                selected={selectedSeverities}
                setSelected={setSelectedSeverities}
            />

            <FilterOption
                label="Status"
                options={Array.from(new Set(vulnerabilities.map(v => v.simplified_status)))}
                selected={selectedStatuses}
                setSelected={handleStatusChange}
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

            <ToggleSwitch
                enabled={hideFixed}
                setEnabled={handleHideFixedToggle}
                label="Hide Fixed"
            />

            <button
                onClick={resetFilters}
                className="ml-auto bg-sky-900 hover:bg-sky-950 px-3 py-1 rounded text-white border border-sky-700"
            >
                Reset Filters
            </button>
        </div>

        <MultiEditBar
            vulnerabilities={vulnerabilities}
            selectedVulns={selectedVulns}
            resetVulns={() => setSelectedRows({})}
            appendAssessment={appendAssessment}
            patchVuln={patchVuln}
            triggerBanner={triggerBanner}
            hideBanner={closeBanner}
        />

        <TableGeneric
            fuseKeys={fuseKeys}
            hoverField="texts"
            search={search}
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
            data={dataToDisplay}
            estimateRowHeight={66}
            selected={selectedRows}
            updateSelected={setSelectedRows}
            onFilteredDataChange={setSearchFilteredData}
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
        ></VulnModal>}
    </>)
}

export default TableVulnerabilities;