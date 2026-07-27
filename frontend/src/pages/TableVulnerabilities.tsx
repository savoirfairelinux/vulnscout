import Vulnerabilities, { type Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import Assessments from "../handlers/assessments";
import type { NVDProgress } from "../handlers/nvd_progress";
import type { EPSSProgress } from "../handlers/epss_progress";
import { createColumnHelper, SortingFn, RowSelectionState, Row, Table } from '@tanstack/react-table'
import React, { useMemo, useState, useEffect, useCallback, useRef } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER, getStatusSortIndex, getTopStatusSummaryLabel, getVulnerabilityStatusSummary } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import MultiEditBar from "../components/MultiEditBar";
import RefreshVulnerabilityData from "../components/RefreshVulnerabilityData";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import { formatSourceName, getOriginalSourceName } from "../helpers/sourceNames";
import { useDocUrl } from "../helpers/useDocUrl";
import { formatPkgId } from "../helpers/pkgId";

import MessageBanner from "../components/MessageBanner";
import NVDProgressHandler from "../handlers/nvd_progress";
import EPSSProgressHandler from "../handlers/epss_progress";
import GHSAProgressHandler from "../handlers/ghsa_progress";
import type { GHSAProgress } from "../handlers/ghsa_progress";
import EUVDProgressHandler from "../handlers/euvd_progress";
import type { EUVDProgress } from "../handlers/euvd_progress";

type SourceBanner = { message: string; type: 'error' | 'success' } | null;

function useRefreshProgressEffect(
    progress: { in_progress: boolean; phase?: string; current: number; total: number; started_at?: string } | null,
    label: string,
    prevInProgress: React.MutableRefObject<boolean | null>,
    prevPhase: React.MutableRefObject<string | null>,
    prevStartedAt: React.MutableRefObject<string | null>,
    setSourceBanner: (state: SourceBanner) => void,
    onRefreshComplete?: () => void,
    noun: string = 'entries',
) {
    useEffect(() => {
        const inProgress = progress?.in_progress ?? false;
        const phase = progress?.phase;
        const startedAt = progress?.started_at ?? null;
        const freshCycle = startedAt !== null && startedAt !== prevStartedAt.current;
        const justCompleted = prevPhase.current !== null && (
            prevInProgress.current === true ||
            (prevPhase.current !== 'completed' &&
             prevPhase.current !== 'cancelled' &&
             (phase === 'completed' || phase === 'cancelled')) ||
            (freshCycle && (phase === 'completed' || phase === 'cancelled')));
        if (inProgress) {
            if (progress && progress.total > 0 && progress.current > 0) {
                setSourceBanner({ message: `${label} ${progress.current}/${progress.total}`, type: 'success' });
            }
        } else if (justCompleted) {
            onRefreshComplete?.();
            if (phase === 'cancelled') {
                const current = progress?.current ?? 0;
                const total = progress?.total ?? 0;
                setSourceBanner({ message: `${label} refresh cancelled${current > 0 ? ` (${current}/${total} ${noun})` : ''}`, type: 'error' });
            } else {
                const total = progress?.total ?? 0;
                setSourceBanner({ message: `${label} refresh complete${total > 0 ? ` (${total} ${noun})` : ''}`, type: 'success' });
            }
        }
        if (progress !== null) {
            prevInProgress.current = inProgress;
            prevPhase.current = phase ?? 'idle';
            prevStartedAt.current = startedAt;
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [progress, onRefreshComplete]);
}
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFilter, faCaretDown, faCircleQuestion, faSync, faCircleInfo, faBook } from '@fortawesome/free-solid-svg-icons';
import ExplicitSearchInput from '../components/ExplicitSearchInput';
import { useLocalStorageState } from '../handlers/localStorage';
import RangeSlider from "../components/RangeSlider";

type Props = {
    vulnerabilities: Vulnerability[];
    appendAssessment: (added: Assessment) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
    filterLabel?: "Source" | "Severity" | "Status" | "Package";
    filterValue?: string;
    filterVulnerabilityIds?: string[];
    preferenceScopeKey?: string;
    variantId?: string;
    projectId?: string;
    /** Origin variant when compare mode is active */
    baseVariantId?: string;
    /** 'difference' or 'intersection' when compare mode is active */
    compareOperation?: string;
    /** Selected variants when a multi-variant (union/intersection/difference) view is active */
    variantIds?: string[];
    /** Multi-variant set operation ('union' | 'intersection' | 'difference') */
    multiOperation?: string;
    /** Called when an NVD, EPSS, or GHSA bulk refresh completes, so the parent can reload data */
    onRefreshComplete?: () => void;
    missingEuvdDataBannerDismissed?: boolean;
    onMissingEuvdDataBannerDismissedChange?: (dismissed: boolean) => void;
    missingPublishedDateDataBannerDismissed?: boolean;
    onMissingPublishedDateDataBannerDismissedChange?: (dismissed: boolean) => void;
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
    const summaryA = getVulnerabilityStatusSummary(rowA.original);
    const summaryB = getVulnerabilityStatusSummary(rowB.original);
    const statusA = summaryA.dominant_status;
    const statusB = summaryB.dominant_status;
    const indexA = getStatusSortIndex(statusA);
    const indexB = getStatusSortIndex(statusB);

    if (indexA !== indexB) return indexA - indexB;

    const dominantCountA = summaryA.counts[statusA] || 0;
    const dominantCountB = summaryB.counts[statusB] || 0;
    if (dominantCountA !== dominantCountB) return dominantCountA - dominantCountB;

    return rowA.original.id.localeCompare(rowB.original.id);
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
    'texts.content',
    'description_search_terms'
]

const descriptionSearchTerms = (rawSearch: string): string[] => {
    const terms = rawSearch
        .split('|')
        .flatMap(group => group.trim().split(/\s+/))
        .filter(token => token && !/^only:/i.test(token))
        .map(token => token.startsWith('-') ? token.slice(1) : token)
        .filter(Boolean)
        .map(token => token.toLocaleLowerCase());
    return [...new Set(terms)];
};

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
    hasAnyPublishedDate: boolean;
};

function PublishedDateFilter({
    filterType, dateValue, daysValue, dateFrom, dateTo,
    setFilterType, setDateValue, setDaysValue, setDateFrom, setDateTo,
    nvdProgress, hasAnyPublishedDate
}: Readonly<PublishedDateFilterProps>) {
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);

    // Disabled only while NVD is actively syncing, or when there is no
    // published-date data at all (neither from NVD nor any other scan).
    const nvdReady = !!nvdProgress && !nvdProgress.in_progress && nvdProgress.phase === 'completed';
    const isDisabled = (nvdProgress?.in_progress ?? false) || (!nvdReady && !hasAnyPublishedDate);
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
                title={isDisabled
                    ? (nvdProgress?.in_progress ? 'NVD sync in progress' : 'No published dates available')
                    : 'Filter by published date'}
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

// Canonical, fixed order for the vulnerability table columns. The rendered
// order and the "Columns" filter list both follow this array so a column
// always appears in the same position regardless of the order in which the
// user toggled it on. (The 'Select' and 'Actions' columns are always pinned
// first and last respectively and are not part of this list.)
const VULN_COLUMN_ORDER = [
    'ID',
    'Severity',
    'EU KEV',
    'EPSS Score',
    'Attack Vector',
    'SBOM Affected',
    'Variants',
    'Status',
    'Published Date',
    'Estimated Effort',
    'Last Assessed',
    'First Scan Date',
    'Last Fetched',
    'Last Updated',
    'Sources',
] as const;

// Columns shown by default (a subset of VULN_COLUMN_ORDER, kept in the same
// canonical order).
const DEFAULT_VISIBLE_COLUMNS = [
    'ID', 'Severity', 'EU KEV', 'EPSS Score', 'SBOM Affected', 'Variants', 'Status', 'Last Assessed',
];

function TableVulnerabilities ({ vulnerabilities, filterLabel, filterValue, filterVulnerabilityIds, preferenceScopeKey = 'unscoped', appendAssessment, appendCVSS, patchVuln, variantId, projectId, baseVariantId, compareOperation, variantIds, multiOperation, onRefreshComplete, missingEuvdDataBannerDismissed, onMissingEuvdDataBannerDismissedChange, missingPublishedDateDataBannerDismissed, onMissingPublishedDateDataBannerDismissedChange }: Readonly<Props>) {
    const preferenceKey = `vulnscout.tables.vulnerabilities.${encodeURIComponent(preferenceScopeKey)}`;

    const docUrl = useDocUrl("interactive-mode.html#vulnerability-table");
    const [modalVuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
    const [modalVulnSnapshot, setModalVulnSnapshot] = useState<Vulnerability[]>([]);
    const [modalDetailsLoading, setModalDetailsLoading] = useState(false);
    const [modalDetailsError, setModalDetailsError] = useState(false);
    const hoverDetailsCache = useRef(new Map<string, Vulnerability>());

    const loadHoverDetails = useCallback(async (summary: Vulnerability): Promise<Vulnerability> => {
        if (summary.details_loaded !== false) return summary;
        const cacheKey = `${summary.id}:${variantId ?? ''}:${projectId ?? ''}`;
        const cached = hoverDetailsCache.current.get(cacheKey);
        if (cached) return cached;
        const details = await Vulnerabilities.getDetails(summary.id, variantId, projectId);
        const resolved = details ? {
            ...summary,
            texts: details.texts,
            urls: details.urls,
            cpes: details.cpes,
            severity: { ...summary.severity, cvss: details.severity.cvss },
            details_loaded: true,
        } : { ...summary, details_loaded: true };
        hoverDetailsCache.current.set(cacheKey, resolved);
        return resolved;
    }, [variantId, projectId]);

    useEffect(() => {
        if (!modalVuln || modalVuln.details_loaded !== false) {
            setModalDetailsLoading(false);
            setModalDetailsError(false);
            return;
        }

        const controller = new AbortController();
        const vulnId = modalVuln.id;
        setModalDetailsLoading(true);
        setModalDetailsError(false);
        Vulnerabilities.getDetails(vulnId, variantId, projectId, controller.signal)
            .then((details) => {
                if (!details || controller.signal.aborted) return;
                const mergeDetails = (summary: Vulnerability): Vulnerability => ({
                    ...summary,
                    texts: details.texts,
                    urls: details.urls,
                    cpes: details.cpes,
                    severity: {
                        ...summary.severity,
                        cvss: details.severity.cvss,
                    },
                    details_loaded: true,
                });
                setModalVuln((current) => (
                    current?.id === vulnId ? mergeDetails(current) : current
                ));
                setModalVulnSnapshot((current) => current.map((vuln) => (
                    vuln.id === vulnId ? mergeDetails(vuln) : vuln
                )));
            })
            .catch((error) => {
                if (error?.name !== 'AbortError' && !controller.signal.aborted) {
                    setModalDetailsError(true);
                }
            })
            .finally(() => {
                if (!controller.signal.aborted) setModalDetailsLoading(false);
            });

        return () => controller.abort();
    }, [modalVuln, variantId, projectId]);
    const [isEditing, setIsEditing] = useState<boolean>(false);
    const [search, setSearch] = useLocalStorageState(`${preferenceKey}.search`, '');
    const [draftSearch, setDraftSearch] = useLocalStorageState(`${preferenceKey}.draftSearch`, '');
    const [descriptionMatches, setDescriptionMatches] = useState<Record<string, Set<string>>>({});
    const [descriptionSearchLoading, setDescriptionSearchLoading] = useState(false);
    const [descriptionSearchError, setDescriptionSearchError] = useState(false);
    const [selectedSeverities, setSelectedSeverities] = useLocalStorageState<string[]>(`${preferenceKey}.severities`, []);
    const [selectedStatuses, setSelectedStatuses] = useLocalStorageState<string[]>(`${preferenceKey}.statuses`, []);
    const [selectedSources, setSelectedSources] = useLocalStorageState<string[]>(`${preferenceKey}.sources`, []);
    const [selectedPackages, setSelectedPackages] = useLocalStorageState<string[]>(`${preferenceKey}.packages`, []);
    const [publishedDateFilterType, setPublishedDateFilterType] = useLocalStorageState(`${preferenceKey}.publishedDate.type`, '');
    const [publishedDateValue, setPublishedDateValue] = useLocalStorageState(`${preferenceKey}.publishedDate.value`, '');
    const [publishedDaysValue, setPublishedDaysValue] = useLocalStorageState(`${preferenceKey}.publishedDate.days`, '');
    const [publishedDateFrom, setPublishedDateFrom] = useLocalStorageState(`${preferenceKey}.publishedDate.from`, '');
    const [publishedDateTo, setPublishedDateTo] = useLocalStorageState(`${preferenceKey}.publishedDate.to`, '');
    const [nvdProgress, setNvdProgress] = useState<NVDProgress | null>(null);
    const [epssProgress, setEpssProgress] = useState<EPSSProgress | null>(null);
    const [ghsaProgress, setGhsaProgress] = useState<GHSAProgress | null>(null);
    const [euvdProgress, setEuvdProgress] = useState<EUVDProgress | null>(null);
    const [selectedRows, setSelectedRows] = useState<RowSelectionState>({});
    const [nvdBanner, setNvdBanner] = useState<SourceBanner>(null);
    const [epssBanner, setEpssBanner] = useState<SourceBanner>(null);
    const [ghsaBanner, setGhsaBanner] = useState<SourceBanner>(null);
    const [euvdBanner, setEuvdBanner] = useState<SourceBanner>(null);
    const [generalBanner, setGeneralBanner] = useState<SourceBanner>(null);
    const [localMissingEuvdDataBannerDismissed, setLocalMissingEuvdDataBannerDismissed] = useState(false);
    const [localMissingPublishedDateDataBannerDismissed, setLocalMissingPublishedDateDataBannerDismissed] = useState(false);
    const [searchFilteredData, setSearchFilteredData] = useState<Vulnerability[]>([]);
    const [visibleColumns, setVisibleColumns] = useLocalStorageState<string[]>(`${preferenceKey}.visibleColumns`, [
        ...DEFAULT_VISIBLE_COLUMNS
    ]);
    const [focusedRowIndex, setFocusedRowIndex] = useState<number | null>(null);

    const [showCustomSeverityFilter, setShowCustomSeverityFilter] = useLocalStorageState(`${preferenceKey}.customSeverity.enabled`, false);
    const [severityRange, setSeverityRange] = useLocalStorageState(`${preferenceKey}.customSeverity.range`, { min: SEVERITY_RANGE_MIN, max: SEVERITY_RANGE_MAX });
    const [showCustomEpssFilter, setShowCustomEpssFilter] = useLocalStorageState(`${preferenceKey}.customEpss.enabled`, false);
    const [epssRange, setEpssRange] = useLocalStorageState(`${preferenceKey}.customEpss.range`, { min: 0, max: 100 });
    const [selectedAttackVectors, setSelectedAttackVectors] = useLocalStorageState<string[]>(`${preferenceKey}.attackVectors`, []);
    const [selectedFirstScanDates, setSelectedFirstScanDates] = useLocalStorageState<string[]>(`${preferenceKey}.firstScanDates`, []);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [showMoreFilters, setShowMoreFilters] = useState(false);
    const [aiSuggestionFilter, setAiSuggestionFilter] = useLocalStorageState<'any' | 'has' | 'no'>(`${preferenceKey}.aiSuggestion`, 'any');
    const [aiSuggestionVulnIds, setAiSuggestionVulnIds] = useState<Set<string>>(new Set());

    const searchInputRef = useRef<HTMLInputElement>(null);
    const descriptionSearchController = useRef<AbortController | null>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const shortcutDropdownRef = useRef<HTMLDivElement>(null);
    const searchHelperButtonRef = useRef<HTMLButtonElement>(null);
    const searchHelperDropdownRef = useRef<HTMLDivElement>(null);
    const moreFiltersRef = useRef<HTMLDivElement>(null);
    const prevNvdInProgress = useRef<boolean | null>(null);
    const prevNvdPhase = useRef<string | null>(null);
    const prevNvdStartedAt = useRef<string | null>(null);
    const prevEpssInProgress = useRef<boolean | null>(null);
    const prevEpssPhase = useRef<string | null>(null);
    const prevEpssStartedAt = useRef<string | null>(null);
    const prevGhsaInProgress = useRef<boolean | null>(null);
    const prevGhsaPhase = useRef<string | null>(null);
    const prevGhsaStartedAt = useRef<string | null>(null);
    const prevEuvdInProgress = useRef<boolean | null>(null);
    const prevEuvdPhase = useRef<string | null>(null);
    const prevEuvdStartedAt = useRef<string | null>(null);
    const hasFetchedProgressOnce = useRef(false);

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
        { syntax: 'only:text', description: 'Show a vuln only when all of its SBOM-affected packages contain text (e.g. only:native keeps vulns whose affected packages are all native)' },
    ];

    const hasAnyGhsaVuln = useMemo(
        () => vulnerabilities.some(v => v.id?.toUpperCase().startsWith('GHSA-')),
        [vulnerabilities]
    );

    // Published dates can come from sources other than NVD (e.g. an
    // sbom-cve-check scan). When at least one vulnerability already has a
    // published date, the filter is usable even if NVD has never synced.
    const hasAnyPublishedDate = useMemo(
        () => vulnerabilities.some(v => !!v.published),
        [vulnerabilities]
    );

    const isMissingEuvdDataBannerDismissed = missingEuvdDataBannerDismissed ?? localMissingEuvdDataBannerDismissed;
    const isMissingPublishedDateDataBannerDismissed = missingPublishedDateDataBannerDismissed ?? localMissingPublishedDateDataBannerDismissed;

    const setMissingEuvdDataBannerDismissed = useCallback((dismissed: boolean) => {
        onMissingEuvdDataBannerDismissedChange?.(dismissed);
        if (missingEuvdDataBannerDismissed === undefined) setLocalMissingEuvdDataBannerDismissed(dismissed);
    }, [missingEuvdDataBannerDismissed, onMissingEuvdDataBannerDismissedChange]);

    const setMissingPublishedDateDataBannerDismissed = useCallback((dismissed: boolean) => {
        onMissingPublishedDateDataBannerDismissedChange?.(dismissed);
        if (missingPublishedDateDataBannerDismissed === undefined) setLocalMissingPublishedDateDataBannerDismissed(dismissed);
    }, [missingPublishedDateDataBannerDismissed, onMissingPublishedDateDataBannerDismissedChange]);

    const hasAnyEuvdData = useMemo(
        () => vulnerabilities.some(v => typeof v.euvd_fetched_at === "string" && v.euvd_fetched_at !== ""),
        [vulnerabilities]
    );
    const previousHasAnyEuvdData = useRef(hasAnyEuvdData);
    const previousHasAnyPublishedDate = useRef(hasAnyPublishedDate);

    const shouldShowMissingEuvdDataBanner = vulnerabilities.length > 0 &&
        !hasAnyEuvdData &&
        !euvdProgress?.in_progress &&
        !isMissingEuvdDataBannerDismissed;

    const shouldShowMissingPublishedDateDataBanner = vulnerabilities.length > 0 &&
        !hasAnyPublishedDate &&
        !nvdProgress?.in_progress &&
        !isMissingPublishedDateDataBannerDismissed;

    const shouldShowMissingDataBanner = shouldShowMissingEuvdDataBanner || shouldShowMissingPublishedDateDataBanner;

    const missingDataBannerMessage = <>Vulnerabilities are incomplete and need updating. Use the "Refresh vulnerability data" button to update them.</>;

    const dismissMissingDataBanner = () => {
        if (shouldShowMissingEuvdDataBanner) setMissingEuvdDataBannerDismissed(true);
        if (shouldShowMissingPublishedDateDataBanner) setMissingPublishedDateDataBannerDismissed(true);
    };

    useEffect(() => {
        if (previousHasAnyEuvdData.current !== hasAnyEuvdData) {
            setMissingEuvdDataBannerDismissed(false);
        }
        previousHasAnyEuvdData.current = hasAnyEuvdData;
    }, [hasAnyEuvdData, setMissingEuvdDataBannerDismissed]);

    useEffect(() => {
        if (previousHasAnyPublishedDate.current !== hasAnyPublishedDate) {
            setMissingPublishedDateDataBannerDismissed(false);
        }
        previousHasAnyPublishedDate.current = hasAnyPublishedDate;
    }, [hasAnyPublishedDate, setMissingPublishedDateDataBannerDismissed]);


    useEffect(() => {
        if (!filterLabel || !filterValue) return;
        if (filterLabel === "Source") setSelectedSources([filterValue]);
        if (filterLabel === "Severity") setSelectedSeverities([filterValue]);
        if (filterLabel === "Status") setSelectedStatuses([filterValue]);
        if (filterLabel === "Package") setSelectedPackages([filterValue]);
    }, [filterLabel, filterValue, setSelectedPackages, setSelectedSeverities, setSelectedSources, setSelectedStatuses]);

    // Fetch pending AI suggestions (origin == 'ai') for the current scope. These are
    // excluded from the vulnerabilities' assessments array by the backend, so they must
    // be fetched separately. Scope to the selected variant, else the project.
    useEffect(() => {
        let cancelled = false;
        if (!variantId && !projectId) {
            setAiSuggestionVulnIds(new Set());
            return;
        }
        Assessments.listReviewAi(variantId, projectId)
            .then(assessments => {
                if (cancelled) return;
                setAiSuggestionVulnIds(new Set(assessments.map(a => a.vuln_id)));
            })
            .catch(() => {
                if (!cancelled) setAiSuggestionVulnIds(new Set());
            });
        return () => { cancelled = true; };
    }, [variantId, projectId]);

    // Update per-source banners with live progress; reload data when each refresh completes
    useRefreshProgressEffect(nvdProgress, 'NVD', prevNvdInProgress, prevNvdPhase, prevNvdStartedAt, setNvdBanner, onRefreshComplete, 'CVEs');
    useRefreshProgressEffect(epssProgress, 'EPSS', prevEpssInProgress, prevEpssPhase, prevEpssStartedAt, setEpssBanner, onRefreshComplete, 'CVEs');
    useRefreshProgressEffect(ghsaProgress, 'GHSA', prevGhsaInProgress, prevGhsaPhase, prevGhsaStartedAt, setGhsaBanner, onRefreshComplete, 'advisories');
    useRefreshProgressEffect(euvdProgress, 'EUVD', prevEuvdInProgress, prevEuvdPhase, prevEuvdStartedAt, setEuvdBanner, onRefreshComplete, 'CVEs');

    const fetchAllProgress = useCallback(async (forceAll = false) => {
        const shouldPollGhsa = forceAll || hasAnyGhsaVuln || Boolean(ghsaProgress?.in_progress);
        const shouldPollEpss = forceAll || Boolean(epssProgress?.in_progress);
        const shouldPollEuvd = forceAll || Boolean(euvdProgress?.in_progress);
        const [nvd, epss, ghsa, euvd] = await Promise.allSettled([
            NVDProgressHandler.getProgress(),
            shouldPollEpss ? EPSSProgressHandler.getProgress() : Promise.resolve(null),
            shouldPollGhsa ? GHSAProgressHandler.getProgress() : Promise.resolve(null),
            shouldPollEuvd ? EUVDProgressHandler.getProgress() : Promise.resolve(null),
        ]);
        if (nvd.status === 'fulfilled') setNvdProgress(nvd.value);
        else console.error('Failed to fetch NVD refresh progress:', nvd.reason);
        if (epss.status === 'fulfilled') setEpssProgress(epss.value);
        else console.error('Failed to fetch EPSS refresh progress:', epss.reason);
        if (ghsa.status === 'fulfilled') setGhsaProgress(ghsa.value);
        else console.error('Failed to fetch GHSA refresh progress:', ghsa.reason);
        if (euvd.status === 'fulfilled') setEuvdProgress(euvd.value);
        else console.error('Failed to fetch EUVD refresh progress:', euvd.reason);
    }, [hasAnyGhsaVuln, ghsaProgress?.in_progress, epssProgress?.in_progress, euvdProgress?.in_progress]);

    // Fetch once on mount so we can recover progress if a refresh was already running.
    useEffect(() => {
        if (!hasFetchedProgressOnce.current) {
            hasFetchedProgressOnce.current = true;
            void fetchAllProgress(true);
        }
    }, [fetchAllProgress]);

    // Poll only while any refresh is actively running.
    useEffect(() => {
        const anyInProgress = Boolean(
            nvdProgress?.in_progress || epssProgress?.in_progress || ghsaProgress?.in_progress || euvdProgress?.in_progress
        );
        if (!anyInProgress) {
            return;
        }

        const interval = setInterval(() => {
            void fetchAllProgress();
        }, 3000);

        return () => clearInterval(interval);
    }, [nvdProgress?.in_progress, epssProgress?.in_progress, ghsaProgress?.in_progress, euvdProgress?.in_progress, fetchAllProgress]);

    const activeBanners = [nvdBanner, epssBanner, ghsaBanner, euvdBanner, generalBanner].filter((b): b is NonNullable<SourceBanner> => b !== null);
    const bannerVisible = activeBanners.length > 0;
    const bannerMessage = activeBanners.map(b => b.message).join(' · ');
    const bannerType: 'error' | 'success' = activeBanners.some(b => b.type === 'error') ? 'error' : 'success';
    const visibleBannerCount = activeBanners.length +
        Number(shouldShowMissingDataBanner);

    const triggerBanner = (message: string, type: 'error' | 'success', source?: 'nvd' | 'epss' | 'ghsa' | 'euvd', refreshActivity?: boolean) => {
        if (source === 'nvd') setNvdBanner({ message, type });
        else if (source === 'epss') setEpssBanner({ message, type });
        else if (source === 'ghsa') setGhsaBanner({ message, type });
        else if (source === 'euvd') setEuvdBanner({ message, type });
        else setGeneralBanner({ message, type });

        // Refresh progress immediately when the caller signals a refresh has
        // just started or been cancelled, so active polling can begin/stop
        // without idle background polling. This relies on an explicit flag
        // rather than parsing the user-facing banner text.
        if (source && refreshActivity) {
            void fetchAllProgress(true);
        }
    };

    const closeBanner = () => {
        setNvdBanner(null);
        setEpssBanner(null);
        setGhsaBanner(null);
        setEuvdBanner(null);
        setGeneralBanner(null);
    };

    const updateCustomSeverityFilter = debounce((value: { min: number; max: number }) => {
        setSeverityRange(value);
    }, 750, { maxWait: 5000 });

    const updateCustomEpssFilter = debounce((value: { min: number; max: number }) => {
        setEpssRange(value);
    }, 750, { maxWait: 5000 });

    const attack_vector_list = useMemo(() => {
        const avSet = new Set<string>();
        vulnerabilities.forEach(vuln => {
            vuln.severity.cvss.forEach(cvss => {
                if (cvss.attack_vector) avSet.add(cvss.attack_vector);
            });
        });
        const order = ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'];
        return Array.from(avSet).sort((a, b) => order.indexOf(a) - order.indexOf(b));
    }, [vulnerabilities]);

    // Build list of distinct first-scan timestamps, grouped by scan (same second = same scan)
    const availableFirstScanDates = useMemo(() => {
        const tsSet = new Set<number>();
        vulnerabilities.forEach(vuln => {
            if (vuln.first_scan_date) {
                // Round to the nearest second to group identical scans
                const ts = Math.round(new Date(vuln.first_scan_date).getTime() / 1000) * 1000;
                tsSet.add(ts);
            }
        });
        return Array.from(tsSet).sort((a, b) => a - b);
    }, [vulnerabilities]);

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

    const sources_list = useMemo(() => vulnerabilities.reduce((acc: string[], vuln) => {
        vuln.found_by.forEach(source => {
            if (!acc.includes(source) && source != '')
                acc.push(source)
        });
        return acc;
    }, []), [vulnerabilities])

    const sources_display_list = useMemo(
        () => sources_list.map(formatSourceName),
        [sources_list]
    );

    // Distinct raw package ids across all vulnerabilities, sorted by display label.
    // Currently selected packages are always included so a stale or absent
    // preselection (e.g. from filterValue) can still be unchecked by the user.
    const packages_list = useMemo(() => {
        const pkgSet = new Set<string>();
        vulnerabilities.forEach(vuln => {
            vuln.packages_current.forEach(pkg => {
                if (pkg !== '') pkgSet.add(pkg);
            });
        });
        selectedPackages.forEach(pkg => {
            if (pkg !== '') pkgSet.add(pkg);
        });
        return Array.from(pkgSet).sort((a, b) => formatPkgId(a).localeCompare(formatPkgId(b)));
    }, [vulnerabilities, selectedPackages]);

    const handleEditClick = useCallback((vuln: Vulnerability) => {
        const index = searchFilteredData.findIndex(v => v.id === vuln.id);
        setModalVuln(vuln);
        setModalVulnIndex(index >= 0 ? index : undefined);
        setModalVulnSnapshot([...searchFilteredData]); // Capture snapshot at modal open time
    }, [searchFilteredData]);

    const handlePatchVuln = useCallback((vulnId: string, replace_vuln: Vulnerability) => {
        patchVuln(vulnId, replace_vuln);
        setModalVuln(prev => prev?.id === vulnId ? replace_vuln : prev);
        setModalVulnSnapshot(prev => prev.map(v => v.id === vulnId ? replace_vuln : v));
    }, [patchVuln]);

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
        'assessments': 'Last Assessed',
        'published': 'Published Date',
        'first_scan_date': 'First Scan Date',
        'data_fetched_at': 'Last Fetched',
        'data_updated_at': 'Last Updated',
        'found_by': 'Sources',
        'euvd': 'EU KEV',
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
                        ref={el => {
                            if (el) el.indeterminate = table.getIsSomePageRowsSelected();
                        }}
                        title={table.getIsAllPageRowsSelected() ? "Unselect all" : "Select all"}
                        checked={table.getIsAllPageRowsSelected()}
                        onChange={table.getToggleAllPageRowsSelectedHandler()}
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
            HintText: <>
                <h3 className="font-bold text-white mb-2">EPSS Score</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Estimates the probability that this vulnerability will be exploited in the next 30 days.</p>
                    <p>Higher percentages indicate a higher likelihood of exploitation.</p>
                    <p>Refresh EPSS data to populate this score.</p>
                </div>
            </>,
            HintAriaLabel: 'EPSS Score helper',
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
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().map(p => formatPkgId(p.split('+git')[0])).join(', ')}</div>,
            enableSorting: false,
            size: 255
            }),
            columnHelper.accessor('severity', {
            id: 'severity',
            header: () => <div className="flex items-center justify-center">Attack Vector</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">Attack Vector</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows how an attacker needs to reach the vulnerable component.</p>
                    <p>Values come from CVSS records, such as Network, Adjacent, Local, or Physical.</p>
                </div>
            </>,
            HintAriaLabel: 'Attack Vector helper',
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
            HintText: <>
                <h3 className="font-bold text-white mb-2">Status Summary</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Status aggregates all assessment outcomes for the vulnerability in the current scope.</p>
                    <p>Scope follows your active project, variant, and compare selection.</p>
                    <p>Display lists every distinct outcome, for example: Exploitable, Pending Assessment.</p>
                    <p>Filtering matches vulnerabilities when any selected status is present in the summary.</p>
                </div>
            </>,
            HintAriaLabel: 'Status summary helper',
            cell: info => {
                const summary = getVulnerabilityStatusSummary(info.row.original);
                const label = getTopStatusSummaryLabel(summary);
                return (
                    <div className="flex items-center justify-center h-full text-center" title={label}>
                        <code>{label}</code>
                    </div>
                );
            },
            sortingFn: sortStatusFn,
            size: 220
            }),
            columnHelper.accessor('effort.likely', {
            id: 'effort.likely',
            header: () => <div className="flex items-center justify-center">Estimated Effort</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">Estimated Effort</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows the estimated time required to assess the vulnerability.</p>
                    <p>The value reflects the likely effort estimate for the current vulnerability.</p>
                </div>
            </>,
            HintAriaLabel: 'Estimated Effort helper',
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().formatHumanShort()}</div>,
            enableSorting: true,
            sortingFn: (rowA, rowB) => rowA.original.effort.likely.total_seconds - rowB.original.effort.likely.total_seconds,
            size: 100
            }),
            columnHelper.accessor('assessments', {
            id: 'assessments',
            header: () => <div className="flex items-center justify-center">Last Assessed</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">Last Assessed</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows the most recent creation or update time across all assessments in the current scope.</p>
                    <p>Vulnerabilities without an assessment display “No assessment”.</p>
                </div>
            </>,
            HintAriaLabel: 'Last Assessed helper',
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
            HintText: <>
                <h3 className="font-bold text-white mb-2">Published Date</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows when the vulnerability was first published.</p>
                    <p>The NVD refresh provides this date for CVEs, and the GitHub Security Advisory refresh provides it for GHSA identifiers.</p>
                    <p>Select vulnerabilities and refresh their data when a date is unavailable.</p>
                </div>
            </>,
            HintAriaLabel: 'Published Date helper',
            cell: info => {
                const published = info.getValue();
                const fetching = nvdProgress?.in_progress && !published;
                if (fetching) {
                    return <div className="flex items-center justify-center h-full text-center"><span className="text-xs text-gray-500 italic">fetching…</span></div>;
                }
                if (!published) {
                    // A published date is provided by the NVD refresh (CVEs) or the
                    // GitHub Security Advisory refresh (GHSA ids). Show "-" only when
                    // such a refresh has already run and still returned no date;
                    // otherwise prompt the user to refresh the vulnerability data.
                    const refreshed = Boolean(info.row.original.nvd_fetched_at || info.row.original.ghsa_fetched_at);
                    return refreshed
                        ? <div className="flex items-center justify-center h-full text-center text-gray-400">—</div>
                        : <div className="flex items-center justify-center h-full text-center text-gray-400">Requires Refresh Vulnerability Data</div>;
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
            HintText: <>
                <h3 className="font-bold text-white mb-2">First Scan Date</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows when this vulnerability was first detected in the scanned SBOM data.</p>
                    <p>This date is recorded by VulnScout and is not the vulnerability publication date.</p>
                </div>
            </>,
            HintAriaLabel: 'First Scan Date helper',
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
            columnHelper.accessor('data_fetched_at', {
            id: 'data_fetched_at',
            header: () => <div className="flex items-center justify-center">Last Fetched</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">Last Fetched</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows when vulnerability data was last retrieved from an external source.</p>
                    <p>A value of “Never” means no external vulnerability data has been fetched yet.</p>
                </div>
            </>,
            HintAriaLabel: 'Last Fetched helper',
            cell: info => {
                const val = info.getValue();
                if (!val) return <div className="flex items-center justify-center h-full text-center text-gray-400">Never</div>;
                const date = new Date(val);
                const formattedDate = date.toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                }) + ' ' + date.toLocaleTimeString(undefined, {
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZoneName: 'short',
                });
                return <div className="flex items-center justify-center h-full text-center text-sm">{formattedDate}</div>;
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const a = rowA.original.data_fetched_at ? new Date(rowA.original.data_fetched_at).getTime() : 0;
                const b = rowB.original.data_fetched_at ? new Date(rowB.original.data_fetched_at).getTime() : 0;
                return a - b;
            },
            size: 130
            }),
            columnHelper.accessor('data_updated_at', {
            id: 'data_updated_at',
            header: () => <div className="flex items-center justify-center">Last Updated</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">Last Updated</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Shows when the vulnerability record was last updated with new data.</p>
                    <p>A value of “Never” means the record has not received an external data update.</p>
                </div>
            </>,
            HintAriaLabel: 'Last Updated helper',
            cell: info => {
                const val = info.getValue();
                if (!val) return <div className="flex items-center justify-center h-full text-center text-gray-400">Never</div>;
                const date = new Date(val);
                const formattedDate = date.toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                }) + ' ' + date.toLocaleTimeString(undefined, {
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZoneName: 'short',
                });
                return <div className="flex items-center justify-center h-full text-center text-sm">{formattedDate}</div>;
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const a = rowA.original.data_updated_at ? new Date(rowA.original.data_updated_at).getTime() : 0;
                const b = rowB.original.data_updated_at ? new Date(rowB.original.data_updated_at).getTime() : 0;
                return a - b;
            },
            size: 130
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
            HintText: <>
                <h3 className="font-bold text-white mb-2">Sources</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Lists the vulnerability sources that reported this vulnerability.</p>
                    <p>Use this information to trace the origin of the vulnerability data.</p>
                </div>
            </>,
            HintAriaLabel: 'Vulnerability Sources helper',
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                    {info.renderValue()
                        ?.map(formatSourceName)
                        .join(', ')}
                </div>
            ),
            enableSorting: false
            }),
            columnHelper.accessor('euvd', {
            id: 'euvd',
            header: () => <div className="flex items-center justify-center">EU KEV</div>,
            HintText: <>
                <h3 className="font-bold text-white mb-2">EU KEV</h3>
                <div className="space-y-1 text-gray-100">
                    <p>Marks vulnerabilities in the consolidated EU Known Exploited Vulnerabilities list.</p>
                    <p>The list combines the CISA KEV and ENISA EU KEV catalogues.</p>
                    <p>Refresh ENISA EUVD data to populate this priority-triage signal.</p>
                </div>
            </>,
            cell: info => {
                const euvd = info.getValue();
                if (euvd?.known_exploited) {
                    return (
                        <div className="flex items-center justify-center h-full">
                            <span className="px-1.5 py-0.5 rounded text-xs font-semibold bg-red-900/60 text-red-200">
                                Known Exploited
                            </span>
                        </div>
                    );
                }
                const fetching = euvdProgress?.in_progress;
                if (fetching) {
                    return <div className="flex items-center justify-center h-full text-center"><span className="text-xs text-gray-500 italic">fetching…</span></div>;
                }
                // The EU KEV signal comes from the ENISA EUVD refresh. Show "-" only
                // when that refresh has already run and the vulnerability was not on
                // the KEV list; otherwise prompt the user to refresh the data.
                const refreshed = Boolean(info.row.original.euvd_fetched_at);
                return refreshed
                    ? <div className="flex items-center justify-center h-full text-center text-gray-500">—</div>
                    : <div className="flex items-center justify-center h-full text-center text-gray-400">Requires Refresh Vulnerability Data</div>;
            },
            sortingFn: (rowA, rowB) => {
                const a = rowA.original.euvd?.known_exploited ? 1 : 0;
                const b = rowB.original.euvd?.known_exploited ? 1 : 0;
                return a - b;
            },
            size: 110
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
    }, [handleEditClick, searchFilteredData, showCustomSeverityFilter, severityRange, nvdProgress, epssProgress, euvdProgress]);

    const columns = useMemo(() => {
        const columnByDisplayName = new Map(
            allColumns.map(column => [
                columnDisplayNames[column.id as keyof typeof columnDisplayNames],
                column,
            ])
        );
        const selectedColumns = VULN_COLUMN_ORDER.flatMap(displayName => {
            if (!visibleColumns.includes(displayName)) return [];
            const column = columnByDisplayName.get(displayName);
            return column ? [column] : [];
        });
        const selectColumn = allColumns.find(column => column.id === 'select-checkbox');
        const actionsColumn = allColumns.find(column => column.id === 'actions');

        return [
            ...(selectColumn ? [selectColumn] : []),
            ...selectedColumns,
            ...(actionsColumn ? [actionsColumn] : []),
        ];
    }, [allColumns, visibleColumns, columnDisplayNames]);

    const dataToDisplay = useMemo(() => {
        const allowedVulnerabilityIds = filterVulnerabilityIds ? new Set(filterVulnerabilityIds) : null;
        return vulnerabilities.filter((el) => {
            if (allowedVulnerabilityIds && !allowedVulnerabilityIds.has(el.id)) return false;
            if (aiSuggestionFilter === 'has' && !aiSuggestionVulnIds.has(el.id)) return false;
            if (aiSuggestionFilter === 'no' && aiSuggestionVulnIds.has(el.id)) return false;
            if (selectedSeverities.length && !selectedSeverities.includes(el.severity.severity)) return false;
            if (selectedStatuses.length) {
                const summary = getVulnerabilityStatusSummary(el);
                const statusKeys = new Set(Object.keys(summary.counts));
                if (!selectedStatuses.some(status => statusKeys.has(status))) return false;
            }
            if (selectedSources.length && !selectedSources.some(src => el.found_by.includes(src))) return false;
            if (selectedPackages.length && !selectedPackages.some(pkg => el.packages_current.includes(pkg))) return false;

            // Published date filter
            if (publishedDateFilterType && el.published) {
                const publishedDate = new Date(el.published);
                const today = new Date();

                switch (publishedDateFilterType) {
                    case 'is':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            // Compare dates in UTC to avoid timezone issues
                            const publishedUTC = Date.UTC(publishedDate.getUTCFullYear(), publishedDate.getUTCMonth(), publishedDate.getUTCDate());
                            const targetUTC = Date.UTC(targetDate.getUTCFullYear(), targetDate.getUTCMonth(), targetDate.getUTCDate());
                            if (publishedUTC !== targetUTC) return false;
                        }
                        break;
                    case '>=':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            const publishedUTC = Date.UTC(publishedDate.getUTCFullYear(), publishedDate.getUTCMonth(), publishedDate.getUTCDate());
                            const targetUTC = Date.UTC(targetDate.getUTCFullYear(), targetDate.getUTCMonth(), targetDate.getUTCDate());
                            if (publishedUTC < targetUTC) return false;
                        }
                        break;
                    case '<=':
                        if (publishedDateValue) {
                            const targetDate = new Date(publishedDateValue);
                            const publishedUTC = Date.UTC(publishedDate.getUTCFullYear(), publishedDate.getUTCMonth(), publishedDate.getUTCDate());
                            const targetUTC = Date.UTC(targetDate.getUTCFullYear(), targetDate.getUTCMonth(), targetDate.getUTCDate());
                            if (publishedUTC > targetUTC) return false;
                        }
                        break;
                    case 'between':
                        if (publishedDateFrom && publishedDateTo) {
                            const fromDate = new Date(publishedDateFrom);
                            const toDate = new Date(publishedDateTo);
                            const publishedUTC = Date.UTC(publishedDate.getUTCFullYear(), publishedDate.getUTCMonth(), publishedDate.getUTCDate());
                            const fromUTC = Date.UTC(fromDate.getUTCFullYear(), fromDate.getUTCMonth(), fromDate.getUTCDate());
                            const toUTC = Date.UTC(toDate.getUTCFullYear(), toDate.getUTCMonth(), toDate.getUTCDate());
                            if (publishedUTC < fromUTC || publishedUTC > toUTC) return false;
                        }
                        break;
                    case 'days_ago':
                        if (publishedDaysValue) {
                            const daysAgo = parseInt(publishedDaysValue);
                            if (!isNaN(daysAgo)) {
                                const cutoffDate = new Date(today);
                                cutoffDate.setDate(cutoffDate.getDate() - daysAgo);
                                const publishedUTC = Date.UTC(publishedDate.getUTCFullYear(), publishedDate.getUTCMonth(), publishedDate.getUTCDate());
                                const cutoffUTC = Date.UTC(cutoffDate.getUTCFullYear(), cutoffDate.getUTCMonth(), cutoffDate.getUTCDate());
                                if (publishedUTC < cutoffUTC) return false;
                            }
                        }
                        break;
                }
            } else if (publishedDateFilterType && !el.published) {
                // If filter is active but vulnerability has no published date, filter it out
                return false;
            }

            if(showCustomSeverityFilter){
                // Use the max score as this is how the final severity level is determined
                const maxScore = el.severity.max_score;

                if (maxScore === null) return false;
                if (maxScore < severityRange.min || maxScore > severityRange.max) return false;
            }

            // EPSS range filter
            if (showCustomEpssFilter) {
                const epssScore = el.epss?.score;
                if (epssScore === undefined || epssScore === null) return false;
                const epssPct = epssScore * 100;
                if (epssPct < epssRange.min || epssPct > epssRange.max) return false;
            }

            // Attack vector filter
            if (selectedAttackVectors.length) {
                const vulnAVs = new Set(el.severity.cvss.map(c => c.attack_vector).filter(Boolean));
                if (!selectedAttackVectors.some(av => vulnAVs.has(av))) return false;
            }

            // First scan date filter (multi-select by scan timestamp)
            if (selectedFirstScanDates.length > 0) {
                if (!el.first_scan_date) return false;
                const elTs = Math.round(new Date(el.first_scan_date).getTime() / 1000) * 1000;
                if (!selectedFirstScanDates.includes(String(elTs))) return false;
            }

            return true;
        });
    }, [vulnerabilities, filterVulnerabilityIds, selectedSeverities, selectedStatuses, selectedSources, selectedPackages, publishedDateFilterType, publishedDateValue, publishedDaysValue, publishedDateFrom, publishedDateTo, showCustomSeverityFilter, severityRange, showCustomEpssFilter, epssRange, selectedAttackVectors, selectedFirstScanDates, aiSuggestionFilter, aiSuggestionVulnIds]);

    const searchableData = useMemo(() => dataToDisplay.map(vuln => ({
        ...vuln,
        description_search_terms: Object.entries(descriptionMatches)
            .filter(([, ids]) => ids.has(vuln.id))
            .map(([term]) => term)
            .join(' ') || '\0',
    })), [dataToDisplay, descriptionMatches]);

    const applySearch = useCallback(async () => {
        const nextSearch = draftSearch.trim();
        const terms = descriptionSearchTerms(nextSearch);
        descriptionSearchController.current?.abort();
        setDescriptionSearchError(false);

        if (nextSearch.length <= 2 || terms.length === 0 ||
            vulnerabilities.every(vuln => vuln.details_loaded !== false)) {
            if (!nextSearch) setDescriptionMatches({});
            setSearch(nextSearch);
            setDescriptionSearchLoading(false);
            return;
        }

        const controller = new AbortController();
        descriptionSearchController.current = controller;
        setDescriptionSearchLoading(true);
        try {
            const matches = await Vulnerabilities.searchDescriptionTerms(
                vulnerabilities.map(vuln => vuln.id),
                terms,
                variantId,
                projectId,
                controller.signal,
            );
            if (controller.signal.aborted) return;
            setDescriptionMatches(Object.fromEntries(
                Object.entries(matches).map(([term, ids]) => [term, new Set(ids)])
            ));
            setSearch(nextSearch);
        } catch (error: any) {
            if (error?.name === 'AbortError' || controller.signal.aborted) return;
            setDescriptionMatches({});
            setDescriptionSearchError(true);
            setSearch(nextSearch);
        } finally {
            if (!controller.signal.aborted) setDescriptionSearchLoading(false);
        }
    }, [draftSearch, vulnerabilities, variantId, projectId, setSearch]);

    const applySearchRef = useRef(applySearch);
    applySearchRef.current = applySearch;

    // Re-run the persisted/restored search whenever the scoped vulnerability
    // data changes. Explorer loads vulnerabilities asynchronously and may
    // initially render the previous scope's rows, so restoring only once on
    // mount would evaluate the search against stale or empty IDs and leave an
    // incorrectly filtered table. Re-running on data changes keeps
    // descriptionMatches consistent with the current scope; applySearch aborts
    // any in-flight description request before starting a new one. Depending on
    // `vulnerabilities` (not `draftSearch`) avoids firing a description search
    // on every keystroke.
    useEffect(() => {
        if (draftSearch.trim()) void applySearchRef.current();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [vulnerabilities]);

    useEffect(() => () => descriptionSearchController.current?.abort(), []);

    const selectedVulns = useMemo(() => {
        return Object.entries(selectedRows).flatMap(([id, selected]) => selected ? [id] : [])
    }, [selectedRows])

    const availableStatuses = useMemo(() => {
        const statuses = new Set<string>();
        vulnerabilities.forEach(vuln => {
            const summary = getVulnerabilityStatusSummary(vuln);
            Object.keys(summary.counts).forEach(status => statuses.add(status));
        });
        return Array.from(statuses).sort((a, b) => getStatusSortIndex(a) - getStatusSortIndex(b));
    }, [vulnerabilities]);

    const handleModalNavigation = (newIndex: number) => {
        if (newIndex >= 0 && newIndex < modalVulnSnapshot.length) {
            setModalVuln(modalVulnSnapshot[newIndex]);
            setModalVulnIndex(newIndex);
        }
    };

    function resetFilters() {
        descriptionSearchController.current?.abort();
        setSearch('');
        setDraftSearch('');
        setDescriptionMatches({});
        setDescriptionSearchError(false);
        setDescriptionSearchLoading(false);
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
        setVisibleColumns([...DEFAULT_VISIBLE_COLUMNS]);
        setShowCustomSeverityFilter(false);
        setSeverityRange({ min: SEVERITY_RANGE_MIN, max: SEVERITY_RANGE_MAX });
        setShowCustomEpssFilter(false);
        setEpssRange({ min: 0, max: 100 });
        setSelectedAttackVectors([]);
        setSelectedFirstScanDates([]);
        setAiSuggestionFilter('any');
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
        {bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}
        {shouldShowMissingDataBanner && (
            <MessageBanner
                type="info"
                message={missingDataBannerMessage}
                isVisible={true}
                onClose={dismissMissingDataBanner}
            />
        )}

        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2 flex-wrap">
            <div className="contents">
                <ExplicitSearchInput
                    id="vulnerability-search"
                    ref={searchInputRef}
                    value={draftSearch}
                    onChange={setDraftSearch}
                    onSearch={applySearch}
                    label="Search"
                    placeholder="Search by ID, packages, description, ..."
                    ariaLabel="Search vulnerabilities"
                    loading={descriptionSearchLoading}
                />
            </div>
            {descriptionSearchError && (
                <span role="alert" className="text-sm text-red-200">
                    Description search failed; ID and package matches are still available.
                </span>
            )}

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
                options={[...VULN_COLUMN_ORDER]}
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
                options={availableStatuses}
                selected={selectedStatuses}
                setSelected={setSelectedStatuses}
            />

            <FilterOption
                label="Packages"
                options={packages_list}
                selected={selectedPackages}
                setSelected={setSelectedPackages}
                searchable
                formatLabel={formatPkgId}
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
                hasAnyPublishedDate={hasAnyPublishedDate}
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
                    {(showCustomEpssFilter || selectedAttackVectors.length > 0 || selectedFirstScanDates.length > 0 || aiSuggestionFilter !== 'any') && (
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

                            <hr className="border-sky-700" />

                            {/* AI Suggestion Filter */}
                            <div>
                                <div className="text-sm font-semibold mb-2">AI Suggestion</div>
                                <div className="space-y-1 ml-2">
                                    {([
                                        { value: 'any', label: 'Any' },
                                        { value: 'has', label: 'Has AI suggestion' },
                                        { value: 'no', label: 'No AI suggestion' },
                                    ] as const).map(opt => (
                                        <label key={opt.value} className="flex items-center space-x-2">
                                            <input
                                                type="radio"
                                                name="ai-suggestion-filter"
                                                checked={aiSuggestionFilter === opt.value}
                                                onChange={() => setAiSuggestionFilter(opt.value)}
                                                className="form-radio text-sky-500 bg-sky-800 border-sky-600 focus:ring-0"
                                            />
                                            <span>{opt.label}</span>
                                        </label>
                                    ))}
                                </div>
                                <p className="text-xs text-gray-400 mt-1 ml-2">
                                    Filter by pending AI suggestion in the current scope.
                                </p>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Package selection is handled by the Packages filter dropdown above */}

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
                <span className="h-6 border-l border-gray-400" aria-hidden="true" />
                <RefreshVulnerabilityData
                    vulnerabilities={vulnerabilities}
                    getRefreshVulnerabilities={() => Vulnerabilities.list(variantId, projectId, baseVariantId, compareOperation, variantIds, multiOperation)}
                    triggerBanner={triggerBanner}
                    hideBanner={closeBanner}
                    nvdProgress={nvdProgress}
                    epssProgress={epssProgress}
                    ghsaProgress={ghsaProgress}
                    euvdProgress={euvdProgress}
                />
            </div>
        </div>

        <MultiEditBar
            vulnerabilities={vulnerabilities}
            selectedVulns={selectedVulns}
            resetVulns={() => setSelectedRows({})}
            appendAssessment={appendAssessment}
            patchVuln={handlePatchVuln}
            triggerBanner={triggerBanner}
            hideBanner={closeBanner}
            variantId={variantId}
            baseVariantId={baseVariantId}
            compareOperation={compareOperation}
        />

        <TableGeneric
            persistenceKey={preferenceKey}
            fuseKeys={fuseKeys}
            forAllValues={(vuln) => (vuln.packages_current?.length ? vuln.packages_current : vuln.packages)}
            hoverField="texts"
            search={search}
            columns={columns}
            tableHeight={
                visibleBannerCount > 0 ?
                    `calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px - ${visibleBannerCount * 64}px)` :
                    'calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px)'
            }
            data={searchableData}
            estimateRowHeight={66}
            selected={selectedRows}
            updateSelected={setSelectedRows}
            onFilteredDataChange={setSearchFilteredData}
            onFocusedRowChange={setFocusedRowIndex}
            onHoverData={loadHoverDetails}
        />

        {modalVuln != undefined && <VulnModal
            vuln={modalVuln}
            detailsLoading={modalDetailsLoading}
            detailsError={modalDetailsError}
            isEditing={isEditing}
            onClose={() => {
                setModalVuln(undefined);
                setModalVulnIndex(undefined);
                setModalVulnSnapshot([]);
                setIsEditing(false);
            }}
            appendAssessment={appendAssessment}
            appendCVSS={appendCVSS}
            patchVuln={handlePatchVuln}
            vulnerabilities={modalVulnSnapshot}
            currentIndex={modalVulnIndex}
            onNavigate={handleModalNavigation}
            variantId={variantId}
            projectId={projectId}
        ></VulnModal>}
    </>)
}

export default TableVulnerabilities;
