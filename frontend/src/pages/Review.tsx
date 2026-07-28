import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { createColumnHelper, OnChangeFn, Row, RowSelectionState, Table } from "@tanstack/react-table";
import TableGeneric from "../components/TableGeneric";
import Assessments from "../handlers/assessments";
import type { Assessment, ReviewTimeEstimate, ReviewCustomCvss } from "../handlers/assessments";
import { asAssessment } from "../handlers/assessments";
import type { Vulnerability } from "../handlers/vulnerabilities";
import { asVulnerability } from "../handlers/vulnerabilities";
import VulnModal from "../components/VulnModal";
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion, faCircleInfo, faFileExport, faFileImport, faPenToSquare, faTrash, faBook, faCheck, faXmark } from '@fortawesome/free-solid-svg-icons';
import { downloadJson, sanitizeFilename, formatTimestampForFilename } from '../helpers/exportJson';
import EditAssessment from '../components/EditAssessment';
import type { EditAssessmentData } from '../components/EditAssessment';
import type { Variant } from '../handlers/variant';
import ConfirmationModal from '../components/ConfirmationModal';
import MessageBanner from '../components/MessageBanner';
import Variants from '../handlers/variant';
import Packages from '../handlers/packages';
import { useDocUrl } from '../helpers/useDocUrl';
import { splitPkgId, extractSupplierName } from '../helpers/pkgId';
import ReviewTransferModal from '../components/ReviewTransferModal';
import ExplicitSearchInput from '../components/ExplicitSearchInput';

type AssessmentMutation =
    | { type: 'delete'; vulnId: string; ids: string[] }
    | { type: 'update'; vulnId: string; ids: string[]; data: EditAssessmentData };

type ReviewTab = 'assessments' | 'ai-assessments' | 'time-estimates' | 'custom-cvss';

type ReviewTimeEstimateRow = ReviewTimeEstimate & {
    texts: { title: string; content: string }[];
};

type ReviewCustomCvssRow = ReviewCustomCvss & {
    texts: { title: string; content: string }[];
};

type Props = {
    variantId?: string;
    projectId?: string;
    onAssessmentChanged?: (mutation: AssessmentMutation) => void;
};

export type { AssessmentMutation };

/** Extended assessment row that carries hover texts for the tooltip. */
type ReviewRow = Assessment & {
    texts: { title: string; content: string }[];
    /** All assessment IDs in this group (for bulk delete). */
    _allIds: string[];
    /** All variant IDs merged into this group. */
    _variantIds: string[];
    /** Raw assessments merged into this group (for per-variant/package edits). */
    _assessments: Assessment[];
    /** Unique supplier display names extracted from packages (for search). */
    extractedSuppliers: string[];
};

const columnHelper = createColumnHelper<ReviewRow>();
const teColumnHelper = createColumnHelper<ReviewTimeEstimate>();
const cvssColumnHelper = createColumnHelper<ReviewCustomCvss>();

function createSelectionColumn<DataType>() {
    return {
        id: 'select-checkbox',
        cell: ({ row }: { row: Row<DataType> }) => (
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
        header: ({ table }: { table: Table<DataType> }) => (
            <div className="flex items-center justify-center h-full">
                <input
                    type="checkbox"
                    ref={element => {
                        if (element) element.indeterminate = table.getIsSomePageRowsSelected();
                    }}
                    title={table.getIsAllPageRowsSelected() ? "Unselect all" : "Select all"}
                    checked={table.getIsAllPageRowsSelected()}
                    onChange={table.getToggleAllPageRowsSelectedHandler()}
                />
            </div>
        ),
        minSize: 10,
        size: 40,
        maxSize: 40,
    };
}

/**
 * Group assessments that share the same CVE, status, justification, notes,
 * workaround and impact into a single row — merging packages, variants and
 * keeping the most recent timestamp.
 */
function groupAssessments(assessments: Assessment[]): Assessment[] {
    const groups = new Map<string, Assessment>();
    const allIds = new Map<string, string[]>();
    const variantIds = new Map<string, Set<string>>();
    const rawAssessments = new Map<string, Assessment[]>();
    for (const a of assessments) {
        const key = [
            a.vuln_id,
            a.status,
            a.justification ?? '',
            a.status_notes ?? '',
            a.impact_statement ?? '',
            a.workaround ?? '',
        ].join('\0');
        const existing = groups.get(key);
        if (existing) {
            // Merge packages (avoid duplicates)
            const pkgSet = new Set([...existing.packages, ...a.packages]);
            existing.packages = [...pkgSet];
            // Keep the most recent timestamp
            if (a.timestamp > existing.timestamp) existing.timestamp = a.timestamp;
            allIds.get(key)!.push(a.id);
            rawAssessments.get(key)!.push(a);
            if (a.variant_id) variantIds.get(key)!.add(a.variant_id);
        } else {
            groups.set(key, { ...a, packages: [...a.packages] });
            allIds.set(key, [a.id]);
            rawAssessments.set(key, [a]);
            const vs = new Set<string>();
            if (a.variant_id) vs.add(a.variant_id);
            variantIds.set(key, vs);
        }
    }
    const result: Assessment[] = [];
    for (const [key, group] of groups) {
        (group as any)._allIds = allIds.get(key)!;
        (group as any)._variantIds = [...variantIds.get(key)!];
        (group as any)._assessments = rawAssessments.get(key)!;
        result.push(group);
    }
    return result;
}

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

function hasOutdatedAssessment(assessment: Assessment): boolean {
    const rawAssessments = (assessment as Partial<ReviewRow>)._assessments ?? [assessment];
    return rawAssessments.some(current => current.outdated);
}

function Review({ variantId, projectId, onAssessmentChanged }: Readonly<Props>) {
    const docUrl = useDocUrl("interactive-mode.html#review");
    const [activeTab, setActiveTab] = useState<ReviewTab>('assessments');
    const [assessments, setAssessments] = useState<Assessment[]>([]);
    const [aiAssessments, setAiAssessments] = useState<Assessment[]>([]);
    const [timeEstimates, setTimeEstimates] = useState<ReviewTimeEstimate[]>([]);
    const [customCvss, setCustomCvss] = useState<ReviewCustomCvss[]>([]);
    const [vulnDescriptions, setVulnDescriptions] = useState<Record<string, { title: string; content: string }[]>>({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [search, setSearch] = useState<string>('');
    const [draftSearch, setDraftSearch] = useState<string>('');
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedJustifications, setSelectedJustifications] = useState<string[]>([]);
    const [selectedSuppliers, setSelectedSuppliers] = useState<string[]>([]);
    const [deselectedVariants, setDeselectedVariants] = useState<string[]>([]);
    const [showOnlyOutdated, setShowOnlyOutdated] = useState(false);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [importStatus, setImportStatus] = useState<string | null>(null);
    const [variantNames, setVariantNames] = useState<Record<string, string>>({});
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [editingRow, setEditingRow] = useState<ReviewRow | null>(null);
    const [editVariants, setEditVariants] = useState<Variant[]>([]);
    const [editVariantPackageMap, setEditVariantPackageMap] = useState<Record<string, string[]>>({});
    const [editSubmitting, setEditSubmitting] = useState(false);
    const [rowToDelete, setRowToDelete] = useState<ReviewRow | null>(null);
    const [selectedAssessments, setSelectedAssessments] = useState<RowSelectionState>({});
    const [selectedAiAssessments, setSelectedAiAssessments] = useState<RowSelectionState>({});
    const [selectedTimeEstimates, setSelectedTimeEstimates] = useState<RowSelectionState>({});
    const [selectedCustomCvss, setSelectedCustomCvss] = useState<RowSelectionState>({});
    const [bulkDeleteTab, setBulkDeleteTab] = useState<ReviewTab | null>(null);
    const [bannerMessage, setBannerMessage] = useState("");
    const [bannerType, setBannerType] = useState<"error" | "success">("success");
    const [showBanner, setShowBanner] = useState(false);
    const [transferMode, setTransferMode] = useState<'import' | 'export' | null>(null);
    const [transferVariantIds, setTransferVariantIds] = useState<string[]>([]);
    const [transferFormat, setTransferFormat] = useState<'custom' | 'openvex'>('custom');
    const [importTimestampPolicy, setImportTimestampPolicy] = useState<'original' | 'current'>('original');

    const showMessage = useCallback((message: string, type: "error" | "success") => {
        setBannerMessage(message);
        setBannerType(type);
        setShowBanner(true);
    }, []);
    const [modalVuln, setModalVuln] = useState<Vulnerability | undefined>(undefined);
    const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
    const [modalVulnIds, setModalVulnIds] = useState<string[]>([]);
    const displayedVulnIdsRef = useRef<string[]>([]);
    const fetchGenRef = useRef(0);
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
        { syntax: 'only:text', description: 'Show a row only when all of its affected packages contain text (e.g. only:native keeps rows whose affected packages are all native)' },
    ];

    useEffect(() => {
        Variants.listAll().then(vs => {
            const map: Record<string, string> = {};
            for (const v of vs) map[v.id] = v.name;
            setVariantNames(map);
            setAllVariants(vs);
        }).catch(() => {});
    }, []);

    // When editing a row, only offer variants that actually have a finding for
    // this CVE (optionally scoped to the current project), instead of every
    // variant in the database.
    useEffect(() => {
        if (!editingRow) {
            setEditVariants([]);
            return;
        }
        setEditVariants([]);
        Variants.listByVuln(editingRow.vuln_id).then(variants => {
            setEditVariants(projectId ? variants.filter(v => v.project_id === projectId) : variants);
        }).catch(() => {});
    }, [editingRow, projectId]);

    // Build the variant -> package compatibility map for the edited row so the
    // popup can block incompatible package/variant combos (same source as the
    // SBOM tab: GET /api/packages?variant_id=<id>).
    useEffect(() => {
        let cancelled = false;
        if (editVariants.length === 0) {
            setEditVariantPackageMap({});
            return;
        }
        (async () => {
            const entries: [string, string[]][] = await Promise.all(
                editVariants.map(async (variant): Promise<[string, string[]]> => {
                    try {
                        const pkgs = await Packages.list(variant.id);
                        return [variant.id, pkgs.map(p =>
                            p.supplier ? `${p.name}@${p.version}::${p.supplier}` : `${p.name}@${p.version}`
                        )];
                    } catch {
                        return [variant.id, []];
                    }
                })
            );
            if (cancelled) return;
            const map: Record<string, string[]> = Object.fromEntries(entries);
            // Seed the map with (variant, package) pairs already covered by the
            // assessment being edited. Deprecated packages are no longer in the
            // variant's current SBOM, so Packages.list omits them; without this
            // they would be flagged incompatible and their checkbox disabled.
            if (editingRow) {
                for (const a of editingRow._assessments) {
                    if (!a.variant_id) continue;
                    const merged = new Set(map[a.variant_id] ?? []);
                    for (const pkg of a.packages) merged.add(pkg);
                    map[a.variant_id] = [...merged];
                }
            }
            setEditVariantPackageMap(map);
        })();
        return () => { cancelled = true; };
    }, [editVariants, editingRow]);

    useEffect(() => {
        setLoading(true);
        setError(null);
        Promise.all([
            Assessments.listReview(variantId, projectId),
            Assessments.listReviewAi(variantId, projectId),
            Assessments.listReviewTimeEstimates(variantId, projectId),
            Assessments.listReviewCustomCvss(variantId, projectId),
        ])
            .then(([reviewData, aiData, teData, cvssData]) => {
                setAssessments(groupAssessments(reviewData));
                setAiAssessments(groupAssessments(aiData));
                setTimeEstimates(teData);
                setCustomCvss(cvssData.filter((item) => item.origin === 'custom'));
                setLoading(false);
                // Build tooltip descriptions from vuln_texts included in the response
                const descMap: Record<string, { title: string; content: string }[]> = {};
                for (const a of [...reviewData, ...aiData]) {
                    if (a.vuln_id && !descMap[a.vuln_id] && a.vuln_texts) {
                        descMap[a.vuln_id] = a.vuln_texts || [{ title: "description", content: "No description available" }];
                    }
                }
                for (const te of teData) {
                    if (te.vuln_id && !descMap[te.vuln_id] && te.vuln_texts) {
                        descMap[te.vuln_id] = te.vuln_texts || [{ title: "description", content: "No description available" }];
                    }
                }
                for (const c of cvssData) {
                    if (c.vuln_id && !descMap[c.vuln_id] && c.vuln_texts) {
                        descMap[c.vuln_id] = c.vuln_texts || [{ title: "description", content: "No description available" }];
                    }
                }
                setVulnDescriptions(descMap);
            })
            .catch(err => {
                console.error(err);
                setError("Failed to load review data");
                setLoading(false);
            });
    }, [variantId, projectId]);

    const applySearch = () => setSearch(draftSearch.trim());

    useEffect(() => {
        const handleKeyPress = (event: KeyboardEvent) => {
            if (event.key === "Escape") {
                if (editingRow && !editSubmitting) {
                    setEditingRow(null);
                    return;
                }
            }
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
    }, [editingRow, editSubmitting]);

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
        for (const a of [...assessments, ...aiAssessments]) {
            if (a.simplified_status) set.add(a.simplified_status);
        }
        return [...set].sort();
    }, [assessments, aiAssessments]);

    const justificationList = useMemo(() => {
        const set = new Set<string>();
        for (const a of [...assessments, ...aiAssessments]) {
            if (a.justification) set.add(a.justification.replace(/_/g, " "));
        }
        return [...set].sort();
    }, [assessments, aiAssessments]);

    const supplierList = useMemo(() => {
        const set = new Set<string>();
        for (const a of [...assessments, ...aiAssessments]) {
            for (const pkg of a.packages) {
                const name = extractSupplierName(splitPkgId(pkg).supplier);
                if (name) set.add(name);
            }
        }
        return [...set].sort();
    }, [assessments, aiAssessments]);

    const hasSupplierInfo = useMemo(() => supplierList.length > 0, [supplierList]);

    const variantList = useMemo(() => {
        const set = new Set<string>();
        for (const a of [...assessments, ...aiAssessments]) {
            const vids = (a as any)._variantIds ?? (a.variant_id ? [a.variant_id] : []);
            for (const vid of vids) {
                const name = variantNames[vid];
                if (name) set.add(name);
            }
        }
        return [...set].sort();
    }, [assessments, aiAssessments, variantNames]);

    // All variants are checked by default; a variant only leaves the selection
    // once the user explicitly unchecks it. Deriving the selection during render
    // (instead of populating it from an effect) prevents a first-render flash.
    const selectedVariants = useMemo(
        () => variantList.filter(v => !deselectedVariants.includes(v)),
        [variantList, deselectedVariants]
    );
    const setSelectedVariants = useCallback((values: string[]) => {
        setDeselectedVariants(variantList.filter(v => !values.includes(v)));
    }, [variantList]);

    const filteredAssessments = useMemo(() => assessments.filter((a) => {
        if (showOnlyOutdated && !hasOutdatedAssessment(a)) {
            return false;
        }
        if (selectedStatuses.length && !selectedStatuses.includes(a.simplified_status)) {
            return false;
        }
        if (selectedJustifications.length && !(a.justification && selectedJustifications.includes(a.justification.replace(/_/g, " ")))) {
            return false;
        }
        if (selectedSuppliers.length) {
            const rowSuppliers = a.packages.map(p => extractSupplierName(splitPkgId(p).supplier));
            if (!selectedSuppliers.some(s => rowSuppliers.includes(s))) return false;
        }
        {
            const vids = (a as any)._variantIds ?? (a.variant_id ? [a.variant_id] : []);
            const rowVariants = vids.map((vid: string) => variantNames[vid]).filter(Boolean);
            if (rowVariants.length && !selectedVariants.some(v => rowVariants.includes(v))) return false;
        }
        return true;
    }), [assessments, selectedStatuses, selectedJustifications, selectedSuppliers, selectedVariants, variantNames, showOnlyOutdated]);

    // Records the display order (filtered + sorted, deduped by vuln_id) of the
    // currently visible tab's table so the modal can navigate across it. Only one
    // tab's TableGeneric is mounted at a time, so a single ref serves all tabs.
    const handleDisplayedVulnsChange = useCallback((rows: { vuln_id: string }[]) => {
        const seen = new Set<string>();
        const ids: string[] = [];
        for (const r of rows) {
            if (!seen.has(r.vuln_id)) {
                seen.add(r.vuln_id);
                ids.push(r.vuln_id);
            }
        }
        displayedVulnIdsRef.current = ids;
    }, []);

    const resetFilters = () => {
        setSearch('');
        setDraftSearch('');
        setSelectedStatuses([]);
        setSelectedJustifications([]);
        setSelectedSuppliers([]);
        setSelectedVariants(variantList);
        setShowOnlyOutdated(false);
    };

    const transferVariants = useMemo(() => {
        const scopedProjectId = projectId ?? allVariants.find(v => v.id === variantId)?.project_id;
        return scopedProjectId ? allVariants.filter(v => v.project_id === scopedProjectId) : allVariants;
    }, [allVariants, projectId, variantId]);

    const openTransfer = useCallback((mode: 'import' | 'export') => {
        setTransferFormat('custom');
        setImportTimestampPolicy('original');
        setTransferVariantIds(mode === 'export'
            ? variantId ? [variantId] : transferVariants.map(variant => variant.id)
            : []);
        setTransferMode(mode);
    }, [transferVariants, variantId]);

    const changeTransferFormat = useCallback((format: 'custom' | 'openvex') => {
        setTransferFormat(format);
        if (format === 'custom') {
            setTransferVariantIds(transferMode === 'export'
                ? variantId ? [variantId] : transferVariants.map(variant => variant.id)
                : []);
            return;
        }
        const defaultVariantId = variantId && transferVariants.some(v => v.id === variantId)
            ? variantId
            : transferVariants[0]?.id;
        setTransferVariantIds(defaultVariantId ? [defaultVariantId] : []);
    }, [transferMode, transferVariants, variantId]);

    const handleExportReview = useCallback(async () => {
        try {
            const params = new URLSearchParams();
            transferVariantIds.forEach(variantId => params.append('variant_id', variantId));
            const endpoint = transferFormat === 'openvex' ? 'export' : 'export-custom-data';
            const url = new URL(
                import.meta.env.VITE_API_URL + `/api/assessments/review/${endpoint}` +
                (params.toString() ? `?${params.toString()}` : ''),
                window.location.href,
            );
            const res = await fetch(url.toString(), { mode: 'cors' });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showMessage(err.error || 'Failed to export review data.', 'error');
                return;
            }
            const ts = formatTimestampForFilename();
            if (transferFormat === 'openvex') {
                const label = variantNames[transferVariantIds[0]] ?? 'variant';
                downloadJson(await res.json(), `review_openvex_${sanitizeFilename(label)}_${ts}.json`);
            } else {
                const label = transferVariantIds.length === 1 ? variantNames[transferVariantIds[0]] ?? 'variant' : 'all';
                downloadJson(await res.json(), `custom_data_${sanitizeFilename(label)}_${ts}.json`);
            }
            setTransferMode(null);
        } catch (err) {
            console.error('Export error:', err);
            showMessage('Failed to export review data.', 'error');
        }
    }, [showMessage, variantNames, transferVariantIds, transferFormat]);

    const handleImportReview = useCallback(() => {
        setTransferMode(null);
        fileInputRef.current?.click();
    }, []);

    const handleFileSelected = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;

        type ImportResult = {
            status?: string;
            error?: string;
            assessments_imported?: number;
            assessments_skipped?: number;
            cvss_imported?: number;
            time_estimates_imported?: number;
            errors?: { error?: string }[];
        };

        if (transferFormat === 'openvex') {
            setImportStatus("Importing...");
            const formData = new FormData();
            formData.append('file', file);
            formData.append('variant_id', transferVariantIds[0]);
            formData.append('timestamp_policy', importTimestampPolicy);
            fetch(new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/import", window.location.href).toString(), {
                method: 'POST',
                body: formData,
                mode: 'cors',
            })
                .then(response => response.json() as Promise<ImportResult>)
                .then(result => {
                    if (result.status === 'success') {
                        Assessments.listReview(variantId, projectId).then(d => setAssessments(groupAssessments(d)));
                        showMessage('Assessments imported successfully!', 'success');
                    } else {
                        showMessage(`Import error: ${result.error || 'Unknown error'}`, 'error');
                    }
                })
                .catch(err => {
                    console.error(err);
                    showMessage('Import failed', 'error');
                })
                .finally(() => {
                    setImportStatus(null);
                    if (fileInputRef.current) fileInputRef.current.value = '';
                });
            return;
        }

        // VulnScout JSON carries its own variant IDs, so no target selection
        // or override is sent with the request.
        const reader = new FileReader();
        reader.onload = async () => {
            try {
                const text = reader.result as string;
                const parsed = JSON.parse(text);

                if (!parsed?.version || !parsed?.assessments) {
                    showMessage('Invalid file format. Expected a VulnScout custom data export.', 'error');
                    if (fileInputRef.current) fileInputRef.current.value = '';
                    return;
                }

                setImportStatus("Importing...");
                const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/import-custom-data", window.location.href);
                const result = await fetch(url.toString(), {
                    method: 'POST',
                    mode: 'cors',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ...parsed, timestamp_policy: importTimestampPolicy }),
                });
                const data = await result.json() as ImportResult;

                if (data.status === 'success') {
                    Assessments.listReview(variantId, projectId).then(d => setAssessments(groupAssessments(d)));
                    const assessmentsImported = data.assessments_imported ?? 0;
                    const assessmentsSkipped = data.assessments_skipped ?? 0;
                    const cvssImported = data.cvss_imported ?? 0;
                    const timeEstimatesImported = data.time_estimates_imported ?? 0;
                    const summary: string[] = [];
                    if (assessmentsImported > 0) {
                        let msg = `${assessmentsImported} assessment(s) imported`;
                        if (assessmentsSkipped) msg += `, ${assessmentsSkipped} skipped`;
                        summary.push(msg);
                    }
                    if (cvssImported > 0) summary.push(`${cvssImported} CVSS score(s)`);
                    if (timeEstimatesImported > 0) summary.push(`${timeEstimatesImported} time estimate(s)`);
                    if (data.errors?.length) summary.push(`${data.errors.length} error(s)`);
                    showMessage(summary.length > 0 ? `Imported: ${summary.join(', ')}` : 'Import complete (no data changed)', 'success');
                } else {
                    showMessage(`Import error: ${data.errors?.[0]?.error || data.error || 'Unknown error'}`, 'error');
                }
                setImportStatus(null);
            } catch (err) {
                console.error(err);
                showMessage('Import failed — invalid file', 'error');
                setImportStatus(null);
            } finally {
                if (fileInputRef.current) fileInputRef.current.value = '';
            }
        };
        reader.readAsText(file);
    }, [variantId, projectId, showMessage, transferFormat, transferVariantIds, importTimestampPolicy]);

    const handleDeleteRow = useCallback(async () => {
        if (!rowToDelete) return;
        let anyError = false;
        for (const id of rowToDelete._allIds) {
            try {
                const res = await fetch(
                    import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(id)}`,
                    { method: 'DELETE', mode: 'cors' }
                );
                if (!res.ok) anyError = true;
            } catch {
                anyError = true;
            }
        }
        if (!anyError) {
            const updated = await Assessments.listReview(variantId, projectId);
            setAssessments(groupAssessments(updated));
            onAssessmentChanged?.({ type: 'delete', vulnId: rowToDelete.vuln_id, ids: rowToDelete._allIds });
            showMessage('Assessment deleted successfully!', 'success');
        } else {
            showMessage('Failed to delete assessment.', 'error');
        }

        setRowToDelete(null);
    }, [rowToDelete, variantId, projectId, onAssessmentChanged, showMessage]);

    /** Refetch both the handmade and AI-pending assessment lists (used after
     * approving/rejecting a pending AI assessment from the AI Assessments
     * table, since approving moves a row from one list to the other). */
    const refreshAssessmentLists = useCallback(async () => {
        const [reviewData, aiData] = await Promise.all([
            Assessments.listReview(variantId, projectId),
            Assessments.listReviewAi(variantId, projectId),
        ]);
        setAssessments(groupAssessments(reviewData));
        setAiAssessments(groupAssessments(aiData));
    }, [variantId, projectId]);

    const handleApproveAiRow = useCallback(async (row: ReviewRow) => {
        try {
            await Assessments.approveAi(row._allIds[0], row._allIds);
            await refreshAssessmentLists();
            showMessage('AI assessment approved!', 'success');
        } catch (e) {
            showMessage(`Failed to approve AI assessment: ${String(e)}`, 'error');
        }
    }, [refreshAssessmentLists, showMessage]);

    const handleRejectAiRow = useCallback(async (row: ReviewRow) => {
        try {
            await Assessments.rejectAi(row._allIds[0], row._allIds);
            await refreshAssessmentLists();
            showMessage('AI assessment rejected.', 'success');
        } catch (e) {
            showMessage(`Failed to reject AI assessment: ${String(e)}`, 'error');
        }
    }, [refreshAssessmentLists, showMessage]);

    const selectedRows = activeTab === 'assessments'
        ? selectedAssessments
        : activeTab === 'ai-assessments'
            ? selectedAiAssessments
            : activeTab === 'time-estimates'
                ? selectedTimeEstimates
                : selectedCustomCvss;
    const selectedRowCount = Object.keys(selectedRows).length;

    const clearSelectedRows = useCallback((tab: ReviewTab) => {
        if (tab === 'assessments') setSelectedAssessments({});
        else if (tab === 'ai-assessments') setSelectedAiAssessments({});
        else if (tab === 'time-estimates') setSelectedTimeEstimates({});
        else setSelectedCustomCvss({});
    }, []);

    const handleBulkDelete = useCallback(async () => {
        if (!bulkDeleteTab) return;

        try {
            if (bulkDeleteTab === 'assessments') {
                const rows = assessments.filter(row => selectedAssessments[row.id]);
                const ids = rows.flatMap(row => (row as ReviewRow)._allIds ?? [row.id]);
                const responses = await Promise.all(ids.map(id => fetch(
                    import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(id)}`,
                    { method: 'DELETE', mode: 'cors' }
                )));
                if (responses.some(response => !response.ok)) throw new Error('Assessment deletion failed');
                setAssessments(groupAssessments(await Assessments.listReview(variantId, projectId)));
                for (const row of rows) {
                    const assessmentRow = row as ReviewRow;
                    onAssessmentChanged?.({
                        type: 'delete',
                        vulnId: row.vuln_id,
                        ids: assessmentRow._allIds ?? [row.id],
                    });
                }
            } else if (bulkDeleteTab === 'ai-assessments') {
                const rows = aiAssessments.filter(row => selectedAiAssessments[row.id]);
                await Promise.all(rows.map(row => {
                    const assessmentRow = row as ReviewRow;
                    const ids = assessmentRow._allIds ?? [row.id];
                    return Assessments.rejectAi(ids[0], ids);
                }));
                await refreshAssessmentLists();
            } else if (bulkDeleteTab === 'time-estimates') {
                const ids = Object.keys(selectedTimeEstimates);
                const response = await fetch(import.meta.env.VITE_API_URL + '/api/assessments/review/time-estimates', {
                    method: 'DELETE',
                    mode: 'cors',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ids }),
                });
                if (!response.ok) throw new Error('Time estimate deletion failed');
                setTimeEstimates(await Assessments.listReviewTimeEstimates(variantId, projectId));
            } else {
                const ids = Object.keys(selectedCustomCvss);
                const response = await fetch(import.meta.env.VITE_API_URL + '/api/assessments/review/custom-cvss', {
                    method: 'DELETE',
                    mode: 'cors',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ids }),
                });
                if (!response.ok) throw new Error('Custom CVSS deletion failed');
                const refreshed = await Assessments.listReviewCustomCvss(variantId, projectId);
                setCustomCvss(refreshed.filter(item => item.origin === 'custom'));
            }
            clearSelectedRows(bulkDeleteTab);
            showMessage(`${selectedRowCount} item${selectedRowCount === 1 ? '' : 's'} deleted successfully!`, 'success');
        } catch (error) {
            console.error(error);
            showMessage('Failed to delete selected items.', 'error');
        } finally {
            setBulkDeleteTab(null);
        }
    }, [
        aiAssessments,
        assessments,
        bulkDeleteTab,
        clearSelectedRows,
        onAssessmentChanged,
        projectId,
        refreshAssessmentLists,
        selectedAiAssessments,
        selectedAssessments,
        selectedCustomCvss,
        selectedRowCount,
        selectedTimeEstimates,
        showMessage,
        variantId,
    ]);

    const handleSaveEdit = useCallback(async (data: EditAssessmentData) => {
        if (!editingRow) return;
        setEditSubmitting(true);

        // Share a single timestamp across all rows created in this edit action.
        const editSharedTimestamp = new Date().toISOString();

        // Target (package × variant) combos from the form selection.
        const targetVariantIds: Array<string | undefined> =
            data.variant_ids && data.variant_ids.length > 0 ? data.variant_ids : [undefined];
        const targetPackages: string[] =
            data.packages && data.packages.length > 0 ? data.packages : editingRow.packages;

        // Existing group assessments indexed by (package, variant) key.
        const existingByKey = new Map<string, Assessment>();
        for (const a of editingRow._assessments) {
            const pkg = a.packages[0] ?? '';
            const vid = a.variant_id ?? '';
            existingByKey.set(`${pkg}::${vid}`, a);
        }

        // Desired set of (package, variant) keys after the edit.
        const targetKeys = new Set<string>();
        for (const pkg of targetPackages) {
            for (const vid of targetVariantIds) {
                targetKeys.add(`${pkg}::${vid ?? ''}`);
            }
        }

        let anyError = false;

        // 1. Update combos that persist, delete combos that were deselected.
        for (const [key, existing] of existingByKey) {
            try {
                if (targetKeys.has(key)) {
                    const res = await fetch(
                        import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(existing.id)}`,
                        {
                            method: 'PUT',
                            mode: 'cors',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                status: data.status,
                                justification: data.justification,
                                impact_statement: data.impact_statement,
                                status_notes: data.status_notes,
                                workaround: data.workaround,
                            }),
                        }
                    );
                    if (!res.ok) anyError = true;
                } else {
                    const res = await fetch(
                        import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(existing.id)}`,
                        { method: 'DELETE', mode: 'cors' }
                    );
                    if (!res.ok) anyError = true;
                }
            } catch {
                anyError = true;
            }
        }

        // 2. Create newly-selected combos — batch packages per variant so the
        //    new rows share one timestamp.
        const newPkgsByVariant = new Map<string | undefined, string[]>();
        for (const pkg of targetPackages) {
            for (const vid of targetVariantIds) {
                const key = `${pkg}::${vid ?? ''}`;
                if (!existingByKey.has(key)) {
                    const arr = newPkgsByVariant.get(vid) ?? [];
                    arr.push(pkg);
                    newPkgsByVariant.set(vid, arr);
                }
            }
        }

        for (const [vid, pkgs] of newPkgsByVariant) {
            if (pkgs.length === 0) continue;
            try {
                const body: Record<string, unknown> = {
                    vuln_id: editingRow.vuln_id,
                    packages: pkgs,
                    status: data.status,
                    justification: data.justification,
                    impact_statement: data.impact_statement,
                    status_notes: data.status_notes,
                    workaround: data.workaround,
                    timestamp: editSharedTimestamp,
                };
                if (vid) body.variant_id = vid;
                const res = await fetch(
                    import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(editingRow.vuln_id)}/assessments`,
                    {
                        method: 'POST',
                        mode: 'cors',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                    }
                );
                if (!res.ok) anyError = true;
            } catch {
                anyError = true;
            }
        }

        if (!anyError) {
            const updated = await Assessments.listReview(variantId, projectId);
            setAssessments(groupAssessments(updated));
            setEditingRow(null);
            onAssessmentChanged?.({ type: 'update', vulnId: editingRow.vuln_id, ids: editingRow._allIds, data });
            showMessage('Assessment updated successfully!', 'success');
        } else {
            showMessage('Failed to update assessment.', 'error');
        }
        setEditSubmitting(false);
    }, [editingRow, variantId, projectId, onAssessmentChanged, showMessage]);

    const fetchVulnForModal = useCallback(async (vulnId: string): Promise<Vulnerability | undefined> => {
        try {
            const [vulnRes, assessRes] = await Promise.all([
                fetch(`${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(vulnId)}`, { mode: 'cors' }),
                fetch(`${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(vulnId)}/assessments`, { mode: 'cors' }),
            ]);
            if (!vulnRes.ok) throw new Error(`HTTP ${vulnRes.status}`);
            const vulnData = await vulnRes.json();
            const vuln = asVulnerability(vulnData);
            if (Array.isArray(vuln)) return undefined;

            if (assessRes.ok) {
                const assessData = await assessRes.json();
                vuln.assessments = (assessData as any[])
                    .flatMap(asAssessment)
                    .filter((a) => a.origin !== 'ai');
            }
            return vuln;
        } catch (err) {
            console.error("Failed to load vulnerability:", err);
            return undefined;
        }
    }, []);

    // Opens the modal with navigation context so the modal renders Previous/Next
    // buttons across the vulnerabilities currently displayed in the active tab.
    const handleVulnClickWithNav = useCallback(async (vulnId: string) => {
        const gen = ++fetchGenRef.current;
        const vuln = await fetchVulnForModal(vulnId);
        if (gen !== fetchGenRef.current) return;
        if (!vuln) return;
        const displayedIds = displayedVulnIdsRef.current;
        const index = displayedIds.indexOf(vulnId);
        setModalVuln(vuln);
        setModalVulnIds(displayedIds);
        setModalVulnIndex(index >= 0 ? index : undefined);
    }, [fetchVulnForModal]);

    const handleModalNavigation = useCallback(async (newIndex: number) => {
        if (newIndex < 0 || newIndex >= modalVulnIds.length) return;
        const gen = ++fetchGenRef.current;
        const vuln = await fetchVulnForModal(modalVulnIds[newIndex]);
        if (gen !== fetchGenRef.current) return;
        if (!vuln) return;
        setModalVuln(vuln);
        setModalVulnIndex(newIndex);
    }, [fetchVulnForModal, modalVulnIds]);


    const columns = useMemo(() => [
        createSelectionColumn<ReviewRow>(),
        columnHelper.accessor("vuln_id", {
            id: 'id',
            header: () => <div className="flex items-center justify-center">Vulnerability</div>,
            size: 130,
            cell: info => (
                <div
                    className="flex items-center justify-center w-full h-full text-center cursor-pointer hover:bg-slate-700 hover:text-blue-300 transition-colors p-4"
                    onClick={() => handleVulnClickWithNav(info.getValue())}
                    title="Click to view details"
                >
                    <span className="font-mono text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
        columnHelper.accessor("packages", {
            header: () => <div className="flex items-center justify-center">SBOM Affected</div>,
            size: 170,
            cell: info => {
                const pkgs = info.getValue();
                if (!pkgs || pkgs.length === 0) return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">—</span></div>;
                return (
                    <div className="flex flex-wrap gap-1 items-center justify-center h-full">
                        {pkgs.map(p => (
                            <span key={p} className="bg-gray-600 text-gray-200 text-xs px-1.5 py-0.5 rounded font-mono">
                                {splitPkgId(p).nameVersion}
                            </span>
                        ))}
                    </div>
                );
            },
        }),
        columnHelper.display({
            id: 'supplier',
            header: () => <div className="flex items-center justify-center">Supplier</div>,
            size: 160,
            cell: info => {
                const pkgs = info.row.original.packages;
                const suppliers = [...new Set(
                    pkgs.map(p => extractSupplierName(splitPkgId(p).supplier)).filter(s => s !== '')
                )];
                if (suppliers.length === 0) return <div className="flex items-center justify-center h-full text-neutral-500">—</div>;
                return (
                    <div className="flex flex-wrap gap-1 items-center justify-center h-full">
                        {suppliers.map(s => (
                            <span key={s} className="bg-gray-600 text-gray-200 text-xs px-1.5 py-0.5 rounded">
                                {s}
                            </span>
                        ))}
                    </div>
                );
            },
            enableSorting: false,
        }),
        columnHelper.accessor("variant_id", {
            header: () => <div className="flex items-center justify-center">Variants</div>,
            size: 120,
            cell: info => {
                const row = info.row.original as ReviewRow;
                const vids = row._variantIds ?? (row.variant_id ? [row.variant_id] : []);
                if (vids.length === 0) return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">—</span></div>;
                return (
                    <div className="flex flex-wrap gap-1 items-center justify-center h-full">
                        {vids.map(vid => {
                            const name = variantNames[vid] ?? vid.slice(0, 8);
                            const variantAssessments = (row._assessments ?? [row]).filter(a => a.variant_id === vid);
                            const isOutdated = variantAssessments.length > 0 && variantAssessments.every(a =>
                                a.outdated === true
                                || (a.packages.length > 0 && a.packages.every(pkg => (a.superseded_map?.[pkg]?.length ?? 0) > 0))
                            );
                            return (
                                <span
                                    key={vid}
                                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${isOutdated ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300' : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'}`}
                                    title={isOutdated ? 'Package version is not present in this variant’s current SBOM' : undefined}
                                >
                                    {name}
                                    {isOutdated && <span className="ml-1.5 text-[10px] font-semibold uppercase tracking-wide">Outdated</span>}
                                </span>
                            );
                        })}
                    </div>
                );
            },
        }),
        columnHelper.accessor("simplified_status", {
            header: () => <div className="flex items-center justify-center">Status</div>,
            size: 110,
            cell: info => {
                return (
                    <div className="flex items-center justify-center h-full">
                        <code>{info.getValue()}</code>
                    </div>
                );
            },
        }),
        columnHelper.accessor("justification", {
            header: () => <div className="flex items-center justify-center">Justification</div>,
            size: 140,
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
        columnHelper.accessor("impact_statement", {
            header: () => <div className="flex items-center justify-center">Impact</div>,
            size: 180,
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
            size: 180,
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
        columnHelper.accessor("workaround", {
            header: () => <div className="flex items-center justify-center">Workaround</div>,
            size: 180,
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
            size: 130,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm text-gray-300">{formatDate(info.getValue())}</span>
                </div>
            ),
        }),
        columnHelper.display({
            id: 'actions',
            header: () => <div className="flex items-center justify-center">Actions</div>,
            size: 70,
            cell: info => (
                <div className="flex items-center justify-center gap-3 h-full">
                    <button
                        onClick={() => setEditingRow(info.row.original)}
                        className="text-blue-400 hover:text-blue-300 transition-colors"
                        title="Edit assessment"
                    >
                        <FontAwesomeIcon icon={faPenToSquare} className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => setRowToDelete(info.row.original)}
                        className="text-red-400 hover:text-red-300 transition-colors"
                        title="Delete assessment"
                    >
                        <FontAwesomeIcon icon={faTrash} className="w-4 h-4" />
                    </button>
                </div>
            ),
        }),
    ], [handleVulnClickWithNav, variantNames]);

    const aiActionsColumn = useMemo(() => columnHelper.display({
        id: 'ai-actions',
        header: () => <div className="flex items-center justify-center">Actions</div>,
        size: 110,
        cell: info => (
            <div className="flex flex-wrap items-center justify-center gap-2 h-full">
                <button
                    onClick={() => handleApproveAiRow(info.row.original)}
                    className="px-2 py-1 rounded bg-green-600 hover:bg-green-500 text-white text-xs flex items-center gap-1"
                    title="Approve AI suggestion"
                >
                    <FontAwesomeIcon icon={faCheck} className="w-3 h-3" />
                    Approve
                </button>
                <button
                    onClick={() => handleRejectAiRow(info.row.original)}
                    className="px-2 py-1 rounded bg-red-600 hover:bg-red-500 text-white text-xs flex items-center gap-1"
                    title="Reject AI suggestion"
                >
                    <FontAwesomeIcon icon={faXmark} className="w-3 h-3" />
                    Reject
                </button>
            </div>
        ),
    }), [handleApproveAiRow, handleRejectAiRow]);

    const aiColumns = useMemo(
        () => columns.map(c => (c.id === 'actions' ? aiActionsColumn : c)),
        [columns, aiActionsColumn]
    );

    const teColumns = useMemo(() => [
        createSelectionColumn<ReviewTimeEstimateRow>(),
        teColumnHelper.accessor("vuln_id", {
            id: 'te_vuln_id',
            header: () => <div className="flex items-center justify-center">Vulnerability</div>,
            size: 160,
            cell: info => (
                <div
                    className="flex items-center justify-center w-full h-full text-center cursor-pointer hover:bg-slate-700 hover:text-blue-300 transition-colors p-4"
                    onClick={() => handleVulnClickWithNav(info.getValue())}
                    title="Click to view details"
                >
                    <span className="font-mono text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
        teColumnHelper.accessor("variant_id", {
            header: () => <div className="flex items-center justify-center">Variant</div>,
            size: 150,
            cell: info => {
                const variant = info.getValue();
                if (!variant) {
                    return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">-</span></div>;
                }
                return (
                    <div className="flex items-center justify-center h-full">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                            {variantNames[variant] ?? variant.slice(0, 8)}
                        </span>
                    </div>
                );
            },
        }),
        teColumnHelper.accessor("optimistic", {
            header: () => <div className="flex items-center justify-center">Optimistic (h)</div>,
            size: 120,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm font-mono">{info.getValue()}h</span>
                </div>
            ),
        }),
        teColumnHelper.accessor("likely", {
            header: () => <div className="flex items-center justify-center">Likely (h)</div>,
            size: 120,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm font-mono">{info.getValue()}h</span>
                </div>
            ),
        }),
        teColumnHelper.accessor("pessimistic", {
            header: () => <div className="flex items-center justify-center">Pessimistic (h)</div>,
            size: 120,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm font-mono">{info.getValue()}h</span>
                </div>
            ),
        }),
    ], [handleVulnClickWithNav, variantNames]);

    const cvssColumns = useMemo(() => [
        createSelectionColumn<ReviewCustomCvssRow>(),
        cvssColumnHelper.accessor("vuln_id", {
            id: 'cvss_vuln_id',
            header: () => <div className="flex items-center justify-center">Vulnerability</div>,
            size: 160,
            cell: info => (
                <div
                    className="flex items-center justify-center w-full h-full text-center cursor-pointer hover:bg-slate-700 hover:text-blue-300 transition-colors p-4"
                    onClick={() => handleVulnClickWithNav(info.getValue())}
                    title="Click to view details"
                >
                    <span className="font-mono text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
        cvssColumnHelper.accessor("variant_id", {
            header: () => <div className="flex items-center justify-center">Variant</div>,
            size: 150,
            cell: info => {
                const variant = info.getValue();
                if (!variant) {
                    return <div className="flex items-center justify-center h-full"><span className="text-gray-500 italic">-</span></div>;
                }
                return (
                    <div className="flex items-center justify-center h-full">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                            {variantNames[variant] ?? variant.slice(0, 8)}
                        </span>
                    </div>
                );
            },
        }),
        cvssColumnHelper.accessor("version", {
            header: () => <div className="flex items-center justify-center">CVSS Version</div>,
            size: 110,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
        cvssColumnHelper.accessor("vector_string", {
            header: () => <div className="flex items-center justify-center">Vector</div>,
            size: 350,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-xs font-mono break-all">{info.getValue()}</span>
                </div>
            ),
        }),
        cvssColumnHelper.accessor("base_score", {
            header: () => <div className="flex items-center justify-center">Base Score</div>,
            size: 100,
            cell: info => {
                const score = info.getValue();
                let color = "text-gray-300";
                if (score >= 9.0) color = "text-red-400";
                else if (score >= 7.0) color = "text-orange-400";
                else if (score >= 4.0) color = "text-yellow-400";
                else if (score > 0) color = "text-green-400";
                return (
                    <div className="flex items-center justify-center h-full">
                        <span className={`text-sm font-bold ${color}`}>{score.toFixed(1)}</span>
                    </div>
                );
            },
        }),
        cvssColumnHelper.accessor("author", {
            header: () => <div className="flex items-center justify-center">Author</div>,
            size: 120,
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <span className="text-sm">{info.getValue()}</span>
                </div>
            ),
        }),
    ], [handleVulnClickWithNav, variantNames]);

    if (loading) {
        return (
            <div className="relative h-64">
                <div className="absolute inset-0 z-50 flex items-center justify-center">
                    <div className="flex flex-col items-center gap-3 text-gray-300">
                        <div className="w-10 h-10 border-4 border-gray-400 border-t-transparent rounded-full animate-spin"></div>
                        <span className="text-sm font-semibold">Loading assessments...</span>
                    </div>
                </div>
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

    const filterReviewRows = (list: Assessment[]) => list.filter((a) => {
        if (showOnlyOutdated && !hasOutdatedAssessment(a)) {
            return false;
        }
        if (selectedStatuses.length && !selectedStatuses.includes(a.simplified_status)) {
            return false;
        }
        if (selectedJustifications.length && !(a.justification && selectedJustifications.includes(a.justification.replace(/_/g, " ")))) {
            return false;
        }
        if (selectedSuppliers.length) {
            const rowSuppliers = a.packages.map(p => extractSupplierName(splitPkgId(p).supplier));
            if (!selectedSuppliers.some(s => rowSuppliers.includes(s))) return false;
        }
        {
            const vids = (a as any)._variantIds ?? (a.variant_id ? [a.variant_id] : []);
            const rowVariants = vids.map((vid: string) => variantNames[vid]).filter(Boolean);
            if (rowVariants.length && !selectedVariants.some(v => rowVariants.includes(v))) return false;
        }
        return true;
    });

    const filteredAiAssessments = filterReviewRows(aiAssessments);

    /** Shared renderer for the "assessments" and "ai-assessments" tabs: both
     * show the same empty-state shape and the same TableGeneric<ReviewRow>
     * setup, differing only in which rows/columns/copy are passed in. */
    const renderAssessmentsTable = (
        rows: Assessment[],
        cols: any[],
        emptyTitle: string,
        emptyBody: string,
        onFilteredDataChange?: (rows: ReviewRow[]) => void,
        selected?: RowSelectionState,
        updateSelected?: OnChangeFn<RowSelectionState>,
    ) => (
        rows.length === 0 ? (
            <div className="text-center py-10 text-gray-400">
                <p className="text-lg">{emptyTitle}</p>
                <p className="text-sm mt-2">{emptyBody}</p>
            </div>
        ) : (
            <TableGeneric<ReviewRow>
                columns={cols}
                data={rows.map(a => ({
                    ...a,
                    texts: vulnDescriptions[a.vuln_id] ?? [],
                    _allIds: (a as any)._allIds ?? [a.id],
                    _variantIds: (a as any)._variantIds ?? (a.variant_id ? [a.variant_id] : []),
                    _assessments: (a as any)._assessments ?? [a],
                    extractedSuppliers: [...new Set(
                        a.packages.map(p => extractSupplierName(splitPkgId(p).supplier)).filter(s => s !== '')
                    )],
                }))}
                search={search}
                fuseKeys={["vuln_id", "packages", "simplified_status", "status_notes", "justification", "workaround", "extractedSuppliers"]}
                forAllValues={(row) => row.packages}
                estimateRowHeight={50}
                hasPagination={true}
                hoverField="texts"
                hoverIdField="vuln_id"
                onFilteredDataChange={onFilteredDataChange}
                selected={selected}
                updateSelected={updateSelected}
            />
        )
    );

    return (
        <div>
            <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
                <ExplicitSearchInput
                    id="review-search"
                    ref={searchInputRef}
                    value={draftSearch}
                    onChange={setDraftSearch}
                    onSearch={applySearch}
                    label="Search"
                    placeholder="Search by vulnerability, package, status, ..."
                    ariaLabel="Search reviews"
                />

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

                {(activeTab === 'assessments' || activeTab === 'ai-assessments') && (
                    <>
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

                        {hasSupplierInfo && (
                            <FilterOption
                                label="Supplier"
                                options={supplierList}
                                selected={selectedSuppliers}
                                setSelected={setSelectedSuppliers}
                            />
                        )}

                        {variantList.length > 0 && (
                            <FilterOption
                                label="Variants"
                                options={variantList}
                                selected={selectedVariants}
                                setSelected={setSelectedVariants}
                            />
                        )}

                        <ToggleSwitch
                            enabled={showOnlyOutdated}
                            setEnabled={setShowOnlyOutdated}
                            label="Outdated"
                        />
                        <div className="flex items-center mx-3">
                            <div className="border-l h-8 dark:border-neutral-300"></div>
                        </div>
                    </>
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

                    {selectedRowCount > 0 && (
                        <button
                            onClick={() => setBulkDeleteTab(activeTab)}
                            className="bg-red-700 hover:bg-red-600 px-3 py-1 rounded text-white border border-red-500 flex items-center gap-1.5"
                            title="Delete selected items"
                        >
                            <FontAwesomeIcon icon={faTrash} />
                            Delete selected ({selectedRowCount})
                        </button>
                    )}

                    <button
                        onClick={() => openTransfer('import')}
                        className="bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5"
                        title="Import review data"
                    >
                        <FontAwesomeIcon icon={faFileImport} />
                        Import
                    </button>
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".json,application/json"
                        className="hidden"
                        onChange={handleFileSelected}
                    />

                    <button
                        onClick={() => openTransfer('export')}
                        className="bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-white border border-green-500 flex items-center gap-1.5"
                        title="Export review data"
                    >
                        <FontAwesomeIcon icon={faFileExport} />
                        Export
                    </button>
                </div>
            </div>

            {transferMode && (
                <ReviewTransferModal
                    mode={transferMode}
                    variants={transferVariants}
                    selectedVariantIds={transferVariantIds}
                    transferFormat={transferFormat}
                    timestampPolicy={importTimestampPolicy}
                    onSelectedVariantIdsChange={setTransferVariantIds}
                    onTransferFormatChange={changeTransferFormat}
                    onTimestampPolicyChange={setImportTimestampPolicy}
                    onConfirm={transferMode === 'export' ? handleExportReview : handleImportReview}
                    onCancel={() => setTransferMode(null)}
                />
            )}

            {showBanner && (
                <div className="sticky top-0 z-10">
                    <MessageBanner
                        type={bannerType}
                        message={bannerMessage}
                        isVisible={showBanner}
                        onClose={() => setShowBanner(false)}
                    />
                </div>
            )}

            {importStatus && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
                    <div className="flex flex-col items-center gap-3 text-white">
                        {importStatus === "Importing..." && (
                            <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                        )}
                        <span className="text-sm font-semibold">{importStatus}</span>
                    </div>
                </div>
            )}

            <div className="mb-3 flex items-center gap-1 border-b border-gray-700">
                <button
                    className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                        activeTab === 'assessments'
                            ? 'bg-sky-800 text-white border-b-2 border-sky-400'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                    }`}
                    onClick={() => setActiveTab('assessments')}
                >
                    Assessments
                </button>
                <button
                    className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                        activeTab === 'time-estimates'
                            ? 'bg-sky-800 text-white border-b-2 border-sky-400'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                    }`}
                    onClick={() => setActiveTab('time-estimates')}
                >
                    Time Estimates
                </button>
                <button
                    className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                        activeTab === 'custom-cvss'
                            ? 'bg-sky-800 text-white border-b-2 border-sky-400'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                    }`}
                    onClick={() => setActiveTab('custom-cvss')}
                >
                    Custom CVSS
                </button>
                <button
                    className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                        activeTab === 'ai-assessments'
                            ? 'bg-sky-800 text-white border-b-2 border-sky-400'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                    }`}
                    onClick={() => setActiveTab('ai-assessments')}
                >
                    AI Assessments
                </button>
            </div>

            {activeTab === 'assessments' && renderAssessmentsTable(
                filteredAssessments,
                columns,
                "No handmade assessments found",
                "Assessments created directly in VulnScout (not imported from SBOM documents) will appear here.",
                handleDisplayedVulnsChange,
                selectedAssessments,
                setSelectedAssessments,
            )}

            {activeTab === 'ai-assessments' && renderAssessmentsTable(
                filteredAiAssessments,
                aiColumns,
                "No AI-generated assessments found",
                "Pending assessments suggested by AI will appear here until approved or rejected.",
                handleDisplayedVulnsChange,
                selectedAiAssessments,
                setSelectedAiAssessments,
            )}

            {activeTab === 'time-estimates' && (
                timeEstimates.length === 0 ? (
                    <div className="text-center py-10 text-gray-400">
                        <p className="text-lg">No time estimates found</p>
                        <p className="text-sm mt-2">
                            Time estimates added to vulnerabilities will appear here.
                        </p>
                    </div>
                ) : (
                    <TableGeneric<ReviewTimeEstimateRow>
                        columns={teColumns as any}
                        data={timeEstimates.map(te => ({
                            ...te,
                            texts: vulnDescriptions[te.vuln_id] ?? [],
                        }))}
                        search={search}
                        fuseKeys={["vuln_id", "variant_id"]}
                        estimateRowHeight={50}
                        hasPagination={true}
                        hoverField="texts"
                        hoverIdField="vuln_id"
                        onFilteredDataChange={handleDisplayedVulnsChange}
                        selected={selectedTimeEstimates}
                        updateSelected={setSelectedTimeEstimates}
                    />
                )
            )}

            {activeTab === 'custom-cvss' && (
                customCvss.length === 0 ? (
                    <div className="text-center py-10 text-gray-400">
                        <p className="text-lg">No custom CVSS scores found</p>
                        <p className="text-sm mt-2">
                            Custom CVSS scores added to vulnerabilities will appear here.
                        </p>
                    </div>
                ) : (
                    <TableGeneric<ReviewCustomCvssRow>
                        columns={cvssColumns as any}
                        data={customCvss.map(c => ({
                            ...c,
                            texts: vulnDescriptions[c.vuln_id] ?? [],
                        }))}
                        search={search}
                        fuseKeys={["vuln_id", "variant_id", "vector_string", "author"]}
                        estimateRowHeight={50}
                        hasPagination={true}
                        hoverField="texts"
                        hoverIdField="vuln_id"
                        onFilteredDataChange={handleDisplayedVulnsChange}
                        selected={selectedCustomCvss}
                        updateSelected={setSelectedCustomCvss}
                    />
                )
            )}

            {modalVuln && (
                <VulnModal
                    vuln={modalVuln}
                    readOnly={true}
                    appendAssessment={() => {}}
                    appendCVSS={() => null}
                    patchVuln={() => {}}
                    onClose={() => {
                        // Invalidate any in-flight fetch so its late completion
                        // cannot re-open the modal with a stale vulnerability.
                        fetchGenRef.current++;
                        setModalVuln(undefined);
                        setModalVulnIndex(undefined);
                        setModalVulnIds([]);
                    }}
                    vulnerabilities={modalVulnIndex !== undefined ? modalVulnIds.map(id => ({ id } as unknown as Vulnerability)) : undefined}
                    currentIndex={modalVulnIndex}
                    onNavigate={handleModalNavigation}
                />
            )}

            <ConfirmationModal
                isOpen={rowToDelete !== null}
                title="Delete Assessment"
                message="Are you sure you want to delete this assessment? This action cannot be undone."
                confirmText="Yes, delete"
                cancelText="Cancel"
                showTitleIcon={true}
                onConfirm={handleDeleteRow}
                onCancel={() => setRowToDelete(null)}
            />

            <ConfirmationModal
                isOpen={bulkDeleteTab !== null}
                title={`Delete ${selectedRowCount} selected item${selectedRowCount === 1 ? '' : 's'}`}
                message="Are you sure you want to delete the selected items? This action cannot be undone."
                confirmText="Yes, delete"
                cancelText="Cancel"
                showTitleIcon={true}
                onConfirm={handleBulkDelete}
                onCancel={() => setBulkDeleteTab(null)}
            />

            {editingRow && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => !editSubmitting && setEditingRow(null)}>
                    <div className="bg-gray-900 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                        <h3 className="text-base font-bold text-gray-400 mb-4 font-mono">{editingRow.vuln_id}</h3>
                        {editSubmitting ? (
                            <div className="flex items-center justify-center py-8">
                                <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                            </div>
                        ) : (
                            <EditAssessment
                                assessment={editingRow}
                                onSaveAssessment={handleSaveEdit}
                                onCancel={() => setEditingRow(null)}
                                triggerBanner={showMessage}
                                availableVariants={editVariants}
                                defaultSelectedVariantIds={editingRow._variantIds}
                                availablePackages={editingRow.packages}
                                defaultSelectedPackages={editingRow.packages}
                                variantPackageMap={Object.keys(editVariantPackageMap).length > 0 ? editVariantPackageMap : undefined}
                            />
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

export default Review;
