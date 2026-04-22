import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import TableGeneric from "../components/TableGeneric";
import Assessments from "../handlers/assessments";
import type { Assessment } from "../handlers/assessments";
import { asAssessment } from "../handlers/assessments";
import type { Vulnerability } from "../handlers/vulnerabilities";
import { asVulnerability } from "../handlers/vulnerabilities";
import VulnModal from "../components/VulnModal";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion, faCircleInfo, faFileExport, faFileImport, faPenToSquare, faTrash } from '@fortawesome/free-solid-svg-icons';
import EditAssessment from '../components/EditAssessment';
import type { EditAssessmentData } from '../components/EditAssessment';
import type { Variant } from '../handlers/variant';
import ConfirmationModal from '../components/ConfirmationModal';
import MessageBanner from '../components/MessageBanner';
import Variants from '../handlers/variant';

type AssessmentMutation =
    | { type: 'delete'; vulnId: string; ids: string[] }
    | { type: 'update'; vulnId: string; ids: string[]; data: EditAssessmentData };

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
};

const columnHelper = createColumnHelper<ReviewRow>();

/**
 * Group assessments that share the same CVE, status, justification, notes,
 * workaround and impact into a single row — merging packages, variants and
 * keeping the most recent timestamp.
 */
function groupAssessments(assessments: Assessment[]): Assessment[] {
    const groups = new Map<string, Assessment>();
    const allIds = new Map<string, string[]>();
    const variantIds = new Map<string, Set<string>>();
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
            if (a.variant_id) variantIds.get(key)!.add(a.variant_id);
        } else {
            groups.set(key, { ...a, packages: [...a.packages] });
            allIds.set(key, [a.id]);
            const vs = new Set<string>();
            if (a.variant_id) vs.add(a.variant_id);
            variantIds.set(key, vs);
        }
    }
    const result: Assessment[] = [];
    for (const [key, group] of groups) {
        (group as any)._allIds = allIds.get(key)!;
        (group as any)._variantIds = [...variantIds.get(key)!];
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

function Review({ variantId, projectId, onAssessmentChanged }: Readonly<Props>) {
    const [assessments, setAssessments] = useState<Assessment[]>([]);
    const [vulnDescriptions, setVulnDescriptions] = useState<Record<string, { title: string; content: string }[]>>({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [search, setSearch] = useState<string>('');
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedJustifications, setSelectedJustifications] = useState<string[]>([]);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [showSearchHelper, setShowSearchHelper] = useState(false);
    const [importStatus, setImportStatus] = useState<string | null>(null);
    const [variantNames, setVariantNames] = useState<Record<string, string>>({});
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [editingRow, setEditingRow] = useState<ReviewRow | null>(null);
    const [editSubmitting, setEditSubmitting] = useState(false);
    const [rowToDelete, setRowToDelete] = useState<ReviewRow | null>(null);
    const [bannerMessage, setBannerMessage] = useState("");
    const [bannerType, setBannerType] = useState<"error" | "success">("success");
    const [showBanner, setShowBanner] = useState(false);

    const showMessage = useCallback((message: string, type: "error" | "success") => {
        setBannerMessage(message);
        setBannerType(type);
        setShowBanner(true);
    }, []);
    const [modalVuln, setModalVuln] = useState<Vulnerability | undefined>(undefined);
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
        Variants.listAll().then(vs => {
            const map: Record<string, string> = {};
            for (const v of vs) map[v.id] = v.name;
            setVariantNames(map);
            setAllVariants(vs);
        }).catch(() => {});
    }, []);

    useEffect(() => {
        setLoading(true);
        setError(null);
        Assessments.listReview(variantId, projectId)
            .then(data => {
                setAssessments(groupAssessments(data));
                setLoading(false);
                // Build tooltip descriptions from vuln_texts included in the response
                const descMap: Record<string, { title: string; content: string }[]> = {};
                for (const a of data) {
                    if (a.vuln_id && !descMap[a.vuln_id] && a.vuln_texts) {
                        const entries = Object.entries(a.vuln_texts);
                        descMap[a.vuln_id] = entries.length > 0
                            ? entries.map(([title, content]) => ({ title, content }))
                            : [{ title: "description", content: "No description available" }];
                    }
                }
                setVulnDescriptions(descMap);
            })
            .catch(err => {
                console.error(err);
                setError("Failed to load review assessments");
                setLoading(false);
            });
    }, [variantId, projectId]);

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 550, { maxWait: 2500 });

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
        fetch(url.toString(), { mode: 'cors' })
            .then(res => {
                if (!res.ok) throw new Error(`Export failed (${res.status})`);
                return res.blob();
            })
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'review_openvex.tar.gz';
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(a.href);
            })
            .catch(err => console.error('Export error:', err));
    }, []);

    const handleImportReview = useCallback(() => {
        fileInputRef.current?.click();
    }, []);

    const handleFileSelected = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/import", window.location.href);
        setImportStatus("Importing...");
        fetch(url.toString(), { method: 'POST', body: formData, mode: 'cors' })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    // Reload the assessments list
                    Assessments.listReview(variantId, projectId).then(data => setAssessments(groupAssessments(data)));
                } else {
                    setImportStatus(`Error: ${data.error || 'Unknown error'}`);
                    setTimeout(() => setImportStatus(null), 4000);
                    return;
                }
                setImportStatus(null);
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
    }, [variantId, projectId]);

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

    const handleSaveEdit = useCallback(async (data: EditAssessmentData) => {
        if (!editingRow) return;
        setEditSubmitting(true);
        let anyError = false;
        for (const id of editingRow._allIds) {
            try {
                const res = await fetch(
                    import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(id)}`,
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

    const handleVulnClick = useCallback(async (vulnId: string) => {
        try {
            const [vulnRes, assessRes] = await Promise.all([
                fetch(`${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(vulnId)}`, { mode: 'cors' }),
                fetch(`${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(vulnId)}/assessments`, { mode: 'cors' }),
            ]);
            if (!vulnRes.ok) throw new Error(`HTTP ${vulnRes.status}`);
            const vulnData = await vulnRes.json();
            const vuln = asVulnerability(vulnData);
            if (Array.isArray(vuln)) return;

            if (assessRes.ok) {
                const assessData = await assessRes.json();
                vuln.assessments = (assessData as any[]).flatMap(asAssessment);
            }
            setModalVuln(vuln);
        } catch (err) {
            console.error("Failed to load vulnerability:", err);
        }
    }, []);

    const columns = useMemo(() => [
        columnHelper.accessor("vuln_id", {
            id: 'id',
            header: () => <div className="flex items-center justify-center">Vulnerability</div>,
            size: 130,
            cell: info => (
                <div
                    className="flex items-center justify-center w-full h-full text-center cursor-pointer hover:bg-slate-700 hover:text-blue-300 transition-colors p-4"
                    onClick={() => handleVulnClick(info.getValue())}
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
                                {p}
                            </span>
                        ))}
                    </div>
                );
            },
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
                            return (
                                <span key={vid} className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                    {name}
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
            cell: info => (
                <div className="flex items-center justify-center h-full">
                    <code>{info.getValue()}</code>
                </div>
            ),
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
    ], [handleVulnClick, variantNames]);

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
            <div>
                {showBanner && (
                    <MessageBanner
                        type={bannerType}
                        message={bannerMessage}
                        isVisible={showBanner}
                        onClose={() => setShowBanner(false)}
                    />
                )}
                <div className="text-center py-10 text-gray-400">
                    <p className="text-lg">No handmade assessments found</p>
                    <p className="text-sm mt-2">
                        Assessments created directly in VulnScout (not imported from SBOM documents) will appear here.
                    </p>
                </div>
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
                        accept=".json,.tar.gz,.tgz,application/json,application/gzip"
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

            <div className="mb-3 flex items-center justify-between">
                <h2 className="text-lg font-bold text-gray-200">
                    Review Assessments
                </h2>
            </div>
            <TableGeneric<ReviewRow>
                columns={columns}
                data={filteredAssessments.map(a => ({
                    ...a,
                    texts: vulnDescriptions[a.vuln_id] ?? [],
                    _allIds: (a as any)._allIds ?? [a.id],
                    _variantIds: (a as any)._variantIds ?? (a.variant_id ? [a.variant_id] : []),
                }))}
                search={search}
                fuseKeys={["vuln_id", "packages", "simplified_status", "status_notes", "justification", "workaround"]}
                estimateRowHeight={50}
                hasPagination={true}
                hoverField="texts"
                hoverIdField="vuln_id"
            />

            {modalVuln && (
                <VulnModal
                    vuln={modalVuln}
                    readOnly={true}
                    appendAssessment={() => {}}
                    appendCVSS={() => null}
                    patchVuln={() => {}}
                    onClose={() => setModalVuln(undefined)}
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
                                availableVariants={allVariants}
                                defaultSelectedVariantIds={editingRow._variantIds}
                                availablePackages={editingRow.packages}
                                defaultSelectedPackages={editingRow.packages}
                            />
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

export default Review;
