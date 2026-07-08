import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import Vulnerabilities, { asCVSS, buildStatusSummary } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { asAssessment } from "../handlers/assessments";
import { escape } from "lodash-es";
import CvssGauge from "./CvssGauge";
import CustomCvss from "./CustomCvss";
import MessageBanner from "./MessageBanner";
import SeverityTag from "./SeverityTag";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import TimeEstimateEditor from "./TimeEstimateEditor";
import type { PostTimeEstimate } from "./TimeEstimateEditor";
import Iso8601Duration from '../handlers/iso8601duration';
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBox, faChevronLeft, faChevronRight, faPenToSquare, faTrash, faPlus, faCircleQuestion, faBook, faRotate, faCheck } from "@fortawesome/free-solid-svg-icons";
import ConfirmationModal from "./ConfirmationModal";
import EditAssessment from "./EditAssessment";
import type { EditAssessmentData } from "./EditAssessment";
import Variants from '../handlers/variant';
import { formatSourceName } from '../helpers/sourceNames';
import { useDocUrl } from '../helpers/useDocUrl';
import { splitPkgId, formatPkgId, extractSupplierName } from '../helpers/pkgId';
import type { Variant } from '../handlers/variant';
import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import NvdRefreshHandler from "../handlers/nvdRefresh";
import EpssRefreshHandler from "../handlers/epssRefresh";
import GhsaRefreshHandler from "../handlers/ghsaRefresh";

type Props = {
    vuln: Vulnerability;
    isEditing?: boolean;
    readOnly?: boolean;
    onClose: () => void;
    appendAssessment: (added: Assessment) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
    vulnerabilities?: Vulnerability[];
    currentIndex?: number;
    onNavigate?: (index: number) => void;
    variantId?: string;
    projectId?: string;
};

const dt_options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    timeZoneName: 'shortOffset'
};

// Tailwind classes for a simplified-status badge, matching the palette used
// across the app (red = exploitable, amber = pending, green = not affected).
const statusBadgeClass = (status: string): string => {
    switch (status) {
        case 'Exploitable':
            return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
        case 'Pending Assessment':
            return 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300';
        case 'Not affected':
            return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
        case 'Fixed':
            return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
        default:
            return 'bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
};

const originLabel = (origin: string): string => {
    switch (origin) {
        case 'custom':
            return 'User';
        case 'sbom':
            return 'SBOM';
        default:
            return origin ? formatSourceName(origin) : 'Unknown';
    }
};

const originBadgeClass = (origin: string): string => {
    switch (origin) {
        case 'custom':
            return 'bg-slate-200 text-slate-800 dark:bg-slate-600 dark:text-slate-100';
        case 'sbom':
            return 'bg-blue-200 text-blue-900 dark:bg-blue-800 dark:text-blue-100';
        case 'scc':
            return 'bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-300';
        case 'grype':
            return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300';
        case 'yocto_cve_check':
            return 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-300';
        case 'nvd':
        case 'nvd_cpe':
            return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300';
        case 'osv':
            return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
        default:
            return 'bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
};



type AssessmentGroup = {
    key: string;
    assessments: Assessment[];
    timestamp: string;
    packages: string[];
};

type StatusSortKey = 'variant' | 'package' | 'status' | 'justification' | 'impact' | 'notes' | 'workaround';

type VariantScopedSnapshot = {
    variantId: string;
    variantName: string;
    hasEffort: boolean;
    effort: {
        optimistic?: string;
        likely?: string;
        pessimistic?: string;
    };
    customCvss: CVSS[];
};

  function VulnModal(props: Readonly<Props>) {
    const { vuln, isEditing: initialIsEditing, readOnly = false, onClose, appendAssessment, appendCVSS, patchVuln, vulnerabilities, currentIndex, onNavigate, variantId, projectId } = props;
    const docUrl = useDocUrl("interactive-mode.html#vulnerability-details");
    const [isEditing, setIsEditing] = useState(initialIsEditing);
    const [showCustomCvss, setShowCustomCvss] = useState(false);
    const [clearTimeFields, setClearTimeFields] = useState(false);
    const [clearAssessmentFields, setClearAssessmentFields] = useState(false);
    const [showConfirmClose, setShowConfirmClose] = useState(false);
    const [newAssessmentIds, setNewAssessmentIds] = useState<Set<string>>(new Set());
    const [pendingNavigation, setPendingNavigation] = useState<number | null>(null);
    const [editingAssessmentId, setEditingAssessmentId] = useState<string | null>(null);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [groupToDelete, setGroupToDelete] = useState<AssessmentGroup | null>(null);
    const [showShortcutHelper, setShowShortcutHelper] = useState(false);
    const [availableVariants, setAvailableVariants] = useState<Variant[]>([]);
    const [variantsLoadedForVulnId, setVariantsLoadedForVulnId] = useState<string | null>(null);
    const [allVulnAssessments, setAllVulnAssessments] = useState<Assessment[]>([]);
    const [selectedTargetVariantIds, setSelectedTargetVariantIds] = useState<string[]>([]);
    const [variantSnapshots, setVariantSnapshots] = useState<VariantScopedSnapshot[]>([]);
    const [variantPackageMap, setVariantPackageMap] = useState<Record<string, string[]>>({});
    // True once the active-SBOM package list has been fetched for every variant,
    // so deprecated packages can reliably be split into their own table.
    const [variantPackageMapLoaded, setVariantPackageMapLoaded] = useState(false);
    const [statusSort, setStatusSort] = useState<{ key: StatusSortKey; dir: 'asc' | 'desc' } | null>(null);
    const [snapshotVersion, setSnapshotVersion] = useState(0);
    const [submittingMessage, setSubmittingMessage] = useState<string | null>(null);
    const [editingGroup, setEditingGroup] = useState<AssessmentGroup | null>(null);

    // Project-scoped package list: prefer packages_current (scoped to
    // the active scan context) and fall back to the full list.
    const projectPackages = (vuln.packages_current?.length > 0) ? vuln.packages_current : vuln.packages;

    // Fetch variants that have a finding for this specific vulnerability,
    // filtered to the current project when a projectId is provided.
    useEffect(() => {
        const controller = new AbortController();
        setAvailableVariants([]);
        setVariantsLoadedForVulnId(null);
        Variants.listByVuln(vuln.id, controller.signal).then(variants => {
            if (controller.signal.aborted) return;
            if (projectId) {
                setAvailableVariants(variants.filter(v => v.project_id === projectId));
            } else {
                setAvailableVariants(variants);
            }
            setVariantsLoadedForVulnId(vuln.id);
        }).catch(() => {});
        return () => controller.abort();
    }, [vuln.id, projectId]);

    // Fetch ALL assessments for this vuln (unfiltered) so variant tags are
    // complete even when a variant filter is active in the explorer.
    useEffect(() => {
        const controller = new AbortController();
        setAllVulnAssessments([]);
        fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments`, { mode: 'cors', signal: controller.signal })
            .then(r => r.json())
            .then((data: any[]) => {
                if (Array.isArray(data)) {
                    setAllVulnAssessments(data.flatMap(asAssessment).filter((a): a is Assessment => !Array.isArray(a)));
                }
            })
            .catch(() => {});
        return () => controller.abort();
    }, [vuln.id]);

    // In all-variants mode, default to all variant targets for custom CVSS/time edits.
    useEffect(() => {
        if (variantId || availableVariants.length === 0) {
            setSelectedTargetVariantIds([]);
            return;
        }
        setSelectedTargetVariantIds(availableVariants.map(v => v.id));
    }, [variantId, vuln.id, availableVariants]);

    const variantIdsKey = useMemo(
        () => availableVariants.map(v => v.id).sort().join(','),
        [availableVariants]
    );

    // Build per-variant snapshots so the modal can show where custom CVSS and
    // effort differ across variants directly in all-variants mode.
    useEffect(() => {
        const controller = new AbortController();
        const signal = controller.signal;
        if (variantId || availableVariants.length === 0) {
            setVariantSnapshots([]);
            return;
        }
        if (variantsLoadedForVulnId !== vuln.id) {
            return;
        }

        const variantNameById = new Map(availableVariants.map(v => [v.id, v.name]));

        (async () => {
            try {
                const url = new URL(
                    import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/variant-snapshots`,
                    window.location.href
                );
                if (projectId) {
                    url.searchParams.set('project_id', projectId);
                }
                const response = await fetch(url.toString(), { mode: 'cors', signal });
                if (!response.ok) {
                    if (!signal.aborted) setVariantSnapshots([]);
                    return;
                }
                const data = await response.json();
                if (!Array.isArray(data)) {
                    if (!signal.aborted) setVariantSnapshots([]);
                    return;
                }

                const snapshots = data
                    .filter((entry: any) => variantNameById.has(entry?.variant_id))
                    .map((entry: any): VariantScopedSnapshot => {
                        const customCvss: CVSS[] = Array.isArray(entry?.custom_cvss)
                            ? entry.custom_cvss.flatMap(asCVSS)
                            : [];

                        const optimisticDuration = typeof entry?.effort?.optimistic === 'string'
                            ? new Iso8601Duration(entry.effort.optimistic) : undefined;
                        const likelyDuration = typeof entry?.effort?.likely === 'string'
                            ? new Iso8601Duration(entry.effort.likely) : undefined;
                        const pessimisticDuration = typeof entry?.effort?.pessimistic === 'string'
                            ? new Iso8601Duration(entry.effort.pessimistic) : undefined;
                        const hasEffort = [optimisticDuration, likelyDuration, pessimisticDuration].some((duration) => {
                            return typeof duration?.total_seconds === 'number' && duration.total_seconds > 0;
                        });

                        return {
                            variantId: entry.variant_id,
                            variantName: variantNameById.get(entry.variant_id) ?? entry.variant_id,
                            hasEffort,
                            effort: {
                                optimistic: optimisticDuration && optimisticDuration.total_seconds > 0 ? optimisticDuration.formatHumanShort() : undefined,
                                likely: likelyDuration && likelyDuration.total_seconds > 0 ? likelyDuration.formatHumanShort() : undefined,
                                pessimistic: pessimisticDuration && pessimisticDuration.total_seconds > 0 ? pessimisticDuration.formatHumanShort() : undefined,
                            },
                            customCvss,
                        };
                    });

                if (!signal.aborted) {
                    setVariantSnapshots(snapshots);
                }
            } catch {
                if (!signal.aborted) setVariantSnapshots([]);
            }
        })();

        return () => { controller.abort(); };
    // availableVariants is read inside but the fetch is intentionally keyed off
    // the stable variantIdsKey memo, not the array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [variantId, variantIdsKey, variantsLoadedForVulnId, vuln.id, projectId, snapshotVersion]);

    useEffect(() => {
        const controller = new AbortController();
        const signal = controller.signal;
        setVariantPackageMapLoaded(false);
        if (availableVariants.length === 0) {
            setVariantPackageMap({});
            setVariantPackageMapLoaded(true);
            return;
        }
        if (variantsLoadedForVulnId !== vuln.id) {
            return;
        }
        (async () => {
            try {
                const url = new URL(
                    import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/variant-active-packages`,
                    window.location.href
                );
                if (projectId) {
                    url.searchParams.set('project_id', projectId);
                }
                const response = await fetch(url.toString(), { mode: 'cors', signal });
                const data = response.ok ? await response.json() : [];
                const map: Record<string, string[]> = {};
                if (Array.isArray(data)) {
                    for (const entry of data) {
                        if (entry && typeof entry.variant_id === 'string' && Array.isArray(entry.active_packages)) {
                            map[entry.variant_id] = entry.active_packages.filter((p: unknown): p is string => typeof p === 'string');
                        }
                    }
                }
                if (!signal.aborted) {
                    setVariantPackageMap(map);
                    setVariantPackageMapLoaded(true);
                }
            } catch {
                if (!signal.aborted) {
                    setVariantPackageMap({});
                    setVariantPackageMapLoaded(true);
                }
            }
        })();
        return () => { controller.abort(); };
    // availableVariants.length is read inside but the fetch is intentionally
    // keyed off the stable variantIdsKey memo, not the array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [variantIdsKey, variantsLoadedForVulnId, vuln.id, projectId]);

    const [hasTimeChanges, setHasTimeChanges] = useState(false);
    const [hasAssessmentChanges, setHasAssessmentChanges] = useState(false);
    const hasUnsavedChanges = hasTimeChanges || hasAssessmentChanges;

    // Message banner state
    const [bannerMessage, setBannerMessage] = useState("");
    const [bannerType, setBannerType] = useState<"error" | "success">("error");
    const [showBanner, setShowBanner] = useState(false);
    const [refreshing, setRefreshing] = useState(false);
    const [refreshError, setRefreshError] = useState<string | null>(null);
    const [refreshedList, setRefreshedList] = useState<string[]>([]);

    const modalRef = useRef<HTMLDivElement>(null);
    const shortcutButtonRef = useRef<HTMLButtonElement>(null);
    const dropdownRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && shortcutButtonRef.current &&
                !dropdownRef.current.contains(event.target as Node) &&
                !shortcutButtonRef.current.contains(event.target as Node)) {
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

    useEffect(() => {
        // force focus the modal content when the modal opens such that keyboard users can interact with it immediately
        if (modalRef.current) {
            modalRef.current.focus();
        }
    }, []);

    useEffect(() => {
        // Scroll to top when vulnerability changes
        if (modalRef.current) {
            modalRef.current.scrollTop = 0;
        }
    }, [vuln.id]);

    useEffect(() => {
        setRefreshing(false);
        setRefreshError(null);
        setRefreshedList([]);
    }, [vuln.id]);

    const showMessage = (message: string, type: "error" | "success") => {
        setBannerMessage(message);
        setBannerType(type);
        setShowBanner(true);
    };

    const hideBanner = () => {
        setShowBanner(false);
    };

    const handleClose = () => {
        if (hasUnsavedChanges) {
            setPendingNavigation(null);
            setShowConfirmClose(true);
        } else {
            onClose();
        }
    };

    const handleConfirmClose = () => {
        setShowConfirmClose(false);
        setClearTimeFields(true);
        setTimeout(() => setClearTimeFields(false), 100);
        if (pendingNavigation !== null && onNavigate) {
            onNavigate(pendingNavigation);
            setPendingNavigation(null);
        } else {
            onClose();
        }
    };

    const handleCancelClose = () => {
        setShowConfirmClose(false);
        setPendingNavigation(null);
    };

    const navigateTo = useCallback((targetIndex: number) => {
        hideBanner();
        if (!vulnerabilities || currentIndex === undefined || !onNavigate) return;
        if (hasUnsavedChanges) {
            setPendingNavigation(targetIndex);
            setShowConfirmClose(true);
        } else {
            onNavigate(targetIndex);
        }
    }, [vulnerabilities, currentIndex, onNavigate, hasUnsavedChanges]);

    const canNavigatePrevious = vulnerabilities && currentIndex !== undefined && currentIndex > 0;
    const canNavigateNext = vulnerabilities && currentIndex !== undefined && currentIndex < vulnerabilities.length - 1;

    // Navigation info
    const navigationInfo = vulnerabilities && currentIndex !== undefined
        ? `Vulnerability ${currentIndex + 1} of ${vulnerabilities.length}`
        : null;

    const isGhsaVuln = vuln.id.toUpperCase().startsWith('GHSA-');

    const handleRefresh = useCallback(async () => {
        setRefreshing(true);
        setRefreshError(null);
        setRefreshedList([]);
        try {
            if (vuln.id.toUpperCase().startsWith('GHSA-')) {
                const result = await GhsaRefreshHandler.triggerSingleRefresh(vuln.id);
                if (result) {
                    const { simplified_status: _ss, assessments: _a, packages_current: _pc, variants: _v, found_by: _fb, ...ghsaUpdates } = result;
                    patchVuln(vuln.id, { ...vuln, ...ghsaUpdates });
                    setRefreshedList(['GHSA']);
                } else {
                    setRefreshError("GitHub Advisory Database refresh failed. Please try again later.");
                }
            } else {
                const [nvdResult, epssResult] = await Promise.allSettled([
                    NvdRefreshHandler.triggerSingleRefresh(vuln.id),
                    EpssRefreshHandler.triggerSingleRefresh(vuln.id),
                ]);

                const errors: string[] = [];
                const nvdValue = nvdResult.status === "fulfilled" ? nvdResult.value : null;
                const nvdUpdated = nvdValue?.kind === "success";
                if (!nvdUpdated) {
                    if (nvdValue?.kind === "error" && nvdValue.code === "rate_limited") {
                        errors.push(nvdValue.apiKeyConfigured
                            ? "NVD rate-limited. Your NVD API key may be exhausted, please try again later."
                            : "NVD rate-limited. Set NVD API key in settings to reduce throttling.");
                    } else {
                        errors.push("NVD API unavailable");
                    }
                }
                if (epssResult.status === "rejected" || epssResult.value === null) {
                    errors.push("EPSS API unavailable");
                }

                const epssUpdated = epssResult.status === "fulfilled" && epssResult.value !== null;

                let merged = { ...vuln };

                if (nvdUpdated || epssUpdated) {
                    if (nvdUpdated) {
                        const {
                            simplified_status: _ss,
                            assessments: _a,
                            packages_current: _pc,
                            variants: _v,
                            found_by: _fb,
                            ...nvdUpdates
                        } = nvdValue.vuln;

                        merged = { ...merged, ...nvdUpdates };
                        setRefreshedList(prev => [...prev, "NVD"]);
                    }

                    if (epssUpdated) {
                        merged = { ...merged, epss: epssResult.value!.epss };
                        setRefreshedList(prev => [...prev, "EPSS"]);
                    }

                    patchVuln(vuln.id, merged);
                }

                if (errors.length > 0) {
                    setRefreshError(errors.join(". ") + ". Please try again later.");
                }
            }
        } catch (error) {
            setRefreshError(String(error) + " Please try again later.");
        } finally {
            setRefreshing(false);
        }
    }, [vuln, patchVuln]);

    const handleEditAssessment = (assessmentId: string, group: AssessmentGroup) => {
        setEditingAssessmentId(assessmentId);
        setEditingGroup(group);
    };

    const handleCancelEdit = () => {
        setEditingAssessmentId(null);
        setEditingGroup(null);
    };

    const handleDeleteAssessment = (group: AssessmentGroup) => {
        setGroupToDelete(group);
        setShowDeleteConfirm(true);
    };

    const handleConfirmDelete = async () => {
        if (groupToDelete) {
            const idsToDelete = groupToDelete.assessments.map(a => a.id);
            let anyError = false;

            for (const id of idsToDelete) {
                try {
                    const response = await fetch(import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(id)}`, {
                        method: 'DELETE',
                        mode: 'cors',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });

                    if (response.ok) {
                        vuln.assessments = vuln.assessments.filter(a => a.id !== id);
                        setAllVulnAssessments(prev => prev.filter(a => a.id !== id));
                    } else {
                        anyError = true;
                        const errorData = await response.text();
                        showMessage(`Failed to delete assessment: HTTP code ${response.status} | ${escape(errorData)}`, "error");
                    }
                } catch (error) {
                    anyError = true;
                    showMessage(`Failed to delete assessment: ${escape(String(error))}`, "error");
                }
            }

            if (!anyError) {
                const updatedAssessments = [...vuln.assessments];
                const statusSummary = buildStatusSummary(updatedAssessments, vuln.packages_current);
                vuln.simplified_status = statusSummary.dominant_status;
                vuln.status_summary = statusSummary;

                patchVuln(vuln.id, {
                    ...vuln,
                    assessments: updatedAssessments,
                    simplified_status: statusSummary.dominant_status,
                    status_summary: statusSummary,
                });
                showMessage("Assessment deleted successfully!", "success");
            }
        }
        setShowDeleteConfirm(false);
        setGroupToDelete(null);
    };

    const handleCancelDelete = () => {
        setShowDeleteConfirm(false);
        setGroupToDelete(null);
    };

    const saveEditedAssessment = async (data: EditAssessmentData) => {
        if (!editingGroup) return;
        setSubmittingMessage('Editing assessment...');

        // Share a single timestamp across all created rows in this edit action
        const editSharedTimestamp = new Date().toISOString();

        // Build target (package × variantId) combos from form selection
        const targetVariantIds: Array<string | undefined> =
            data.variant_ids && data.variant_ids.length > 0
                ? data.variant_ids
                : [undefined];
        const targetPackages: string[] =
            data.packages && data.packages.length > 0
                ? data.packages
                : editingGroup.packages;

        // Index existing group assessments by (pkg, vid) key
        const existingByKey = new Map<string, Assessment>();
        for (const a of editingGroup.assessments) {
            const pkg = a.packages[0] ?? '';
            const vid = a.variant_id ?? '';
            existingByKey.set(`${pkg}::${vid}`, a);
        }

        // Build the desired target key set
        const targetKeys = new Set<string>();
        for (const pkg of targetPackages) {
            for (const vid of targetVariantIds) {
                targetKeys.add(`${pkg}::${vid ?? ''}`);
            }
        }

        let anyError = false;

        // Helper — normalise an Assessment from the API response
        const normalise = (raw: unknown): Assessment | null => {
            const a = asAssessment(raw);
            if (Array.isArray(a) || typeof a !== 'object') return null;
            const isRelevant = a.status === 'not_affected' || a.status === 'false_positive';
            if (!isRelevant) {
                a.justification = undefined;
                a.impact_statement = undefined;
            }
            return a;
        };

        // 1. PUT-update persisting combos / DELETE removed combos
        for (const [key, existing] of existingByKey) {
            if (targetKeys.has(key)) {
                try {
                    const res = await fetch(import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(existing.id)}`, {
                        method: 'PUT', mode: 'cors',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            status: data.status,
                            justification: data.justification,
                            impact_statement: data.impact_statement,
                            status_notes: data.status_notes,
                            workaround: data.workaround
                        })
                    });
                    if (res.ok) {
                        const rd = await res.json();
                        if (rd?.status !== 'success') {
                            anyError = true;
                            showMessage('Error: invalid response from server', 'error');
                        } else {
                            const updated = normalise(rd.assessment);
                            if (updated) {
                                const idx = vuln.assessments.findIndex(a => a.id === existing.id);
                                if (idx !== -1) vuln.assessments[idx] = updated;
                                setAllVulnAssessments(prev => prev.map(a => a.id === updated.id ? updated : a));
                            } else {
                                anyError = true;
                                showMessage('Error: invalid assessment data received', 'error');
                            }
                        }
                    } else {
                        anyError = true;
                        showMessage(`Failed to update assessment: HTTP ${res.status}`, 'error');
                    }
                } catch (e) {
                    anyError = true;
                    showMessage(`Failed to update assessment: ${escape(String(e))}`, 'error');
                }
            } else {
                // Deselected — delete this record
                try {
                    const res = await fetch(import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(existing.id)}`, {
                        method: 'DELETE', mode: 'cors'
                    });
                    if (res.ok) {
                        vuln.assessments = vuln.assessments.filter(a => a.id !== existing.id);
                        setAllVulnAssessments(prev => prev.filter(a => a.id !== existing.id));
                    } else {
                        anyError = true;
                        showMessage(`Failed to delete assessment: HTTP ${res.status}`, 'error');
                    }
                } catch (e) {
                    anyError = true;
                    showMessage(`Failed to delete assessment: ${escape(String(e))}`, 'error');
                }
            }
        }

        // 2. POST-create newly-added combos — batch packages per variant so
        //    all Assessment rows share the exact same timestamp.
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
                    vuln_id: vuln.id,
                    packages: pkgs,
                    status: data.status,
                    justification: data.justification,
                    impact_statement: data.impact_statement,
                    status_notes: data.status_notes,
                    workaround: data.workaround,
                    timestamp: editSharedTimestamp,
                };
                if (vid) body.variant_id = vid;
                const res = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments`, {
                    method: 'POST', mode: 'cors',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const rd = await res.json();
                if (rd?.status === 'success') {
                    const rawList: unknown[] = Array.isArray(rd.assessments) ? rd.assessments : (rd.assessment ? [rd.assessment] : []);
                    for (const raw of rawList) {
                        const casted = normalise(raw);
                        if (casted) {
                            vuln.assessments.push(casted);
                            setAllVulnAssessments(prev => [...prev, casted]);
                        }
                    }
                } else {
                    anyError = true;
                    showMessage(`Failed to create assessment: HTTP ${res.status}`, 'error');
                }
            } catch (e) {
                anyError = true;
                showMessage(`Failed to create assessment: ${escape(String(e))}`, 'error');
            }
        }

        if (!anyError) {
            const updatedAssessments = [...vuln.assessments];
            const statusSummary = buildStatusSummary(updatedAssessments, vuln.packages_current);
            vuln.simplified_status = statusSummary.dominant_status;
            vuln.status_summary = statusSummary;
            patchVuln(vuln.id, {
                ...vuln,
                assessments: updatedAssessments,
                simplified_status: statusSummary.dominant_status,
                status_summary: statusSummary,
            });
            showMessage('Assessment updated successfully!', 'success');
        }

        setSubmittingMessage(null);
        setEditingAssessmentId(null);
        setEditingGroup(null);
    };

    // Handle keyboard navigation (ESC to close, arrow keys to navigate)
    useEffect(() => {
        const handleKeyDown = (event: KeyboardEvent) => {
            const target = event.target as HTMLElement;
            const isInTextField =
                target.tagName === 'INPUT' ||
                target.tagName === 'TEXTAREA' ||
                target.tagName === 'SELECT' ||
                target.isContentEditable;

            if (event.key === 'Escape') {
                event.preventDefault();
                if (hasUnsavedChanges) {
                    setPendingNavigation(null);
                    setShowConfirmClose(true);
                } else {
                    onClose();
                }
            } else if (event.key === 'ArrowLeft' && canNavigatePrevious && !isInTextField) {
                event.preventDefault();
                navigateTo(currentIndex! - 1);
            } else if (event.key === 'ArrowRight' && canNavigateNext && !isInTextField) {
                event.preventDefault();
                navigateTo(currentIndex! + 1);
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [hasUnsavedChanges, onClose, canNavigatePrevious, canNavigateNext, navigateTo, currentIndex]);

    const groupAssessments = (assessments: Assessment[]) => {
        const groups: { [key: string]: Assessment[] } = {};

        assessments.forEach(assess => {
            // Create a key based on timestamp (date only), status, and assessment content
            const date = new Date(assess.timestamp);
            const dateKey = date.toDateString(); // This gives us just the date part
            const contentKey = `${assess.simplified_status}|${assess.justification || ''}|${assess.impact_statement || ''}|${assess.status_notes || ''}|${assess.workaround || ''}`;
            const groupKey = `${dateKey}::${contentKey}`;

            if (!groups[groupKey]) {
                groups[groupKey] = [];
            }
            groups[groupKey].push(assess);
        });

        // Convert groups to array and sort by most recent timestamp
        return Object.entries(groups)
            .map(([key, assessments]) => ({
                key,
                assessments,
                timestamp: assessments[0].timestamp, // Use first assessment's timestamp for sorting
                packages: [...new Set(assessments.flatMap(a => a.packages))].sort() // Collect unique packages
            }))
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    };

    const groupedAssessments = groupAssessments(vuln.assessments);

    const latestAssessmentFor = (variantIdValue: string, pkg: string | null): Assessment | null =>
        allVulnAssessments
            .filter(a => a.variant_id === variantIdValue && (pkg === null || a.packages.includes(pkg)))
            .reduce<Assessment | null>((best, a) => {
                if (!best) return a;
                return new Date(a.timestamp).getTime() > new Date(best.timestamp).getTime() ? a : best;
            }, null);

    type StatusRow = { variant: Variant; pkg: string | null; assessment: Assessment | null; deprecated: boolean };

    const allStatusRows: StatusRow[] = availableVariants.flatMap((variant): StatusRow[] => {
        const variantPkgs = variantPackageMap[variant.id] ?? [];
        // Packages affected by this vuln that still exist in the variant's active SBOM.
        const activeAffected = projectPackages.filter(p => variantPkgs.includes(p));
        // Packages referenced by the variant's assessments may include older,
        // now-deprecated versions that are no longer in the active SBOM.
        const assessmentPkgs = [...new Set(
            allVulnAssessments
                .filter(a => a.variant_id === variant.id)
                .flatMap(a => a.packages)
        )];
        const allPkgs = [...new Set([...activeAffected, ...assessmentPkgs])];
        if (allPkgs.length === 0) {
            return [{ variant, pkg: null, assessment: latestAssessmentFor(variant.id, null), deprecated: false }];
        }
        return allPkgs.slice().sort().map(pkg => ({
            variant,
            pkg,
            assessment: latestAssessmentFor(variant.id, pkg),
            // A package is deprecated once it's no longer in the variant's active
            // SBOM. Until that list has loaded, keep it in the current table.
            deprecated: variantPackageMapLoaded && !variantPkgs.includes(pkg),
        }));
    });

    const currentAssessmentRows = allStatusRows.filter(r => !r.deprecated);
    const deprecatedAssessmentRows = allStatusRows.filter(r => r.deprecated);

    // Value used to compare two rows for a given sortable column.
    const statusSortValue = (row: StatusRow, key: StatusSortKey): string => {
        switch (key) {
            case 'variant': return row.variant.name ?? '';
            case 'package': return row.pkg ? formatPkgId(row.pkg) : '';
            case 'status': return row.assessment?.simplified_status ?? 'No status';
            case 'justification': return row.assessment?.justification ?? '';
            case 'impact': return row.assessment?.impact_statement ?? '';
            case 'notes': return row.assessment?.status_notes ?? '';
            case 'workaround': return row.assessment?.workaround ?? '';
        }
    };

    const sortStatusRows = (rows: StatusRow[]): StatusRow[] =>
        statusSort
            ? rows.slice().sort((a, b) => {
                const cmp = statusSortValue(a, statusSort.key)
                    .localeCompare(statusSortValue(b, statusSort.key), undefined, { sensitivity: 'base' });
                return statusSort.dir === 'asc' ? cmp : -cmp;
            })
            : rows;

    const toggleStatusSort = (key: StatusSortKey) => {
        setStatusSort(prev =>
            prev?.key === key
                ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
                : { key, dir: 'asc' }
        );
    };

    const statusSortColumns: { key: StatusSortKey; label: string }[] = [
        { key: 'variant', label: 'Variant' },
        { key: 'package', label: 'Package' },
        { key: 'status', label: 'Status' },
        { key: 'justification', label: 'Justification' },
        { key: 'impact', label: 'Impact' },
        { key: 'notes', label: 'Notes' },
        { key: 'workaround', label: 'Workaround' },
    ];

    const renderStatusTable = (rows: StatusRow[]) => (
        <div className="overflow-x-auto">
            <table className="w-full text-sm text-left border-collapse">
                <thead>
                    <tr className="text-gray-400 border-b border-gray-600">
                        {statusSortColumns.map((col, idx) => (
                            <th
                                key={col.key}
                                className={`py-1 font-semibold cursor-pointer select-none hover:text-gray-200 ${idx < statusSortColumns.length - 1 ? 'pr-3' : ''}`}
                                onClick={() => toggleStatusSort(col.key)}
                                aria-sort={statusSort?.key === col.key ? (statusSort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                            >
                                {col.label}
                                <span className="ml-1 text-xs">
                                    {statusSort?.key === col.key ? (statusSort.dir === 'asc' ? '▲' : '▼') : ''}
                                </span>
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {rows.map(({ variant, pkg, assessment }) => (
                        <tr key={`${variant.id}::${pkg ?? ''}`} className="border-b border-gray-700 last:border-0 align-top">
                            <td className="py-1.5 pr-3">
                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 whitespace-nowrap">
                                    {variant.name}
                                </span>
                            </td>
                            <td className="py-1.5 pr-3 text-gray-300 whitespace-nowrap">{pkg ? formatPkgId(pkg) : '—'}</td>
                            <td className="py-1.5 pr-3">
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full font-medium whitespace-nowrap ${statusBadgeClass(assessment?.simplified_status ?? 'No status')}`}>
                                    {assessment?.simplified_status ?? 'No status'}
                                </span>
                            </td>
                            <td className="py-1.5 pr-3 text-gray-300 whitespace-pre-line">{assessment?.justification || '—'}</td>
                            <td className="py-1.5 pr-3 text-gray-300 whitespace-pre-line">{assessment?.impact_statement || '—'}</td>
                            <td className="py-1.5 pr-3 text-gray-300 whitespace-pre-line">{assessment?.status_notes || '—'}</td>
                            <td className="py-1.5 text-gray-300 whitespace-pre-line">{assessment?.workaround || '—'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );

    const bothRefreshed = isGhsaVuln
        ? refreshedList.includes('GHSA')
        : refreshedList.includes('NVD') && refreshedList.includes('EPSS');
    const partialRefreshed = refreshedList.length > 0 && !bothRefreshed;

    // Get the default status for new assessments
    // Use the most recent assessment's status, or "under_investigation" if no assessments exist
    const getDefaultStatus = () => {
        if (groupedAssessments.length > 0) {
            // Get the most recent assessment's status (groupedAssessments are already sorted by most recent first)
            return groupedAssessments[0].assessments[0].status;
        }
        return "under_investigation";
    };

    const defaultStatus = getDefaultStatus();

    const addAssessment = async (content: PostAssessment) => {
        content.vuln_id = vuln.id;
        // packages come from StatusEditor selection; fall back to project-scoped packages
        if (!content.packages || content.packages.length === 0) {
            content.packages = projectPackages;
        }

        // Determine which variants to post to.
        // Prefer explicit selections from the form; fall back to the current
        // variantId context so the assessment is never stored without a variant.
        const variantIds: Array<string | undefined> =
            content.variant_ids && content.variant_ids.length > 0
                ? content.variant_ids
                : variantId
                ? [variantId]
                : [undefined];

        const { variant_ids: _, ...baseContent } = content;

        // Share a single timestamp across all variant requests so grouped
        // assessment rows get the exact same value in the database.
        const sharedTimestamp = new Date().toISOString();

        let successCount = 0;
        let lastCasted: Assessment | null = null;
        const touchedVariantIds = new Set<string>();
        const touchedPackages = new Set<string>();

        setSubmittingMessage('Adding assessment...');
        try {
        // Post every variant in a single batch request
        const items = variantIds.map(vid =>
            vid
                ? { ...baseContent, variant_id: vid, timestamp: sharedTimestamp }
                : { ...baseContent, timestamp: sharedTimestamp }
        );
        const response = await fetch(import.meta.env.VITE_API_URL + `/api/assessments/batch`, {
            method: 'POST',
            mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ assessments: items })
        });
        const data = await response.json();
        if (data?.status === 'success') {
            // Backend returns one record per (package, variant) pair.
            const rawList: unknown[] = Array.isArray(data?.assessments) ? data.assessments : [];
            for (const raw of rawList) {
                const casted = asAssessment(raw);
                if (!Array.isArray(casted) && typeof casted === 'object') {
                    successCount++;
                    lastCasted = casted;
                    if (casted.variant_id) touchedVariantIds.add(casted.variant_id);
                    for (const pkg of casted.packages ?? []) touchedPackages.add(pkg);

                    // Highlight the very first created assessment
                    if (successCount === 1) {
                        setNewAssessmentIds(prev => new Set(prev).add(casted.id));
                        setTimeout(() => {
                            setNewAssessmentIds(prev => {
                                const newSet = new Set(prev);
                                newSet.delete(casted.id);
                                return newSet;
                            });
                        }, 5500);
                    }

                    appendAssessment(casted);
                    vuln.assessments.push(casted);
                    // Keep allVulnAssessments in sync so variant tags appear immediately
                    setAllVulnAssessments(prev => [...prev, casted]);
                    vuln.simplified_status = casted.simplified_status;
                }
            }
            if (Array.isArray(data?.errors) && data.errors.length > 0) {
                showMessage(`Some assessments failed: ${escape(JSON.stringify(data.errors))}`, 'error');
            }
        } else {
            showMessage(`Failed to add assessment: HTTP code ${Number(response?.status)} | ${escape(JSON.stringify(data))}`, 'error');
        }

        if (lastCasted) {
            const updatedAssessments = [...vuln.assessments];
            const statusSummary = buildStatusSummary(updatedAssessments, vuln.packages_current);
            patchVuln(vuln.id, {
                ...vuln,
                assessments: updatedAssessments,
                simplified_status: statusSummary.dominant_status,
                status_summary: statusSummary,
            });

            const variantCount = touchedVariantIds.size;
            const packageCount = touchedPackages.size;
            const variantPart = variantCount > 0
                ? `${variantCount} variant${variantCount === 1 ? '' : 's'}`
                : '';
            const packagePart = packageCount > 0
                ? `${packageCount} package${packageCount === 1 ? '' : 's'}`
                : '';

            let msg = 'Successfully added assessment.';
            if (packagePart && variantPart) {
                msg = `Successfully added assessment to ${packagePart} across ${variantPart}.`;
            } else if (packagePart) {
                msg = `Successfully added assessment to ${packagePart}.`;
            } else if (variantPart) {
                msg = `Successfully added assessment to ${variantPart}.`;
            } else if (successCount > 1) {
                msg = `Successfully added ${successCount} assessments.`;
            }
            showMessage(msg, 'success');
            setClearAssessmentFields(true);
            setTimeout(() => setClearAssessmentFields(false), 100);
        }
        } finally {
            setSubmittingMessage(null);
        }
    };

    const addCvss = async (vector: string) => {
        const content = appendCVSS(vuln.id, vector);

        if (content === null) {
            showMessage("The vector string is invalid, please check the format.", "error");
            return;
        }

        const targetVariantIds: Array<string | undefined> =
            variantId
                ? [variantId]
                : (availableVariants.length > 0
                    ? (selectedTargetVariantIds.length > 0 ? selectedTargetVariantIds : [])
                    : [undefined]);

        if (!variantId && availableVariants.length > 0 && targetVariantIds.length === 0) {
            showMessage("Please select at least one variant before adding a custom CVSS score.", "error");
            return;
        }

        const updates = targetVariantIds.map((vid) => ({
            id: vuln.id,
            ...(vid ? { variant_id: vid } : {}),
            cvss: content,
        }));

        const url = updates.length > 1
            ? import.meta.env.VITE_API_URL + '/api/vulnerabilities/batch'
            : import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}`;
        const body = updates.length > 1 ? { vulnerabilities: updates } : updates[0];

        const response = await fetch(url, {
            method: 'PATCH',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (response.status == 200) {
            const data = await response.json();

            const updatedSeverity = updates.length > 1
                ? data?.vulnerabilities?.[0]?.severity?.cvss
                : data?.severity?.cvss;

            if (Array.isArray(updatedSeverity) && variantId) {
                // Only use the response severity directly when viewing a specific
                // variant: the PATCH response is already variant-scoped.
                const updatedVuln = { ...vuln, severity: { ...vuln.severity, cvss: updatedSeverity } };
                patchVuln(vuln.id, updatedVuln);
            } else if (!variantId) {
                // All-variants mode: the PATCH response is variant-scoped, so it
                // can't populate the union gauge view. Re-fetch the vulnerability
                // in the current (project) scope so the CVSS gauges reflect the new
                // custom score immediately, mirroring a page reload.
                try {
                    const refreshedCvss = await Vulnerabilities.fetchScopedCvss(vuln.id, projectId);
                    if (refreshedCvss) {
                        const updatedVuln = { ...vuln, severity: { ...vuln.severity, cvss: refreshedCvss } };
                        patchVuln(vuln.id, updatedVuln);
                    }
                } catch (e) {
                    console.error("Failed to refresh vulnerability after CVSS save:", e);
                }
            }

            // Refresh per-variant snapshots immediately so the panel reflects the
            // new data without requiring the modal to be closed and reopened.
            setSnapshotVersion(v => v + 1);
            setShowCustomCvss(false);
            showMessage("Successfully added Custom CVSS.", "success");
        } else {
            const data = await response.text();
            console.error("API error response:", response.status, data);
            showMessage(`Failed to save CVSS: HTTP code ${Number(response?.status)} | ${escape(data)}`, "error");
        }
    };

    const saveEstimation = async (content: PostTimeEstimate) => {
        const targetVariantIds: Array<string | undefined> =
            variantId
                ? [variantId]
                : (availableVariants.length > 0
                    ? (selectedTargetVariantIds.length > 0 ? selectedTargetVariantIds : [])
                    : [undefined]);

        if (!variantId && availableVariants.length > 0 && targetVariantIds.length === 0) {
            showMessage("Please select at least one variant before saving an estimate.", "error");
            return;
        }

        const updates = targetVariantIds.map((vid) => ({
            id: vuln.id,
            ...(vid ? { variant_id: vid } : {}),
            effort: {
                optimistic: content.optimistic.formatAsIso8601(),
                likely: content.likely.formatAsIso8601(),
                pessimistic: content.pessimistic.formatAsIso8601()
            }
        }));

        const url = updates.length > 1
            ? import.meta.env.VITE_API_URL + '/api/vulnerabilities/batch'
            : import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}`;

        const response = await fetch(url, {
            method: 'PATCH',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updates.length > 1 ? { vulnerabilities: updates } : updates[0])
        })
        if (response.status == 200) {
            const data = await response.json()

            const updatedEffort = updates.length > 1
                ? data?.vulnerabilities?.[0]?.effort
                : data?.effort;

            if (variantId) {
                // Only update the local vuln object when viewing a specific variant.
                // In all-variants mode the snapshot refresh below handles the display,
                // so we must not overwrite the global vuln with variant-scoped values.
                if (typeof updatedEffort?.optimistic === "string")
                    vuln.effort.optimistic = new Iso8601Duration(updatedEffort.optimistic);
                if (typeof updatedEffort?.likely === "string")
                    vuln.effort.likely = new Iso8601Duration(updatedEffort.likely);
                if (typeof updatedEffort?.pessimistic === "string")
                    vuln.effort.pessimistic = new Iso8601Duration(updatedEffort.pessimistic);

                // Also patch the vulnerability for real-time refresh in other views
                patchVuln(vuln.id, vuln);
            }

            // Refresh per-variant snapshots immediately so the panel reflects the
            // new data without requiring the modal to be closed and reopened.
            setSnapshotVersion(v => v + 1);
            setClearTimeFields(true);
            setTimeout(() => setClearTimeFields(false), 100);
            showMessage("Successfully added estimation.", "success");
        } else {
            const data = await response.text();
            showMessage(`Failed to save estimation: HTTP code ${Number(response?.status)} | ${escape(data)}`, "error");
        }
    };

    return (
        <div
            key={vuln.id}
            data-testid="vuln-modal-backdrop"
            tabIndex={-1}
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) {
                    handleClose();
                }
            }}
            className="overflow-x-hidden fixed top-0 right-0 left-0 z-50 justify-center items-center w-full md:inset-0 h-full max-h-full bg-gray-900/90"
        >
            {submittingMessage && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40">
                    <div className="flex flex-col items-center gap-3 text-white">
                        <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span className="text-sm font-semibold">{submittingMessage}</span>
                    </div>
                </div>
            )}
            <div className="relative p-16 h-full">
                <div
                    ref={modalRef}
                    tabIndex={-1}
                    className="relative rounded-lg shadow bg-gray-700 h-full overflow-y-auto">

                    {/* Modal header */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                        <h3 id="vulnerability_modal_title" className="text-xl font-semibold text-gray-900 dark:text-white">
                            {vuln.id}
                        </h3>
                        <div className="flex items-center space-x-2">
                            {/* Keyboard Shortcut Helper */}
                            <div className="px-2 py-2 flex items-center gap-2 relative">
                                <button
                                    ref={shortcutButtonRef}
                                    aria-label='shortcut helper'
                                    title='View keyboard shortcuts'
                                    type='button'
                                    className='hover:text-blue-400 transition-colors'
                                    onClick={() => setShowShortcutHelper(!showShortcutHelper)}
                                >
                                    <FontAwesomeIcon icon={faCircleQuestion} size='lg' />
                                </button>
                                <a
                                    href={docUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    aria-label="documentation"
                                    title="Open documentation"
                                    className="hover:text-blue-400 transition-colors"
                                >
                                    <FontAwesomeIcon icon={faBook} size='lg' />
                                </a>
                                {showShortcutHelper && (
                                    <div
                                        ref={dropdownRef}
                                        className="absolute top-full mt-1 right-0 bg-cyan-900 border border-cyan-700 rounded-lg shadow-lg p-4 z-50 w-[300px] text-sm"
                                    >
                                        <h3 className="font-bold text-white mb-3">Keyboard Shortcuts</h3>
                                        <div className="space-y-2 text-gray-100">
                                            <div className="flex justify-between">
                                                <span className="font-semibold text-cyan-300">← / →</span>
                                                <span>Previous/Next vulnerability</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="font-semibold text-cyan-300">Esc</span>
                                                <span>Close modal</span>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {!readOnly && (
                                <div className="flex items-center gap-2">
                                    <button
                                        onClick={handleRefresh}
                                        disabled={refreshing}
                                        title={isGhsaVuln ? "Refresh from GitHub Advisory Database" : "Refresh from NVD & EPSS"}
                                        type="button"
                                        className={`px-3 py-2 text-sm font-medium focus:outline-none rounded-lg border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                                            bothRefreshed
                                                ? 'text-green-400 border-green-600 hover:bg-green-900 bg-transparent'
                                                : partialRefreshed
                                                    ? 'text-yellow-400 border-yellow-600 hover:bg-yellow-900 bg-transparent'
                                                    : 'border-gray-600 hover:bg-gray-600 hover:text-white bg-transparent text-gray-300'
                                        }`}
                                    >
                                        <FontAwesomeIcon
                                            icon={(bothRefreshed || partialRefreshed) ? faCheck : faRotate}
                                            className={refreshing ? "animate-spin" : ""}
                                        />
                                        {bothRefreshed && <span className="ml-2 text-xs">Updated</span>}
                                        {partialRefreshed && <span className="ml-2 text-xs">{refreshedList[0]} Updated</span>}
                                    </button>
                                    {refreshError && (
                                        <span className="text-xs text-red-400">{refreshError}</span>
                                    )}
                                </div>
                            )}

                            {!readOnly && <button
                                onClick={() => setIsEditing(!isEditing)}
                                type="button"
                                className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                                    isEditing
                                        ? "bg-blue-700 hover:bg-blue-800 text-white"
                                        : "bg-blue-600 hover:bg-blue-700 text-white"
                                }`}
                                title={isEditing ? "Exit editing mode" : "Enter editing mode"}
                            >
                                <FontAwesomeIcon icon={faPenToSquare} className="mr-2" />
                                {isEditing ? "Exit editing" : "Edit"}
                            </button>}
                            <button
                                onClick={handleClose}
                                type="button"
                                className="text-white bg-transparent border border-gray-600 hover:bg-gray-600 hover:border-gray-500 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center transition-colors"
                            >
                                <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                    <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                                </svg>
                                <span className="sr-only">Close modal</span>
                            </button>
                        </div>
                    </div>

                    {/* Message Banner - Sticky at top */}
                    {showBanner && (
                        <div className="sticky top-0 z-10 bg-gray-700">
                            <MessageBanner
                                type={bannerType}
                                message={bannerMessage}
                                isVisible={showBanner}
                                onClose={hideBanner}
                            />
                        </div>
                    )}

                    {/* Modal body */}
                    <div className="p-4 md:p-5 space-y-4 text-gray-300 text-justify" id="vulnerability_modal_body">

                        <div className="flex flex-row mb-6 ">
                            <ul className="flex-[1.5] leading-6">
                                <li key="severity">
                                    <span className="font-bold mr-1">Severity:</span>
                                    <SeverityTag severity={vuln.severity.severity} className="text-white" />
                                </li>
                                {vuln.epss?.score !== undefined && vuln.epss.score !== 0 && <li key="epss">
                                    <span className="font-bold mr-1">EPSS Score: </span>
                                    {(vuln.epss.score * 100).toFixed(2)}%
                                </li>}
                                {vuln.published && <li key="published">
                                    <span className="font-bold mr-1">Published:</span>
                                    {new Date(vuln.published).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}
                                </li>}
                                <li key="sources">
                                    <span className="font-bold mr-1">Found by:</span>
                                    {vuln.found_by
                                        .map(formatSourceName)
                                        .join(', ')
                                    }
                                </li>
                                <li key="status">
                                    <span className="font-bold mr-1">Status:</span>
                                    {vuln.simplified_status}
                                </li>
                                <li key="packages">
                                    <span className="font-bold mr-1">Affects:</span>
                                    <code>{vuln.packages.map(formatPkgId).join(', ')}</code>
                                </li>
                                <li key="aliases">
                                    <span className="font-bold mr-1">Aliases:</span>
                                    <code>{vuln.aliases.join(', ')}</code>
                                </li>
                                {vuln.euvd?.id && (
                                    <li key="euvd">
                                        <span className="font-bold mr-1">ENISA EUVD:</span>
                                        {vuln.euvd.url ? (
                                            <a
                                                href={vuln.euvd.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-blue-400 hover:underline"
                                            >
                                                <code>{vuln.euvd.id}</code>
                                            </a>
                                        ) : (
                                            <code>{vuln.euvd.id}</code>
                                        )}
                                        {vuln.euvd.known_exploited && (
                                            <span className="ml-2 px-1.5 py-0.5 rounded text-xs font-semibold bg-red-900/60 text-red-200">
                                                EU KEV — Known Exploited
                                            </span>
                                        )}
                                    </li>
                                )}
                                <li key="related_vulns">
                                    <span className="font-bold mr-1">Related vulnerabilities:</span>
                                    <code>{vuln.related_vulnerabilities.join(', ')}</code>
                                </li>
                            </ul>

                            <div className="ml-2 grow-1">
                                <div className="flex gap-3 justify-start items-center mb-2">
                                    <h3 className="text-lg font-bold text-white flex items-center">
                                        CVSS
                                    </h3>
                                    {isEditing && (
                                        <div className="relative">
                                            <button
                                                onClick={() => setShowCustomCvss(!showCustomCvss)}
                                                className="text-blue-400 hover:text-blue-300 transition-colors"
                                                title="Add custom CVSS vector"
                                                aria-label="Add custom CVSS vector"
                                            >
                                                <FontAwesomeIcon icon={faPlus} className="w-4 h-4" />
                                            </button>

                                            {showCustomCvss && (
                                                <div className="absolute right-0 mt-2 z-50 w-64">
                                                    <CustomCvss
                                                        onCancel={() => setShowCustomCvss(false)}
                                                        onAddCvss={(vector) => {
                                                            addCvss(vector);
                                                        }}
                                                        triggerBanner={showMessage}
                                                        variants={!variantId ? availableVariants : undefined}
                                                        selectedVariantIds={!variantId ? selectedTargetVariantIds : undefined}
                                                        onSelectedVariantIdsChange={!variantId ? setSelectedTargetVariantIds : undefined}
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>

                                <div className="flex flex-wrap gap-2">
                                    {vuln.severity.cvss.map((cvss) => (
                                    <div
                                        key={encodeURIComponent(
                                        `${cvss.variant_id ?? 'global'}-${cvss.author}-${cvss.version}-${cvss.base_score}`
                                        )}
                                        className="bg-gray-800 p-2 rounded-xl min-w-[216px]"
                                    >
                                        <h3 className="text-center font-bold">CVSS {cvss.version}</h3>
                                        {cvss.variant_id && (
                                            <div className="flex justify-center mb-1">
                                                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                                    {availableVariants.find(v => v.id === cvss.variant_id)?.name ?? cvss.variant_id}
                                                </span>
                                            </div>
                                        )}
                                        <CvssGauge data={cvss} />
                                    </div>
                                    ))}
                                </div>

                                {!variantId && variantSnapshots.some(s => s.customCvss.length > 0) && (
                                    <div className="mt-3 p-3 rounded-lg bg-gray-800/70 border border-gray-600">
                                        <h4 className="font-semibold text-gray-200 mb-2">Custom CVSS by variant</h4>
                                        <div className="space-y-2">
                                            {variantSnapshots
                                                .filter(snapshot => snapshot.customCvss.length > 0)
                                                .map(snapshot => (
                                                    <div key={snapshot.variantId} className="text-sm">
                                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 mr-2">{snapshot.variantName}</span>
                                                        <span className="text-gray-300">
                                                            {snapshot.customCvss.map(score => `CVSS ${score.version} (${score.base_score})`).join(', ')}
                                                        </span>
                                                    </div>
                                                ))}
                                        </div>
                                    </div>
                                )}
                            </div>

                        </div>

                        <div className="mb-6 flex flex-col gap-2">
                            {vuln.texts.map((text) => {
                                return (
                                <div key={encodeURIComponent(text.title)}>
                                    <h3>
                                        <span className="font-bold mb-2">{text.title?.replace(/\b\w/g, c => c.toLocaleUpperCase())}</span>
                                        {text.packages && <span className="pl-2">({text.packages.join(", ")})</span>}
                                    </h3>
                                    <p className="leading-relaxed bg-gray-800 p-2 px-4 rounded-lg whitespace-pre-line">{text.content}</p>
                                </div>)
                            })}
                        </div>

                        <div className="mb-6 mt-6">
                            <h3 className="font-bold mb-2">Links</h3>
                            <ul>
                                {vuln.urls.map(url => (
                                    <li key={encodeURIComponent(url)}><a className="underline" href={encodeURI(url)} target="_blank">{url}</a></li>
                                ))}
                            </ul>
                        </div>

                        <div className="mb-6 mt-6" tabIndex={isEditing ? undefined : -1}>
                            <TimeEstimateEditor
                                progressBar={undefined}
                                onSaveTimeEstimation={(data) => saveEstimation(data)}
                                clearFields={clearTimeFields}
                                onFieldsChange={setHasTimeChanges}
                                triggerBanner={showMessage}
                                hideInputs={!isEditing}
                                variants={!variantId && isEditing ? availableVariants : undefined}
                                selectedVariantIds={!variantId && isEditing ? selectedTargetVariantIds : undefined}
                                onSelectedVariantIdsChange={!variantId && isEditing ? setSelectedTargetVariantIds : undefined}
                                actualEstimate={{
                                    optimistic: vuln?.effort?.optimistic?.formatHumanShort(),
                                    likely: vuln?.effort?.likely?.formatHumanShort(),
                                    pessimistic: vuln?.effort?.pessimistic?.formatHumanShort(),
                                }}
                            />

                            {!variantId && variantSnapshots.some(s => s.hasEffort) && (
                                <div className="mt-3 p-3 rounded-lg bg-gray-800/70 border border-gray-600">
                                    <h4 className="font-semibold text-gray-200 mb-2">Time estimate by variant</h4>
                                    <div className="space-y-1 text-sm text-gray-300">
                                        {variantSnapshots
                                            .filter(snapshot => snapshot.hasEffort)
                                            .map(snapshot => (
                                                <div key={snapshot.variantId}>
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded-full font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 mr-2">{snapshot.variantName}</span>
                                                    <span>O: {snapshot.effort.optimistic ?? 'N/A'} | L: {snapshot.effort.likely ?? 'N/A'} | P: {snapshot.effort.pessimistic ?? 'N/A'}</span>
                                                </div>
                                            ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="mt-6">
                            <h3 className="font-bold mb-2">Assessments</h3>
                            {currentAssessmentRows.length > 0 && (
                                <div className="mb-4 p-3 rounded-lg bg-gray-800/70 border border-gray-600">
                                    <h4 className="font-semibold text-gray-200 mb-2">Assessments on current SBOMs packages</h4>
                                    {renderStatusTable(sortStatusRows(currentAssessmentRows))}
                                </div>
                            )}
                            {deprecatedAssessmentRows.length > 0 && (
                                <div className="mb-4 p-3 rounded-lg bg-gray-800/70 border border-gray-600">
                                    <h4 className="font-semibold text-gray-200 mb-2">Assessments on old packages (not present in current SBOMs)</h4>
                                    {renderStatusTable(sortStatusRows(deprecatedAssessmentRows))}
                                </div>
                            )}
                            <h4 className="font-semibold text-gray-200 mb-2">Assessment history</h4>
                            <ol className="relative border-s border-gray-800">
                                {isEditing && (
                                    <li className="ms-4 text-white pb-8">
                                        <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-sky-500 bg-sky-500"></div>
                                        <time className="mb-1 text-sm font-normal leading-none text-gray-400">Add a new assessment</time>
                                        <StatusEditor
                                            onAddAssessment={(data) => addAssessment(data)}
                                            clearFields={clearAssessmentFields}
                                            onFieldsChange={setHasAssessmentChanges}
                                            triggerBanner={showMessage}
                                            defaultStatus={defaultStatus}
                                            variants={availableVariants}
                                            availablePackages={projectPackages}
                                            defaultSelectedPackages={vuln.packages_current}
                                            variantPackageMap={Object.keys(variantPackageMap).length > 0 ? variantPackageMap : undefined}
                                        />
                                    </li>
                                )}

                                {groupedAssessments.map(group => {
                                    const dt = new Date(group.timestamp);
                                    const firstAssess = group.assessments[0]; // Use first assessment for content
                                    const isNewlyAdded = group.assessments.some(assess => newAssessmentIds.has(assess.id));
                                    const isBeingEdited = editingAssessmentId === firstAssess.id;
                                    const groupOrigins = [...new Set(group.assessments.map(a => a.origin).filter(Boolean))];

                                    return (
                                        <li key={encodeURIComponent(group.key)} className={`mb-10 ms-4 ${isNewlyAdded ? 'new-element-glow' : ''}`}>
                                            <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-gray-800 bg-gray-800"></div>
                                            <div className="mb-2 flex flex-wrap items-center gap-2">
                                                <time className="text-sm font-normal leading-none text-gray-400">{dt.toLocaleString(undefined, dt_options)}</time>
                                                {groupOrigins.map(origin => (
                                                    <span key={origin} className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${originBadgeClass(origin)}`} title={`Assessment origin: ${origin}`}>
                                                        {originLabel(origin)}
                                                    </span>
                                                ))}
                                            </div>
                                            <div className="text-sm mb-2 flex flex-wrap gap-1">
                                                {group.packages.map(pkg => {
                                                    const { nameVersion, supplier } = splitPkgId(pkg);
                                                    const supplierName = extractSupplierName(supplier);
                                                    return (
                                                        <span key={pkg} className="inline-flex items-center px-2.5 py-0.5 rounded-full font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300" title={supplierName ? `Supplier: ${supplierName}` : undefined}>
                                                            <FontAwesomeIcon icon={faBox} className="w-3 h-3 mr-1" />
                                                            {nameVersion}
                                                            {supplierName && <span className="ml-1 opacity-70 text-xs">({supplierName})</span>}
                                                        </span>
                                                    );
                                                })}
                                            </div>
                                            {(() => {
                                                // Build the same group key (date + content fingerprint) used by
                                                // groupAssessments, then find ALL matching records in the
                                                // unfiltered allVulnAssessments so we can show every variant tag
                                                // even when the explorer is filtered to a single variant.
                                                const groupDateKey = new Date(group.timestamp).toDateString();
                                                const fp = `${firstAssess.simplified_status}|${firstAssess.justification || ''}|${firstAssess.impact_statement || ''}|${firstAssess.status_notes || ''}|${firstAssess.workaround || ''}`;
                                                const allVariantIds = [...new Set(
                                                    allVulnAssessments
                                                        .filter(a => {
                                                            const aDateKey = new Date(a.timestamp).toDateString();
                                                            const afp = `${a.simplified_status}|${a.justification || ''}|${a.impact_statement || ''}|${a.status_notes || ''}|${a.workaround || ''}`;
                                                            return aDateKey === groupDateKey && afp === fp && !!a.variant_id;
                                                        })
                                                        .map(a => a.variant_id as string)
                                                )];
                                                const variantTags = allVariantIds
                                                    .map(vid => availableVariants.find(v => v.id === vid))
                                                    .filter(Boolean) as Variant[];
                                                return variantTags.length > 0 ? (
                                                    <div className="text-sm mb-2 flex flex-wrap gap-1">
                                                        {variantTags.map(v => (
                                                            <span key={v.id} className="inline-flex items-center px-2.5 py-0.5 rounded-full font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                                                {v.name}
                                                            </span>
                                                        ))}
                                                    </div>
                                                ) : null;
                                            })()}
                                            <div className="flex items-start justify-between">
                                                <div className="flex-1">
                                                    <h3 className="text-lg font-semibold text-white mb-2 flex items-center">
                                                        {firstAssess.simplified_status}{firstAssess.justification && <> - {firstAssess.justification}</>}
                                                        {isEditing && (
                                                            <div className="flex items-center ml-3 gap-2">
                                                                <button
                                                                    onClick={() => handleEditAssessment(firstAssess.id, group)}
                                                                    className="text-blue-400 hover:text-blue-300 transition-colors"
                                                                    title="Edit assessment"
                                                                >
                                                                    <FontAwesomeIcon icon={faPenToSquare} className="w-4 h-4" />
                                                                </button>
                                                                <button
                                                                    onClick={() => handleDeleteAssessment(group)}
                                                                    className="text-red-400 hover:text-red-300 transition-colors"
                                                                    title="Delete assessment"
                                                                >
                                                                    <FontAwesomeIcon icon={faTrash} className="w-4 h-4" />
                                                                </button>
                                                            </div>
                                                        )}
                                                    </h3>
                                                    {!isBeingEdited && (
                                                        <p className="text-base font-normal text-gray-300 whitespace-pre-line">
                                                            {firstAssess.impact_statement && <>{firstAssess.impact_statement}<br/></>}
                                                            {!firstAssess.impact_statement && firstAssess.status == 'not_affected' && <>no impact statement<br/></>}
                                                            {firstAssess.status_notes ?? 'no status notes'}<br/>
                                                            {firstAssess.workaround ?? 'no workaround available'}
                                                        </p>
                                                    )}
                                                </div>
                                            </div>
                                            {isBeingEdited && (
                                                <div className="mt-3">
                                                    <EditAssessment
                                                        assessment={firstAssess}
                                                        onSaveAssessment={saveEditedAssessment}
                                                        onCancel={handleCancelEdit}
                                                        triggerBanner={showMessage}
                                                        availableVariants={availableVariants}
                                                        defaultSelectedVariantIds={[...new Set(
                                                            group.assessments
                                                                .map(a => a.variant_id)
                                                                .filter((v): v is string => !!v)
                                                        )]}
                                                        availablePackages={projectPackages}
                                                        defaultSelectedPackages={group.packages}
                                                    />
                                                </div>
                                            )}
                                        </li>
                                    );
                                })}
                            </ol>
                        </div>
                    </div>

                                        {/* Modal footer */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                        {vulnerabilities && currentIndex !== undefined ? (
                            <div className="flex items-center space-x-2">
                                <button
                                    onClick={() => navigateTo(currentIndex - 1)}
                                    disabled={!canNavigatePrevious}
                                    type="button"
                                    aria-label="Previous vulnerability"
                                    className="py-2.5 px-5 text-sm font-medium focus:outline-none rounded-lg border disabled:opacity-50 disabled:cursor-not-allowed border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-blue-500 bg-gray-800 text-gray-400"
                                >
                                    <FontAwesomeIcon icon={faChevronLeft} className="w-3 h-3 mr-2" />
                                </button>
                                <button
                                    onClick={() => navigateTo(currentIndex + 1)}
                                    disabled={!canNavigateNext}
                                    type="button"
                                    aria-label="Next vulnerability"
                                    className="py-2.5 px-5 text-sm font-medium focus:outline-none rounded-lg border disabled:opacity-50 disabled:cursor-not-allowed border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-blue-500 bg-gray-800 text-gray-400"
                                >
                                    <FontAwesomeIcon icon={faChevronRight} className="w-3 h-3 ml-2" />
                                </button>
                                {navigationInfo && (
                                    <span className="text-sm text-gray-400 px-3" id="navigation-info">
                                        {navigationInfo}
                                    </span>
                                )}
                            </div>
                        ) : (
                            <div />
                        )}
                        <button
                            onClick={handleClose}
                            type="button"
                            className="py-2.5 px-5 ms-3 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-blue-500 bg-gray-800"
                        >
                            Close
                        </button>
                    </div>

                </div>
            </div>

            <ConfirmationModal
                isOpen={showConfirmClose}
                title="Unsaved Changes"
                message={
                    pendingNavigation !== null
                        ? "Are you sure you want to navigate without saving? All unsaved changes will be lost."
                        : "Are you sure you want to close without saving? All unsaved changes will be lost."
                }
                confirmText={pendingNavigation !== null ? "Yes, navigate" : "Yes, close"}
                cancelText={pendingNavigation !== null ? "No, stay" : "No, stay"}
                showTitleIcon={true}
                onConfirm={handleConfirmClose}
                onCancel={handleCancelClose}
            />

            <ConfirmationModal
                isOpen={showDeleteConfirm}
                title="Delete Assessment"
                message={`Are you sure you want to delete this assessment? This action cannot be undone.`}
                confirmText="Yes, delete"
                cancelText="Cancel"
                showTitleIcon={true}
                onConfirm={handleConfirmDelete}
                onCancel={handleCancelDelete}
            />
        </div>
    );
}

export default VulnModal;
