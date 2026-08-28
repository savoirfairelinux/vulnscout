import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import Vulnerabilities, { asCVSS, buildStatusSummary } from "../handlers/vulnerabilities";
import type { Assessment, AssessmentGroup, AssessmentTarget } from "../handlers/assessments";
import Assessments, { asAssessment, isMultiTargetGroup } from "../handlers/assessments";
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
import { faBox, faChevronDown, faChevronLeft, faChevronRight, faPenToSquare, faTrash, faPlus, faCircleQuestion, faBook, faRotate, faCheck, faRobot, faCopy } from "@fortawesome/free-solid-svg-icons";
import ConfirmationModal from "./ConfirmationModal";
import EditAssessment from "./EditAssessment";
import type { EditAssessmentData } from "./EditAssessment";
import HelpPopover from "./HelpPopover";
import Variants from '../handlers/variant';
import { formatSourceName } from '../helpers/sourceNames';
import { useDocUrl } from '../helpers/useDocUrl';
import { splitPkgId, formatPkgId, extractSupplierName } from '../helpers/pkgId';
import type { Variant } from '../handlers/variant';
import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import NvdRefreshHandler from "../handlers/nvdRefresh";
import EpssRefreshHandler from "../handlers/epssRefresh";
import GhsaRefreshHandler from "../handlers/ghsaRefresh";
import ModalShell, { ModalActions, ModalButton } from "./ModalShell";

type Props = {
    vuln: Vulnerability;
    detailsLoading?: boolean;
    detailsError?: boolean;
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

// How long the inline "Copied" confirmation stays next to a copy button.
const COPIED_FEEDBACK_MS = 2000;

const hasAssessmentText = (value: string | null | undefined): boolean => Boolean(value?.trim());

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



type StatusSortKey = 'variant' | 'package' | 'status' | 'justification' | 'impact' | 'notes' | 'workaround';

type VariantFinding = {
    findingId: string;
    pkg: string;
    outdated: boolean;
};

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
        const { vuln, detailsLoading = false, detailsError = false, isEditing: initialIsEditing, readOnly = false, onClose, appendAssessment, appendCVSS, patchVuln, vulnerabilities, currentIndex, onNavigate, variantId, projectId } = props;
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
    const [showCpeHint, setShowCpeHint] = useState(false);
    const [showCpeList, setShowCpeList] = useState(false);
    const [availableVariants, setAvailableVariants] = useState<Variant[]>([]);
    const [variantsLoadedForVulnId, setVariantsLoadedForVulnId] = useState<string | null>(null);
    const [allVulnAssessments, setAllVulnAssessments] = useState<Assessment[]>([]);
    const [assessmentGroups, setAssessmentGroups] = useState<AssessmentGroup[]>([]);
    const [selectedTargetVariantIds, setSelectedTargetVariantIds] = useState<string[]>([]);
    const [variantSnapshots, setVariantSnapshots] = useState<VariantScopedSnapshot[]>([]);
    const [variantPackageMap, setVariantPackageMap] = useState<Record<string, string[]>>({});
    const [variantFindingsMap, setVariantFindingsMap] = useState<Record<string, VariantFinding[]>>({});
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

    useEffect(() => {
        const closeCpeHint = (event: MouseEvent) => {
            const target = event.target;
            if (target instanceof Element && !target.closest('[data-cpe-hint]')) {
                setShowCpeHint(false);
            }
        };
        if (showCpeHint) {
            document.addEventListener('mousedown', closeCpeHint);
        }
        return () => document.removeEventListener('mousedown', closeCpeHint);
    }, [showCpeHint]);

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

    // Fetch all assessments for this vulnerability in the current project so
    // its history remains complete when the Explorer is variant-scoped.
    useEffect(() => {
        const controller = new AbortController();
        setAllVulnAssessments([]);
        const projectQuery = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
        fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments${projectQuery}`, { mode: 'cors', signal: controller.signal })
            .then(r => r.json())
            .then((data: any[]) => {
                if (Array.isArray(data)) {
                    const fullAssessments = data.flatMap(asAssessment).filter((a): a is Assessment => !Array.isArray(a));
                    const fullById = new Map(fullAssessments.map(a => [a.id, a]));
                    // Keep the Explorer's current scope, but replace its compact
                    // assessment rows with the full records used by the modal.
                    vuln.assessments = vuln.assessments.map(a => fullById.get(a.id) ?? a);
                    setAllVulnAssessments(fullAssessments);
                }
            })
            .catch(() => {});
        return () => controller.abort();
    }, [vuln, projectId]);

    // Re-fetch the full assessment list after a group mutation (reconcile,
    // approve/reject, delete) so vuln.assessments/allVulnAssessments — and
    // therefore the status table above the history — reflect the write.
    // vuln.assessments is rebuilt from the returned list rather than patched
    // by id, because a reconcile can create and delete rows: a merge by id
    // would keep deleted records and miss the new ones. Returns the list
    // scoped the way the modal is scoped, which is what callers must use to
    // recompute the vulnerability status summary.
    const refreshAllVulnAssessments = useCallback(async (): Promise<Assessment[] | null> => {
        const projectQuery = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
        try {
            const r = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments${projectQuery}`, { mode: 'cors' });
            const data = await r.json();
            if (Array.isArray(data)) {
                const fullAssessments = data.flatMap(asAssessment).filter((a): a is Assessment => !Array.isArray(a));
                const scopedAssessments = variantId
                    ? fullAssessments.filter(a => a.variant_id === variantId)
                    : fullAssessments;
                vuln.assessments = scopedAssessments;
                setAllVulnAssessments(fullAssessments);
                return scopedAssessments;
            }
        } catch {
            // Keep whatever was previously loaded.
        }
        return null;
    }, [vuln, projectId, variantId]);

    // Fetch server-built assessment groups for this vulnerability (Task 8/11),
    // replacing the old client-side grouping heuristic. When this request is
    // still pending, empty, or fails, the render below falls back to grouping
    // allVulnAssessments/vuln.assessments locally so history still renders.
    const refreshAssessmentGroups = useCallback(async () => {
        try {
            const groups = await Assessments.listGroups(vuln.id, projectId);
            setAssessmentGroups(Array.isArray(groups) ? groups : []);
        } catch {
            // Keep whatever was previously loaded; the render's fallback path
            // covers the case where nothing ever loaded successfully.
        }
    }, [vuln.id, projectId]);

    useEffect(() => {
        const controller = new AbortController();
        setAssessmentGroups([]);
        Assessments.listGroups(vuln.id, projectId)
            .then(groups => {
                if (!controller.signal.aborted) setAssessmentGroups(Array.isArray(groups) ? groups : []);
            })
            .catch(() => {});
        return () => controller.abort();
    }, [vuln.id, projectId]);

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
        setVariantFindingsMap({});
        if (availableVariants.length === 0) {
            // Only mark as loaded once we know variants have been resolved.
            // If variants are still loading (variantsLoadedForVulnId !== vuln.id),
            // keep variantPackageMapLoaded = false to avoid a premature
            // "all packages deprecated" flash when the map is empty but
            // variants haven't arrived yet.
            if (variantsLoadedForVulnId === vuln.id) {
                setVariantPackageMap({});
                setVariantPackageMapLoaded(true);
            }
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
                const findingsMap: Record<string, VariantFinding[]> = {};
                if (Array.isArray(data)) {
                    for (const entry of data) {
                        if (entry && typeof entry.variant_id === 'string' && Array.isArray(entry.active_packages)) {
                            map[entry.variant_id] = entry.active_packages.filter((p: unknown): p is string => typeof p === 'string');
                            if (Array.isArray(entry.findings)) {
                                findingsMap[entry.variant_id] = entry.findings.flatMap((finding: any): VariantFinding[] => {
                                    if (typeof finding?.finding_id !== 'string' || typeof finding?.package !== 'string') return [];
                                    return [{
                                        findingId: finding.finding_id,
                                        pkg: finding.package,
                                        outdated: finding.outdated === true,
                                    }];
                                });
                            }
                        }
                    }
                }
                if (!signal.aborted) {
                    setVariantPackageMap(map);
                    setVariantFindingsMap(findingsMap);
                    setVariantPackageMapLoaded(true);
                }
            } catch {
                if (!signal.aborted) {
                    setVariantPackageMap({});
                    setVariantFindingsMap({});
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
    // Identifies which copy button was last used, so only that one confirms.
    const [copiedGroupKey, setCopiedGroupKey] = useState<string | null>(null);

    const copiedResetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const modalRef = useRef<HTMLDivElement>(null);

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
                    NvdRefreshHandler.triggerSingleRefresh(vuln.id, "api"),
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
                    } else if (nvdValue?.kind === "error" && nvdValue.code === "unauthorized") {
                        errors.push("NVD API key rejected. Check your key in Settings.");
                    } else {
                        errors.push("NVD API unavailable. Please try again later.");
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

    const groupCopyKey = (group: AssessmentGroup) =>
        `${isMultiTargetGroup(group.targets) ? 'group' : 'assessment'}:${group.group_id ?? group.assessment_ids[0]}`;

    const copyGroupId = async (group: AssessmentGroup) => {
        const text = groupCopyKey(group);
        try {
            await navigator.clipboard.writeText(text);
            // Confirm the copy inline: the clipboard gives no visible feedback of
            // its own, so without this the button looks inert.
            setCopiedGroupKey(text);
            if (copiedResetTimer.current !== null) clearTimeout(copiedResetTimer.current);
            copiedResetTimer.current = setTimeout(() => setCopiedGroupKey(null), COPIED_FEEDBACK_MS);
        } catch {
            // Clipboard access can be denied by the browser; nothing more to do.
        }
    };

    // Drop the pending reset if the modal closes while the confirmation shows.
    useEffect(() => () => {
        if (copiedResetTimer.current !== null) clearTimeout(copiedResetTimer.current);
    }, []);

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

    const handleApproveAiAssessment = async (group: AssessmentGroup) => {
        try {
            const groupId = group.group_id ?? await Assessments.promoteToGroup(group.assessment_ids[0]);
            const approved = await Assessments.approveAiGroup(groupId);
            const approvedIds = new Set(group.assessment_ids);
            const approvedById = new Map(approved.map(a => [a.id, a]));

            setAllVulnAssessments(prev => prev.map(a => {
                if (!approvedIds.has(a.id)) return a;
                return approvedById.get(a.id) ?? { ...a, origin: "custom" };
            }));

            approved.forEach(a => {
                if (!vuln.assessments.some(x => x.id === a.id)) {
                    vuln.assessments.push(a);
                } else {
                    vuln.assessments = vuln.assessments.map(x => x.id === a.id ? a : x);
                }
            });

            const latest = vuln.assessments.slice().sort(
                (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
            );
            if (latest.length > 0) vuln.simplified_status = latest[0].simplified_status;

            patchVuln(vuln.id, vuln);
            refreshAssessmentGroups();
            showMessage("AI assessment approved!", "success");
        } catch (e) {
            showMessage(`Failed to approve AI assessment: ${escape(String(e))}`, "error");
        }
    };

    const handleRejectAiAssessment = async (group: AssessmentGroup) => {
        try {
            const groupId = group.group_id ?? await Assessments.promoteToGroup(group.assessment_ids[0]);
            await Assessments.rejectAiGroup(groupId);
            const rejectedIds = new Set(group.assessment_ids);
            setAllVulnAssessments(prev => prev.filter(a => !rejectedIds.has(a.id)));
            refreshAssessmentGroups();
            showMessage("AI assessment rejected.", "success");
        } catch (e) {
            showMessage(`Failed to reject AI assessment: ${escape(String(e))}`, "error");
        }
    };

    const handleConfirmDelete = async () => {
        if (groupToDelete) {
            const idsToDelete = groupToDelete.assessment_ids;
            let anyError = false;

            if (groupToDelete.group_id) {
                try {
                    await Assessments.deleteGroup(groupToDelete.group_id);
                    const deletedIds = new Set(idsToDelete);
                    vuln.assessments = vuln.assessments.filter(a => !deletedIds.has(a.id));
                    setAllVulnAssessments(prev => prev.filter(a => !deletedIds.has(a.id)));
                } catch (error) {
                    anyError = true;
                    showMessage(`Failed to delete assessment: ${escape(String(error))}`, "error");
                }
            } else {
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
                refreshAssessmentGroups();
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

        // Keep every row affected by this edit in one history group. Depending
        // on the user's choice, reuse the group's timestamp or move the whole
        // group to the top with one shared current timestamp.
        const editSharedTimestamp = data.update_timestamp === false
            ? editingGroup.timestamp
            : new Date().toISOString();

        const targetPackages: string[] =
            data.packages && data.packages.length > 0
                ? data.packages
                : [...new Set(editingGroup.targets.map(t => t.package))];

        // A group-reconcile call needs at least one variant target — the
        // backend rejects an empty ``variant_ids`` list. When the user has a
        // variant to target, reconcile the whole group (creating one on the
        // fly for an ungrouped entry) in a single request. Otherwise fall back
        // to the legacy per-row PUT/POST/DELETE flow below, which is the only
        // way to edit an assessment that isn't scoped to any variant.
        const targetVariantIds: string[] =
            data.variant_ids && data.variant_ids.length > 0 ? data.variant_ids : [];

        if (targetVariantIds.length > 0) {
            try {
                const groupId = editingGroup.group_id
                    ?? await Assessments.promoteToGroup(editingGroup.assessment_ids[0]);
                const body: Record<string, unknown> = {
                    vuln_id: vuln.id,
                    packages: targetPackages,
                    variant_ids: targetVariantIds,
                    existing_ids: editingGroup.assessment_ids,
                    status: data.status,
                    justification: data.justification,
                    impact_statement: data.impact_statement,
                    status_notes: data.status_notes,
                    workaround: data.workaround,
                    update_timestamp: data.update_timestamp !== false,
                    timestamp: editSharedTimestamp,
                };
                await Assessments.reconcileGroup(groupId, body);
                const reconciledAssessments = await refreshAllVulnAssessments();
                await refreshAssessmentGroups();

                const updatedAssessments = [...(reconciledAssessments ?? vuln.assessments)];
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
            } catch (e) {
                showMessage(`Failed to update assessment: ${escape(String(e))}`, 'error');
            }

            setSubmittingMessage(null);
            setEditingAssessmentId(null);
            setEditingGroup(null);
            return;
        }

        // Legacy per-row path (no variant target selected). Index the group's
        // underlying Assessment records — sourced from allVulnAssessments/
        // vuln.assessments, the same data the group itself was built from —
        // by (pkg, vid) key.
        const groupAssessmentRecords = (allVulnAssessments.length > 0 ? allVulnAssessments : vuln.assessments)
            .filter(a => editingGroup.assessment_ids.includes(a.id));
        const existingByKey = new Map<string, Assessment>();
        for (const a of groupAssessmentRecords) {
            const pkg = a.packages[0] ?? '';
            const vid = a.variant_id ?? '';
            existingByKey.set(`${pkg}::${vid}`, a);
        }

        // Build the desired target key set. This branch only runs when no
        // variant was selected, so every target is scoped to "no variant".
        const legacyVariantIds: Array<string | undefined> = [undefined];
        const targetKeys = new Set<string>();
        for (const pkg of targetPackages) {
            for (const vid of legacyVariantIds) {
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
                            workaround: data.workaround,
                            update_timestamp: data.update_timestamp !== false,
                            timestamp: editSharedTimestamp,
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
            for (const vid of legacyVariantIds) {
                const key = `${pkg}::${vid ?? ''}`;
                if (!existingByKey.has(key)) {
                    const arr = newPkgsByVariant.get(vid) ?? [];
                    arr.push(pkg);
                    newPkgsByVariant.set(vid, arr);
                }
            }
        }

        // One submit is one request: the backend then assigns one group per
        // vulnerability. Posting per variant would create one group per variant.
        const batchItems = [...newPkgsByVariant.entries()]
            .filter(([, pkgs]) => pkgs.length > 0)
            .map(([vid, pkgs]) => ({
                vuln_id: vuln.id,
                packages: pkgs,
                status: data.status,
                justification: data.justification,
                impact_statement: data.impact_statement,
                status_notes: data.status_notes,
                workaround: data.workaround,
                timestamp: editSharedTimestamp,
                ...(vid ? { variant_id: vid } : {}),
            }));

        if (batchItems.length > 0) {
            try {
                const result = await Assessments.createBatch(batchItems);
                if (result.status === 'success') {
                    for (const raw of result.assessments) {
                        const casted = normalise(raw);
                        if (casted) {
                            vuln.assessments.push(casted);
                            setAllVulnAssessments(prev => [...prev, casted]);
                        }
                    }
                } else {
                    anyError = true;
                    showMessage('Failed to create assessment', 'error');
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
            refreshAssessmentGroups();
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

    // Build AssessmentGroup-shaped entries from raw assessments, mirroring the
    // server's grouping shape (src/controllers/assessment_groups.py). Used as
    // a fallback whenever assessmentGroups has no entry for a given bucket
    // (non-ai / ai) — most commonly because Assessments.listGroups is still
    // in flight on mount (assessmentGroups starts at [] and this fallback
    // fills the gap using vuln.assessments/allVulnAssessments, which render
    // synchronously), and it self-corrects on the next render once the real
    // response lands. It also engages if the request errors, or if the
    // server genuinely returns zero groups for a vulnerability with zero
    // assessments — both cases where the fallback's own computation is also
    // empty, so nothing is shown either way. This is a best-effort client-side
    // guess for "we don't have the server's answer yet," not a proven
    // equivalence with it: every write path below (delete/approve/reject/
    // reconcile) guards on group_id being non-null before calling a
    // group-scoped endpoint, so a stale/guessed fallback group can't corrupt
    // a write — but if listGroups has already resolved and genuinely returned
    // fewer/different groups than this heuristic would compute from the same
    // assessments (e.g. a backend grouping bug), this fallback would silently
    // paper over that mismatch rather than surface it, since there is no
    // separate "loading" flag distinguishing "not fetched yet" from "fetched
    // and empty."
    const buildFallbackGroups = (assessments: Assessment[]): AssessmentGroup[] => {
        const buckets: { [key: string]: Assessment[] } = {};

        assessments.forEach(assess => {
            // Rows created by one user action share the exact timestamp. Keep
            // separate actions distinct even when their content is identical.
            const contentKey = `${assess.simplified_status}|${assess.justification || ''}|${assess.impact_statement || ''}|${assess.status_notes || ''}|${assess.workaround || ''}`;
            const groupKey = `${assess.timestamp}::${contentKey}`;

            if (!buckets[groupKey]) {
                buckets[groupKey] = [];
            }
            buckets[groupKey].push(assess);
        });

        return Object.values(buckets)
            .map((members): AssessmentGroup => {
                const head = members[0];
                const targets: AssessmentTarget[] = members.flatMap(member =>
                    member.packages.map(pkg => {
                        const finding = member.variant_id
                            ? variantFindingsMap[member.variant_id]?.find(item => item.pkg === pkg)
                            : undefined;
                        const outdated = finding?.outdated ?? (
                            variantPackageMapLoaded
                            && !!member.variant_id
                            && variantPackageMap[member.variant_id] !== undefined
                            && !variantPackageMap[member.variant_id].includes(pkg)
                        );
                        return { variant_id: member.variant_id ?? null, package: pkg, outdated, assessment_id: member.id };
                    })
                );
                return {
                    group_id: null,
                    vuln_id: head.vuln_id,
                    status: head.status,
                    simplified_status: head.simplified_status,
                    justification: head.justification ?? '',
                    impact_statement: head.impact_statement ?? '',
                    status_notes: head.status_notes ?? '',
                    workaround: head.workaround ?? '',
                    responses: head.responses ?? [],
                    origin: head.origin,
                    timestamp: head.timestamp,
                    targets,
                    assessment_ids: members.map(m => m.id),
                };
            })
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    };

    // Prefer the project-wide response so history includes every variant. The
    // scoped vulnerability rows remain a fallback for unavailable or empty
    // history responses.
    const effectiveAssessments = allVulnAssessments.length > 0 ? allVulnAssessments : vuln.assessments;

    const nonAiRealGroups = assessmentGroups.filter(g => g.origin !== 'ai');
    const nonAiGroups = nonAiRealGroups.length > 0
        ? nonAiRealGroups
        : buildFallbackGroups(effectiveAssessments.filter(assessment => assessment.origin !== 'ai'));

    const pendingAiAssessments = allVulnAssessments.filter(a =>
        a.origin === "ai" && (!variantId || a.variant_id === variantId));
    const aiRealGroups = assessmentGroups.filter(g =>
        g.origin === 'ai' && (!variantId || g.targets.some(t => t.variant_id === variantId)));
    const aiGroups = aiRealGroups.length > 0
        ? aiRealGroups
        : buildFallbackGroups(pendingAiAssessments);

    const latestAssessmentFor = (variantIdValue: string, pkg: string | null): Assessment | null =>
        allVulnAssessments
            .filter(a => a.origin !== "ai" && a.variant_id === variantIdValue && (pkg === null || a.packages.includes(pkg)))
            .reduce<Assessment | null>((best, a) => {
                if (!best) return a;
                return new Date(a.timestamp).getTime() > new Date(best.timestamp).getTime() ? a : best;
            }, null);

    type StatusRow = { variant: Variant; pkg: string | null; assessment: Assessment | null; deprecated: boolean };

    const allStatusRows: StatusRow[] = availableVariants.flatMap((variant): StatusRow[] => {
        const variantActivePkgs = variantPackageMap[variant.id];
        const variantPkgs = variantActivePkgs ?? [];
        // Packages affected by this vuln that still exist in the variant's active SBOM.
        const activeAffected = projectPackages.filter(p => variantPkgs.includes(p));
        // Packages referenced by the variant's assessments may include older,
        // now-deprecated versions that are no longer in the active SBOM.
        const assessmentPkgs = [...new Set(
            allVulnAssessments
                .filter(a => a.origin !== "ai" && a.variant_id === variant.id)
                .flatMap(a => a.packages)
        )];
        const allPkgs = [...new Set([...activeAffected, ...assessmentPkgs])];
        const hasActivePkgData = variantPackageMapLoaded && variantActivePkgs !== undefined;
        if (allPkgs.length === 0) {
            return [{ variant, pkg: null, assessment: latestAssessmentFor(variant.id, null), deprecated: false }];
        }
        return allPkgs.slice().sort().map(pkg => ({
            variant,
            pkg,
            assessment: latestAssessmentFor(variant.id, pkg),
            // A package is deprecated once it's no longer in the variant's active
            // SBOM. Until that list has loaded, keep it in the current table.
            deprecated: hasActivePkgData && !variantPkgs.includes(pkg),
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
        if (nonAiGroups.length > 0) {
            // Get the most recent group's status (nonAiGroups are already sorted by most recent first)
            return nonAiGroups[0].status;
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
        const variantIds: string[] =
            content.variant_ids && content.variant_ids.length > 0
                ? content.variant_ids
                : variantId
                ? [variantId]
                : [];

        const { variant_ids: _, ...baseContent } = content;
        const sharedTimestamp = new Date().toISOString();

        setSubmittingMessage('Adding assessment...');
        try {
            // One user action -> one request -> one fused Assessment row,
            // whose target_rows cover every selected (package, variant) combo.
            const response = await fetch(
                import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments`,
                {
                    method: 'POST',
                    mode: 'cors',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...baseContent,
                        variant_ids: variantIds,
                        timestamp: sharedTimestamp,
                    }),
                }
            );
            const data = await response.json();
            const row = data?.assessment ?? (Array.isArray(data?.assessments) ? data.assessments[0] : undefined);
            if (response.ok !== false && data?.status === 'success' && row) {
                const casted = asAssessment(row);
                if (!Array.isArray(casted) && typeof casted === 'object') {
                    setNewAssessmentIds(prev => new Set(prev).add(casted.id));
                    setTimeout(() => {
                        setNewAssessmentIds(prev => {
                            const newSet = new Set(prev);
                            newSet.delete(casted.id);
                            return newSet;
                        });
                    }, 5500);

                    appendAssessment(casted);
                    vuln.assessments.push(casted);
                    // Keep allVulnAssessments in sync so variant tags appear immediately
                    setAllVulnAssessments(prev => [...prev, casted]);
                    vuln.simplified_status = casted.simplified_status;

                    // History renders from the server-built groups, so
                    // refresh them or the assessment just created stays
                    // invisible until the modal is reopened.
                    await refreshAssessmentGroups();

                    const updatedAssessments = [...vuln.assessments];
                    const statusSummary = buildStatusSummary(updatedAssessments, vuln.packages_current);
                    patchVuln(vuln.id, {
                        ...vuln,
                        assessments: updatedAssessments,
                        simplified_status: statusSummary.dominant_status,
                        status_summary: statusSummary,
                    });

                    const variantCount = casted.variant_ids?.length ?? 0;
                    const packageCount = casted.packages.length;
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
                    }
                    showMessage(msg, 'success');
                    setClearAssessmentFields(true);
                    setTimeout(() => setClearAssessmentFields(false), 100);
                }
            } else {
                const detail = String(data?.error ?? 'The selected package versions are not valid for every selected variant.');
                showMessage(`Assessment not added: ${escape(detail)}`, 'error');
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

    const headerActions = (
        <>
            <div className="relative flex items-center gap-2 px-2 py-2">
                <HelpPopover
                    ariaLabel="shortcut helper"
                    title="View keyboard shortcuts"
                    heading="Keyboard Shortcuts"
                    open={showShortcutHelper}
                    onOpenChange={setShowShortcutHelper}
                    surfaceClassName="w-[300px]"
                >
                    <div className="space-y-2 text-neutral-200">
                        <div className="flex justify-between gap-4"><span className="font-semibold text-neutral-300">← / →</span><span>Previous/Next vulnerability</span></div>
                        <div className="flex justify-between gap-4"><span className="font-semibold text-neutral-300">Esc</span><span>Close shortcuts</span></div>
                    </div>
                </HelpPopover>
                <a
                    href={docUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="documentation"
                    title="Open documentation"
                    className="transition-colors hover:text-blue-400"
                >
                    <FontAwesomeIcon icon={faBook} size="lg" />
                </a>
            </div>
            {!readOnly && (
                <div className="flex flex-wrap items-center gap-2">
                    <button
                        onClick={handleRefresh}
                        disabled={refreshing}
                        title={isGhsaVuln ? "Refresh from GitHub Advisory Database" : "Refresh from NVD & EPSS"}
                        type="button"
                        className={`rounded-lg border bg-transparent px-3 py-2 text-sm font-medium transition-colors focus:outline-none disabled:cursor-not-allowed disabled:opacity-50 ${
                            bothRefreshed
                                ? "border-green-600 text-green-400 hover:bg-green-900"
                                : partialRefreshed
                                    ? "border-yellow-600 text-yellow-400 hover:bg-yellow-900"
                                    : "border-gray-600 text-gray-300 hover:bg-gray-600 hover:text-white"
                        }`}
                    >
                        <FontAwesomeIcon icon={(bothRefreshed || partialRefreshed) ? faCheck : faRotate} className={refreshing ? "animate-spin" : ""} />
                        {bothRefreshed && <span className="ml-2 text-xs">Updated</span>}
                        {partialRefreshed && <span className="ml-2 text-xs">{refreshedList[0]} Updated</span>}
                    </button>
                    {refreshError && <span className="text-xs text-red-400">{refreshError}</span>}
                </div>
            )}
            {!readOnly && (
                <button
                    onClick={() => setIsEditing(!isEditing)}
                    type="button"
                    className={`rounded-lg px-3 py-2 text-sm font-medium text-white transition-colors ${isEditing ? "bg-blue-700 hover:bg-blue-800" : "bg-blue-600 hover:bg-blue-700"}`}
                    title={isEditing ? "Exit editing mode" : "Enter editing mode"}
                >
                    <FontAwesomeIcon icon={faPenToSquare} className="mr-2" />
                    {isEditing ? "Exit editing" : "Edit"}
                </button>
            )}
        </>
    );

    const footer = (
        <ModalActions align="between">
            {vulnerabilities && currentIndex !== undefined ? (
                <div className="flex items-center space-x-2">
                    <button onClick={() => navigateTo(currentIndex - 1)} disabled={!canNavigatePrevious} type="button" aria-label="Previous vulnerability" className="rounded-lg border border-gray-600 bg-gray-800 px-5 py-2.5 text-sm font-medium text-gray-400 hover:bg-gray-700 hover:text-white focus:outline-none focus:ring-4 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50">
                        <FontAwesomeIcon icon={faChevronLeft} className="mr-2 h-3 w-3" />
                    </button>
                    <button onClick={() => navigateTo(currentIndex + 1)} disabled={!canNavigateNext} type="button" aria-label="Next vulnerability" className="rounded-lg border border-gray-600 bg-gray-800 px-5 py-2.5 text-sm font-medium text-gray-400 hover:bg-gray-700 hover:text-white focus:outline-none focus:ring-4 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50">
                        <FontAwesomeIcon icon={faChevronRight} className="ml-2 h-3 w-3" />
                    </button>
                    {navigationInfo && <span className="px-3 text-sm text-gray-400" id="navigation-info">{navigationInfo}</span>}
                </div>
            ) : <div />}
            <ModalButton onClick={handleClose}>Close</ModalButton>
        </ModalActions>
    );

    return (
        <>
        <ModalShell
            key={vuln.id}
            isOpen={true}
            title={vuln.id}
            size="fullscreen"
            titleId="vulnerability_modal_title"
            onClose={handleClose}
            closeLabel="Close modal"
            closeOnEscape={false}
            closeOnPanel={true}
            testId="vuln-modal-backdrop"
            panelRef={modalRef}
            panelTabIndex={-1}
            headerActions={headerActions}
            contentClassName="relative flex min-h-0 flex-1 flex-col p-0 md:p-0"
            footer={footer}
        >
            {submittingMessage && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40">
                    <div className="flex flex-col items-center gap-3 text-white">
                        <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span className="text-sm font-semibold">{submittingMessage}</span>
                    </div>
                </div>
            )}
                    {/* Scrollable content region (only the body scrolls) */}
                    <div className="flex-1 overflow-y-auto min-h-0">

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

                        {detailsLoading && (
                            <div className="mb-6 rounded-lg bg-gray-800 p-3 text-gray-300">
                                Loading description, links, and CVSS details...
                            </div>
                        )}
                        {detailsError && (
                            <div className="mb-6 rounded-lg bg-red-900 p-3 text-red-100">
                                Vulnerability details could not be loaded.
                            </div>
                        )}

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

                        {(vuln.cpes?.length ?? 0) > 0 && (
                            <div className="mb-6 mt-6">
                                <div className="relative mb-2 flex items-center gap-2">
                                    <h3 className="font-bold">Affected CPEs ({vuln.cpes?.length})</h3>
                                    <button
                                        aria-label="About affected CPEs"
                                        type="button"
                                        data-cpe-hint
                                        className="text-sky-300 hover:text-sky-100 transition-colors"
                                        onClick={() => setShowCpeHint(current => !current)}
                                    >
                                        <FontAwesomeIcon icon={faCircleQuestion} />
                                    </button>
                                    <button
                                        aria-expanded={showCpeList}
                                        aria-label={showCpeList ? "Collapse affected CPEs" : "Expand affected CPEs"}
                                        title={showCpeList ? "Collapse affected CPEs" : "Expand affected CPEs"}
                                        type="button"
                                        className="text-sky-300 hover:text-sky-100 transition-colors"
                                        onClick={() => setShowCpeList(current => !current)}
                                    >
                                        <FontAwesomeIcon className={showCpeList ? "rotate-180 transition-transform" : "transition-transform"} icon={faChevronDown} />
                                    </button>
                                    {showCpeHint && (
                                        <div
                                            role="tooltip"
                                            data-cpe-hint
                                            className="absolute top-full mt-1 left-0 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-3 z-50 w-[360px] text-sm text-left"
                                        >
                                            <h3 className="font-bold text-white mb-2">Affected CPEs</h3>
                                            <div className="space-y-1 text-gray-100">
                                                <p>These CPEs are provided by NVD for this vulnerability.</p>
                                                <p>They describe all NVD-reported affected products, not only packages in the current scope.</p>
                                                <p>They do not indicate whether the current project, variant, or scan is affected.</p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                                {showCpeList && (
                                    <ul className="max-h-64 overflow-y-auto space-y-1 rounded-lg bg-gray-800 p-3 text-sm">
                                        {vuln.cpes?.map(cpe => (
                                            <li key={cpe}><code className="break-all">{cpe}</code></li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}

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
                                    <h4 className="font-semibold text-gray-200 mb-2">Assessments on current SBOM packages and variants</h4>
                                    {renderStatusTable(sortStatusRows(currentAssessmentRows))}
                                </div>
                            )}
                            {deprecatedAssessmentRows.length > 0 && (
                                <div className="mb-4 p-3 rounded-lg bg-gray-800/70 border border-gray-600">
                                    <h4 className="font-semibold text-gray-200 mb-2">Assessments on old packages and variants (not present in current SBOMs)</h4>
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
                                            variantFindingsMap={variantFindingsMap}
                                            findingsLoading={!variantPackageMapLoaded}
                                        />
                                    </li>
                                )}

                                {aiGroups.map(group => {
                                    const groupKey = group.group_id ?? group.assessment_ids[0];
                                    const firstTarget = group.targets[0];
                                    const hasStatusNotes = hasAssessmentText(group.status_notes);
                                    const hasWorkaround = hasAssessmentText(group.workaround);
                                    return (
                                        <div
                                            key={`ai-${encodeURIComponent(groupKey)}`}
                                            data-group-id={group.group_id ?? undefined}
                                            className="mb-6 p-4 rounded-lg border-2 border-amber-500 bg-amber-950/30"
                                        >
                                            <div className="flex items-center justify-between mb-2">
                                                <span className="inline-flex items-center gap-2 text-amber-300 font-semibold">
                                                    <FontAwesomeIcon icon={faRobot} className="w-4 h-4" />
                                                    AI-generated · Pending review
                                                    {(() => {
                                                        const v = availableVariants.find(v => v.id === firstTarget?.variant_id);
                                                        return v ? <span className="ml-1 opacity-80 text-xs">({v.name})</span> : null;
                                                    })()}
                                                </span>
                                                <div className="flex items-center gap-2">
                                                    {isEditing && (
                                                    <div className="flex gap-2">
                                                        <button
                                                            type="button"
                                                            onClick={() => handleApproveAiAssessment(group)}
                                                            className="px-3 py-1 rounded bg-green-600 hover:bg-green-500 text-white text-sm"
                                                        >
                                                            Approve
                                                        </button>
                                                        <button
                                                            type="button"
                                                            onClick={() => handleRejectAiAssessment(group)}
                                                            className="px-3 py-1 rounded bg-red-600 hover:bg-red-500 text-white text-sm"
                                                        >
                                                            Reject
                                                        </button>
                                                    </div>
                                                    )}
                                                    <button
                                                        type="button"
                                                        onClick={() => copyGroupId(group)}
                                                        aria-label={isMultiTargetGroup(group.targets) ? "Copy group id" : "Copy assessment id"}
                                                        title={isMultiTargetGroup(group.targets) ? "Copy group id" : "Copy assessment id"}
                                                        className="text-amber-300 hover:text-amber-100 transition-colors"
                                                    >
                                                        <FontAwesomeIcon icon={faCopy} className="w-4 h-4" />
                                                    </button>
                                                    {copiedGroupKey === groupCopyKey(group) && (
                                                        <span role="status" className="inline-flex items-center gap-1 text-xs text-amber-300">
                                                            <FontAwesomeIcon icon={faCheck} className="w-3 h-3" />
                                                            Copied
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                            <div className="text-sm mb-2 flex flex-wrap gap-1">
                                                {group.targets.map(target => {
                                                    const { nameVersion, supplier } = splitPkgId(target.package);
                                                    const supplierName = extractSupplierName(supplier);
                                                    const variant = availableVariants.find(v => v.id === target.variant_id);
                                                    return (
                                                        <span key={`${target.variant_id ?? ''}::${target.package}`} className="inline-flex items-center px-2.5 py-0.5 rounded-full font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">
                                                            <FontAwesomeIcon icon={faBox} className="w-3 h-3 mr-1" />
                                                            {nameVersion}
                                                            {supplierName && <span className="ml-1 opacity-70 text-xs">({supplierName})</span>}
                                                            {variant && <span className="ml-1.5 opacity-80">· {variant.name}</span>}
                                                            {target.outdated && (
                                                                <span className="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide bg-amber-200 text-amber-900 dark:bg-amber-700 dark:text-amber-100">
                                                                    Outdated
                                                                </span>
                                                            )}
                                                        </span>
                                                    );
                                                })}
                                            </div>
                                            <h3 className="text-lg font-semibold text-white mb-1">
                                                {group.simplified_status}
                                                {group.justification && <> - {group.justification}</>}
                                            </h3>
                                            {(group.impact_statement || hasStatusNotes || hasWorkaround) && (
                                                <p className="text-base font-normal text-gray-300 whitespace-pre-line">
                                                    {group.impact_statement && <>{group.impact_statement}<br/></>}
                                                    {hasStatusNotes && <>{group.status_notes}<br/></>}
                                                    {hasWorkaround && group.workaround}
                                                </p>
                                            )}
                                        </div>
                                    );
                                })}

                                {nonAiGroups.map(group => {
                                    const dt = new Date(group.timestamp);
                                    const groupKey = group.group_id ?? group.assessment_ids[0];
                                    const firstId = group.assessment_ids[0];
                                    const isNewlyAdded = group.assessment_ids.some(id => newAssessmentIds.has(id));
                                    const isBeingEdited = editingAssessmentId === firstId;
                                    const hasStatusNotes = hasAssessmentText(group.status_notes);
                                    const hasWorkaround = hasAssessmentText(group.workaround);
                                    const groupPackages = [...new Set(group.targets.map(t => t.package))];
                                    // Build a synthetic Assessment for EditAssessment, which still expects
                                    // one Assessment object rather than a group.
                                    const groupAsAssessment: Assessment = {
                                        id: firstId,
                                        vuln_id: vuln.id,
                                        packages: groupPackages,
                                        variant_id: group.targets[0]?.variant_id ?? undefined,
                                        origin: group.origin,
                                        status: group.status,
                                        simplified_status: group.simplified_status,
                                        status_notes: group.status_notes,
                                        justification: group.justification,
                                        impact_statement: group.impact_statement,
                                        workaround: group.workaround,
                                        timestamp: group.timestamp,
                                        responses: group.responses,
                                    };

                                    return (
                                        <li key={groupKey} data-group-id={group.group_id ?? undefined} className={`mb-10 ms-4 ${isNewlyAdded ? 'new-element-glow' : ''}`}>
                                            <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-gray-800 bg-gray-800"></div>
                                            <div className="mb-2 flex flex-wrap items-center gap-2">
                                                <time className="text-sm font-normal leading-none text-gray-400">{dt.toLocaleString(undefined, dt_options)}</time>
                                                {group.origin && (
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${originBadgeClass(group.origin)}`} title={`Assessment origin: ${group.origin}`}>
                                                        {originLabel(group.origin)}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="text-sm mb-2 flex flex-wrap gap-1">
                                                {group.targets.map(target => {
                                                    const { nameVersion, supplier } = splitPkgId(target.package);
                                                    const supplierName = extractSupplierName(supplier);
                                                    const variant = availableVariants.find(v => v.id === target.variant_id);
                                                    return (
                                                        <span key={`${target.variant_id ?? ''}::${target.package}`} className={`inline-flex items-center px-2.5 py-0.5 rounded-full font-medium ${target.outdated ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300' : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'}`} title={supplierName ? `Supplier: ${supplierName}` : undefined}>
                                                            <FontAwesomeIcon icon={faBox} className="w-3 h-3 mr-1" />
                                                            {nameVersion}
                                                            {supplierName && <span className="ml-1 opacity-70 text-xs">({supplierName})</span>}
                                                            {variant && <span className="ml-1.5 opacity-80">· {variant.name}</span>}
                                                            {target.outdated && (
                                                                <span className="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide bg-amber-200 text-amber-900 dark:bg-amber-700 dark:text-amber-100">
                                                                    Outdated
                                                                </span>
                                                            )}
                                                        </span>
                                                    );
                                                })}
                                            </div>
                                            <div className="flex items-start justify-between">
                                                <div className="flex-1">
                                                    <h3 className="text-lg font-semibold text-white mb-2 flex items-center">
                                                        {group.simplified_status}{group.justification && <> - {group.justification}</>}
                                                        <div className="flex items-center ml-3 gap-2">
                                                            {isEditing && (
                                                                <>
                                                                    <button
                                                                        onClick={() => handleEditAssessment(firstId, group)}
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
                                                                </>
                                                            )}
                                                            <button
                                                                type="button"
                                                                onClick={() => copyGroupId(group)}
                                                                aria-label={isMultiTargetGroup(group.targets) ? "Copy group id" : "Copy assessment id"}
                                                                title={isMultiTargetGroup(group.targets) ? "Copy group id" : "Copy assessment id"}
                                                                className="text-gray-400 hover:text-gray-200 transition-colors"
                                                            >
                                                                <FontAwesomeIcon icon={faCopy} className="w-4 h-4" />
                                                            </button>
                                                            {copiedGroupKey === groupCopyKey(group) && (
                                                                <span role="status" className="inline-flex items-center gap-1 text-xs text-green-400">
                                                                    <FontAwesomeIcon icon={faCheck} className="w-3 h-3" />
                                                                    Copied
                                                                </span>
                                                            )}
                                                        </div>
                                                    </h3>
                                                    {!isBeingEdited && (group.impact_statement || group.status === 'not_affected' || hasStatusNotes || hasWorkaround) && (
                                                        <p className="text-base font-normal text-gray-300 whitespace-pre-line">
                                                            {group.impact_statement && <>{group.impact_statement}<br/></>}
                                                            {!group.impact_statement && group.status == 'not_affected' && <>no impact statement<br/></>}
                                                            {hasStatusNotes && <>{group.status_notes}<br/></>}
                                                            {hasWorkaround && group.workaround}
                                                        </p>
                                                    )}
                                                </div>
                                            </div>
                                            {isBeingEdited && (
                                                <div className="mt-3">
                                                    <EditAssessment
                                                        assessment={groupAsAssessment}
                                                        onSaveAssessment={saveEditedAssessment}
                                                        onCancel={handleCancelEdit}
                                                        triggerBanner={showMessage}
                                                        availableVariants={availableVariants}
                                                        defaultSelectedVariantIds={[...new Set(
                                                            group.targets
                                                                .map(t => t.variant_id)
                                                                .filter((v): v is string => !!v)
                                                        )]}
                                                        availablePackages={projectPackages}
                                                        defaultSelectedPackages={groupPackages}
                                                        variantPackageMap={Object.keys(variantPackageMap).length > 0 ? variantPackageMap : undefined}
                                                        variantFindingsMap={variantFindingsMap}
                                                        findingsLoading={!variantPackageMapLoaded}
                                                    />
                                                </div>
                                            )}
                                        </li>
                                    );
                                })}
                            </ol>
                        </div>
                    </div>

                    </div>
        </ModalShell>

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
        </>
    );
}

export default VulnModal;
