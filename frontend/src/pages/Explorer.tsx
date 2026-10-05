import { useState, useEffect, useCallback, useRef, useSyncExternalStore } from "react";
import { useLocation, useNavigate, Routes, Route } from "react-router-dom";
import { ROUTES, tabForPath } from "../routes";
import type { RouteKey, TabKey } from "../routes";
import NavigationBar from "../components/NavigationBar";
import NotFound from "./NotFound";
import OperationQueueModal from "../components/OperationQueueModal";
import { subscribe as operationSubscribe, getSnapshot as getOperations } from "../handlers/operationStore";
import { groupQueueItems, isQueueItemActive } from "../helpers/operationRuns";
import MessageBanner from "../components/MessageBanner";
import ModalShell from "../components/ModalShell";
import type { Package } from "../handlers/packages";
import type { CVSS, Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import Packages from "../handlers/packages";
import Vulnerabilities from "../handlers/vulnerabilities";
import TablePackages from "./TablePackages";
import TableVulnerabilities from "./TableVulnerabilities";
import Metrics from "./Metrics";
import Exports from "./Exports";
import ScanHistory from "./ScanHistory";
import Review from './Review';
import type { AssessmentMutation } from './Review';
import Settings from './Settings';
import AIContext from './AIContext';
import AgentChat from '../components/AgentChat';
import type { AgentContext, AgentViewContext } from '../types/agent';
import Assessments, { removeDuplicateAssessments, STATUS_VEX_TO_GRAPH } from '../handlers/assessments';
import Config from "../handlers/config";
import type { AppConfig } from "../handlers/config";
import type { FrontendScope } from "../handlers/config";
import Projects from '../handlers/project';
import Variants from '../handlers/variant';

const tabLabels: Record<string, string> = {
        metrics: 'Metrics',
        packages: 'SBOM',
        vulnerabilities: 'Vulnerabilities',
        scans: 'Scans',
        review: 'Review',
        exports: 'Export',
        settings: 'Settings',
        ai: 'AI Context',
        unknown: 'Page not found',
};

/**
 * Intent carried by a programmatic navigation. Plain navigations (a nav-bar
 * link) carry none, so the destination always renders with a clean slate
 * instead of inheriting state from an earlier visit.
 */
type ExplorerNavState = {
    vulnFilter?: {
        label: "Source" | "Severity" | "Status" | "Package";
        value: string;
        vulnerabilityIds?: string[];
    };
    settingsDestination?: { tab: 'projects'; projectId?: string };
};

function Explorer() {
    const [selectorKey, setSelectorKey] = useState(0);
    const [pkgs, setPkgs] = useState<Package[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const vulnsRef = useRef<Vulnerability[]>([]);
    const location = useLocation();
    const navigate = useNavigate();
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);
    const [missingEuvdDataBannerDismissed, setMissingEuvdDataBannerDismissed] = useState(false);
    const [missingPublishedDateDataBannerDismissed, setMissingPublishedDateDataBannerDismissed] = useState(false);
    const [isLoadingData, setIsLoadingData] = useState<boolean>(true);
    const [loadingMessage, setLoadingMessage] = useState<string>("Loading data...");
    const [defaultConfig, setDefaultConfig] = useState<AppConfig>({
        project: null,
        variant: null,
        product_name: "",
        author_name: "vulnscout",
        client_name: "",
        contact_email: "",
        grype_memlimit: "",
    });
    const [frontendScope, setFrontendScope] = useState<FrontendScope | null>(null);
    const [currentVariantId, setCurrentVariantId] = useState<string | undefined>(undefined);
    const [currentProjectId, setCurrentProjectId] = useState<string | undefined>(undefined);
    const [currentBaseVariantId, setCurrentBaseVariantId] = useState<string | undefined>(undefined);
    const [currentOperation, setCurrentOperation] = useState<string | undefined>(undefined);
    const [currentVariantIds, setCurrentVariantIds] = useState<string[] | undefined>(undefined);
    const [currentMultiOperation, setCurrentMultiOperation] = useState<string | undefined>(undefined);
    const [operationQueueOpen, setOperationQueueOpen] = useState(false);
    const [agentOpen, setAgentOpen] = useState(false);
    const [agentMounted, setAgentMounted] = useState(false);
    const [compactAgent, setCompactAgent] = useState(false);
    const agentPanel = useRef<HTMLElement>(null);
    const mainContent = useRef<HTMLElement>(null);
    const navigation = useRef<HTMLElement>(null);
    const [vulnerabilityAgentView, setVulnerabilityAgentView] = useState<AgentViewContext>({});
    const [packagesAgentView, setPackagesAgentView] = useState<AgentViewContext>({});
    const [reviewAgentView, setReviewAgentView] = useState<AgentViewContext>({});
    const [metricsAgentView, setMetricsAgentView] = useState<AgentViewContext>({});
    const [scansAgentView, setScansAgentView] = useState<AgentViewContext>({});
    const [exportsAgentView, setExportsAgentView] = useState<AgentViewContext>({});
    const [settingsAgentView, setSettingsAgentView] = useState<AgentViewContext>({});
    const [aiAgentView, setAiAgentView] = useState<AgentViewContext>({});
    const [modalVariantScope, setModalVariantScope] = useState<{ vulnId: string; projectId?: string; ids: string[] } | null>(null);
    const [projectVariantScope, setProjectVariantScope] = useState<{ projectId: string; ids: string[] } | null>(null);
    const [setupRequirement, setSetupRequirement] = useState<
        { kind: 'project' } | { kind: 'variant'; projectId: string } | { kind: 'error' } | null
    >(null);
    const hadActiveScans = useRef(false);
    const observedOperationStatuses = useRef(new Map<string, string>());
    const setupCheckGeneration = useRef(0);
    const operationEntries = useSyncExternalStore(operationSubscribe, getOperations);
    const queueItems = groupQueueItems(operationEntries);
    const trackedScanCount = queueItems.length;
    const activeScanCount = queueItems.filter(isQueueItemActive).length;
    const finishedScanCount = trackedScanCount - activeScanCount;

    useEffect(() => {
        if (activeScanCount > 0 && !hadActiveScans.current) {
            setOperationQueueOpen(true);
        }
        hadActiveScans.current = activeScanCount > 0;
    }, [activeScanCount]);

    const loadSetupRequirement = useCallback(() => {
        const generation = ++setupCheckGeneration.current;
        return Promise.all([Projects.list(), Variants.listAll()])
            .then(([projects, variants]) => {
                if (generation !== setupCheckGeneration.current) return;
                if (projects.length === 0) {
                    setSetupRequirement({ kind: 'project' });
                } else if (variants.length === 0) {
                    setSetupRequirement({ kind: 'variant', projectId: projects[0].id });
                } else {
                    setSetupRequirement(null);
                }
            })
            .catch(() => {
                if (generation === setupCheckGeneration.current) {
                    setSetupRequirement({ kind: 'error' });
                }
            });
    }, []);

    useEffect(() => {
        void loadSetupRequirement();
    }, [loadSetupRequirement]);

    const triggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const loadData = useCallback((variantId?: string, projectId?: string, compareVariantId?: string, operation?: string, variantIds?: string[], multiOperation?: string) => {
        setIsLoadingData(true);

        const multiActive = !!(variantIds && variantIds.length >= 2);
        Promise.allSettled([
            Packages.list(variantId, projectId, compareVariantId, operation, variantIds, multiOperation),
            Vulnerabilities.list(variantId, projectId, compareVariantId, operation, variantIds, multiOperation),
        ]).then(async ([pkgsResult, vulnsResult]) => {
            if (pkgsResult.status === 'rejected' || vulnsResult.status === 'rejected') {
                throw new Error("Failed to load packages or vulnerabilities");
            }
            let assessments: Assessment[];
            if (multiActive) {
                const lists = await Promise.all(
                    variantIds!.map(id => Assessments.list(id, projectId)),
                );
                assessments = removeDuplicateAssessments(lists.flat());
            } else if (compareVariantId && variantId) {
                const [a1, a2] = await Promise.all([
                    Assessments.list(variantId, projectId),
                    Assessments.list(compareVariantId, projectId),
                ]);
                assessments = removeDuplicateAssessments([...a1, ...a2]);
            } else {
                assessments = await Assessments.list(variantId, projectId);
            }

            setIsLoadingData(false);
            setLoadingMessage("Loading data...");
            const enriched_vulns = Vulnerabilities.enrich_with_assessments(vulnsResult.value, assessments);
            setVulns(enriched_vulns);
            const enrichedPkgs = Packages.enrich_with_vulns(pkgsResult.value, enriched_vulns);
            setPkgs(enrichedPkgs);
        }).catch(error => {
            console.error(error);
            setIsLoadingData(false);
            setLoadingMessage("Loading data...");
            triggerBanner("Failed to load data", "error");
        });
    }, []);

    // On mount: fetch default project/variant from config, then load data
    useEffect(() => {
        let cancelled = false;

        Config.get()
            .then(async config => {
                let scope = Config.getFrontendScope();
                // Validate the saved scope against the live project/variant
                // lists. A transient fetch failure here must not discard the
                // successfully-loaded config: fall back to the server default
                // scope while keeping the config and loading default data.
                // When the saved scope simply no longer exists (e.g. after
                // loading a different DB), silently fall back to the default
                // scope without surfacing an error banner.
                try {
                    if (scope) {
                        const projects = await Projects.list();
                        const projectExists = projects.some(project => project.id === scope?.project_id);
                        const canConfirmProjectAbsence = projects.length > 0 || !config.project;
                        if (!projectExists && canConfirmProjectAbsence) {
                            Config.clearFrontendScope();
                            scope = null;
                        } else if (projectExists) {
                            const variants = await Variants.list(scope.project_id);
                            if (!Config.isFrontendScopeAvailable(scope, projects.map(project => project.id), variants.map(variant => variant.id))) {
                                Config.clearFrontendScope();
                                scope = null;
                            }
                        }
                    }
                } catch {
                    // Validation could not complete (e.g. network hiccup);
                    // keep the loaded config and use the server default scope.
                    scope = null;
                }
                if (cancelled) return;
                setDefaultConfig(config);
                setFrontendScope(scope);
                const multiActive = scope?.mode === 'select' && scope.variant_ids.length >= 2;
                const compareActive = scope?.mode === 'compare';
                const variantId = compareActive
                    ? scope?.compare_base_id
                    : scope?.mode === 'select' && scope.variant_ids.length === 1
                        ? scope.variant_ids[0]
                        : config.variant?.id || undefined;
                const projectId = scope?.project_id || config.project?.id || undefined;
                const compareVariantId = compareActive ? scope?.compare_variant_id : undefined;
                setCurrentVariantId(compareVariantId || variantId);
                setCurrentProjectId(projectId);
                setCurrentBaseVariantId(compareActive ? variantId : undefined);
                setCurrentOperation(compareActive ? scope?.compare_operation : undefined);
                setCurrentVariantIds(multiActive ? scope?.variant_ids : undefined);
                setCurrentMultiOperation(multiActive ? 'union' : undefined);
                loadData(
                    multiActive ? undefined : variantId,
                    (multiActive || !variantId) ? projectId : undefined,
                    compareVariantId,
                    compareActive ? scope?.compare_operation : undefined,
                    multiActive ? scope?.variant_ids : undefined,
                    multiActive ? 'union' : undefined,
                );
            })
            .catch(() => {
                if (!cancelled) loadData(undefined);
            });
        return () => { cancelled = true; };
    }, [loadData]);

    const handleApply = useCallback((projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => {
        const multiActive = !!(variantIds && variantIds.length >= 2);
        const effectiveVariantId = multiActive ? undefined : (compareVariantId || variantId || undefined);
        // A new scope invalidates any filter the previous page navigated with.
        navigate(location.pathname, { replace: true, state: null });
        setCurrentVariantId(effectiveVariantId);
        setCurrentProjectId(projectId || undefined);
        // Track origin variant and operation separately for MultiEditBar intersection logic
        setCurrentBaseVariantId((!multiActive && compareVariantId) ? (variantId || undefined) : undefined);
        setCurrentOperation((!multiActive && compareVariantId) ? (operation || undefined) : undefined);
        setCurrentVariantIds(multiActive ? variantIds : undefined);
        setCurrentMultiOperation(multiActive ? (multiOperation || undefined) : undefined);
        const frontendScope: FrontendScope = {
            project_id: projectId,
            mode: compareVariantId ? 'compare' : 'select',
            variant_ids: compareVariantId ? [] : (variantIds.length ? variantIds : (variantId ? [variantId] : [])),
            compare_base_id: compareVariantId ? variantId : '',
            compare_operation: operation === 'intersection' ? 'intersection' : 'difference',
            compare_variant_id: compareVariantId,
        };
        try {
            Config.setFrontendScope(frontendScope);
            setFrontendScope(frontendScope);
        } catch {
            triggerBanner("Selection applied, but it could not be saved for restart", "error");
        }
        loadData(
            multiActive ? undefined : (variantId || undefined),
            (multiActive || !variantId) ? (projectId || undefined) : undefined,
            multiActive ? undefined : (compareVariantId || undefined),
            multiActive ? undefined : (operation || undefined),
            multiActive ? variantIds : undefined,
            multiActive ? (multiOperation || undefined) : undefined,
        );
    }, [loadData, navigate, location.pathname]);

    const handleScanComplete = useCallback(() => {
        loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
    }, [loadData, currentVariantId, currentProjectId, currentVariantIds, currentMultiOperation]);

    const handleRefreshComplete = useCallback(() => {
        loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
    }, [loadData, currentVariantId, currentProjectId, currentVariantIds, currentMultiOperation]);

    useEffect(() => {
        const previous = observedOperationStatuses.current;
        const next = new Map(operationEntries.map(operation => [operation.op_id, operation.status]));
        const finished = operationEntries.some(operation =>
            ['scan', 'refresh', 'upload', 'enrichment'].includes(operation.kind)
            && ['done', 'error', 'cancelled'].includes(operation.status)
            && previous.get(operation.op_id) !== operation.status);
        observedOperationStatuses.current = next;
        if (finished) handleRefreshComplete();
    }, [operationEntries, handleRefreshComplete]);


    function appendAssessment(added: Assessment) {
        const updatedVulns = Vulnerabilities.append_assessment(vulns, added);
        setVulns(updatedVulns);

        // Update packages with the new vulnerability data
        setPkgs(Packages.enrich_with_vulns(pkgs, updatedVulns));
    }

    function appendCVSS(vulnId: string, vector: string) {
        const cvss: CVSS | null = Vulnerabilities.calculate_cvss_from_vector(vector, defaultConfig.author_name) ?? null;
        if (cvss !== null) {
            const updatedVulns = Vulnerabilities.append_cvss(vulns, vulnId, cvss);
            setVulns(updatedVulns);

            // Update packages with the new vulnerability data
            setPkgs(Packages.enrich_with_vulns(pkgs, updatedVulns));
            return cvss;
        }
        return null;
    }

    // Keep vulnsRef in sync when vulns state is updated externally
    // (e.g. after loadData or appendAssessment).
    useEffect(() => { vulnsRef.current = vulns; }, [vulns]);

    function patchVuln(vulnId: string, replace_vuln: Vulnerability) {
        // Update the ref immediately so the next synchronous call to patchVuln
        // (for a different CVE in the same multi-edit batch) reads the already-
        // patched list rather than the stale closure value.
        vulnsRef.current = vulnsRef.current.map(v => v.id === vulnId ? replace_vuln : v);
        setVulns(vulnsRef.current);

        // Update packages with the new vulnerability data
        setPkgs(Packages.enrich_with_vulns(pkgs, vulnsRef.current));
    }

    // Update vulns state in-place after a Review tab edit or delete
    const handleAssessmentChanged = useCallback((mutation: AssessmentMutation) => {
        setVulns(prev => prev.map(vuln => {
            if (vuln.id !== mutation.vulnId) return vuln;
            let newAssessments: Assessment[];
            if (mutation.type === 'delete') {
                newAssessments = vuln.assessments.filter(a => !mutation.ids.includes(a.id));
            } else {
                const simplified = STATUS_VEX_TO_GRAPH[mutation.data.status] ?? mutation.data.status;
                newAssessments = vuln.assessments.map(a =>
                    mutation.ids.includes(a.id)
                        ? { ...a, status: mutation.data.status, simplified_status: simplified,
                               justification: mutation.data.justification,
                               impact_statement: mutation.data.impact_statement,
                               status_notes: mutation.data.status_notes,
                               workaround: mutation.data.workaround }
                        : a
                );
            }
            const [enriched] = Vulnerabilities.enrich_with_assessments([
                {
                    ...vuln,
                    assessments: [],
                    simplified_status: 'unknown',
                }
            ], newAssessments);
            return enriched;
        }));
    }, []);

    function goToVulnsTabWithFilter(
        filterType: "Source" | "Severity" | "Status" | "Package",
        value: string,
        matchingVulnerabilityIds?: string[],
    ) {
        const state: ExplorerNavState = {
            vulnFilter: { label: filterType, value, vulnerabilityIds: matchingVulnerabilityIds },
        };
        navigate(ROUTES.vulnerabilities, { state });
    }

    const loadOutdatedPackages = useCallback(async () => {
        const baseVariantId = currentBaseVariantId ?? currentVariantId;
        const compareVariantId = currentBaseVariantId ? currentVariantId : undefined;
        const loaded = await Packages.list(
            baseVariantId,
            baseVariantId ? undefined : currentProjectId,
            compareVariantId,
            currentOperation,
            currentVariantIds,
            currentMultiOperation,
            true,
        );
        return Packages.enrich_with_vulns(loaded, vulnsRef.current);
    }, [currentBaseVariantId, currentVariantId, currentProjectId, currentOperation, currentVariantIds, currentMultiOperation]);
    const tablePreferenceScopeKey = [
        currentProjectId ?? '',
        currentBaseVariantId ?? '',
        currentVariantId ?? '',
        currentOperation,
        currentMultiOperation,
        ...(currentVariantIds ?? []),
    ].join(':');
    const outdatedPackagesScopeKey = tablePreferenceScopeKey;
    const hasOutdatedPackagesScope = Boolean(
        currentProjectId || currentVariantId || (currentVariantIds?.length ?? 0) > 0
    );

    function showVulnsForPackage(packageId: string, matchingVulnerabilityIds?: string[]) {
        goToVulnsTabWithFilter("Package", packageId, matchingVulnerabilityIds);
    }

    const tab: RouteKey = tabForPath(location.pathname);
    const activeAgentView = tab === 'vulnerabilities' ? vulnerabilityAgentView : tab === 'review' ? reviewAgentView : tab === 'packages' ? packagesAgentView : tab === 'metrics' ? metricsAgentView : tab === 'scans' ? scansAgentView : tab === 'exports' ? exportsAgentView : tab === 'settings' ? settingsAgentView : tab === 'ai' ? aiAgentView : undefined;
    const openAgentVulnerabilityId = activeAgentView?.openVulnerabilityId;
    const agentOverlay = compactAgent && !openAgentVulnerabilityId;

    useEffect(() => {
        const update = () => setCompactAgent(window.innerWidth < 1024);
        update();
        window.addEventListener('resize', update);
        return () => window.removeEventListener('resize', update);
    }, []);

    useEffect(() => {
        if (!agentOpen) return;
        setAgentMounted(true);
        const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        agentPanel.current?.focus();
        return () => { window.requestAnimationFrame(() => { if (previousFocus?.isConnected) previousFocus.focus(); }); };
    }, [agentOpen]);

    useEffect(() => {
        const background = [mainContent.current, navigation.current];
        background.forEach(element => { if (element) element.inert = agentOpen && agentOverlay; });
        return () => { background.forEach(element => { if (element) element.inert = false; }); };
    }, [agentOpen, agentOverlay]);

    useEffect(() => {
        if (!agentOpen || !currentProjectId) return;
        const controller = new AbortController();
        Variants.list(currentProjectId, controller.signal).then(variants => {
            if (!controller.signal.aborted) setProjectVariantScope({ projectId: currentProjectId, ids: variants.map(variant => variant.id) });
        }).catch(() => {
            if (!controller.signal.aborted) setProjectVariantScope(null);
        });
        return () => controller.abort();
    }, [agentOpen, currentProjectId]);

    useEffect(() => {
        if (!agentOpen || !openAgentVulnerabilityId) return;
        const controller = new AbortController();
        Variants.listByVuln(openAgentVulnerabilityId, controller.signal).then(variants => {
            if (!controller.signal.aborted) setModalVariantScope({
                vulnId: openAgentVulnerabilityId,
                projectId: currentProjectId,
                ids: variants.filter(variant => !currentProjectId || variant.project_id === currentProjectId).map(variant => variant.id),
            });
        }).catch(() => {
            if (!controller.signal.aborted) setModalVariantScope(null);
        });
        return () => controller.abort();
    }, [agentOpen, openAgentVulnerabilityId, currentProjectId]);

    const agentContext: AgentContext = {
        page: tab,
        projectId: currentProjectId,
        variantId: currentVariantId,
        baseVariantId: currentBaseVariantId,
        compareOperation: currentOperation,
        variantIds: currentVariantIds ?? (!currentVariantId && projectVariantScope?.projectId === currentProjectId ? projectVariantScope?.ids : undefined),
        multiOperation: currentMultiOperation,
        view: activeAgentView && {
            ...activeAgentView,
            matchingVariantIds: openAgentVulnerabilityId && modalVariantScope?.vulnId === openAgentVulnerabilityId && modalVariantScope.projectId === currentProjectId
                ? modalVariantScope.ids : undefined,
        },
    };

    // Navigation intent for the current location, set by the page that
    // navigated here. Reading it during render (instead of resetting state in
    // an effect) guarantees the destination's first render already has the
    // right filter/destination, so a plain nav-bar click can never make it
    // mount with leftovers from an earlier visit.
    const navState = (location.state ?? null) as ExplorerNavState | null;
    const vulnFilter = navState?.vulnFilter;
    const settingsDestination = navState?.settingsDestination ?? null;

    // Accepts a plain string to match Metrics' existing setTab prop contract;
    // every caller passes one of our known tab keys.
    function handleTabChange(newTab: string) {
        navigate(ROUTES[newTab as TabKey] ?? ROUTES.metrics);
    }

    return (
        <div className="w-screen h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] flex flex-col overflow-hidden">
            <a
                href="#main-content"
                className="sr-only focus:not-sr-only focus:absolute focus:z-[100] focus:top-2 focus:left-2 focus:px-4 focus:py-2 focus:bg-cyan-800 focus:text-white focus:rounded focus:text-sm focus:font-semibold"
            >
                Skip to content
            </a>
            <header ref={navigation}>
                <NavigationBar
                    key={selectorKey}
                    defaultProject={defaultConfig.project}
                    defaultVariant={defaultConfig.variant}
                    defaultScope={frontendScope}
                    onApply={handleApply}
                    trackedScanCount={trackedScanCount}
                    finishedScanCount={finishedScanCount}
                    activeScanCount={activeScanCount}
                    onOpenOperationQueue={() => setOperationQueueOpen(true)}
                    isAgentOpen={agentOpen}
                    onToggleAgent={() => setAgentOpen(open => !open)}
                />
            </header>
            <OperationQueueModal isOpen={operationQueueOpen} onClose={() => setOperationQueueOpen(false)} />
            <ModalShell
                isOpen={!agentOpen && tab === 'metrics' && setupRequirement !== null}
                title={setupRequirement?.kind === 'project'
                    ? 'Add your first project'
                    : setupRequirement?.kind === 'variant'
                        ? 'Add a project variant'
                        : 'Unable to check setup'}
                onClose={() => setSetupRequirement(null)}
                testId="setup-required-popup"
                size="compact"
            >
                <p className="text-sm text-gray-600 dark:text-gray-300">
                    {setupRequirement?.kind === 'project'
                        ? 'Projects organize your software variants, vulnerability data, scans, and assessments. Create one to get started.'
                        : setupRequirement?.kind === 'variant'
                            ? 'VulnScout needs a variant before it can display metrics for your project.'
                            : 'VulnScout could not load the project list. Check the connection and try again.'}
                </p>
                <div className="mt-5 flex justify-end gap-2">
                    <button
                        type="button"
                        onClick={() => { setSetupRequirement(null); setAgentOpen(true); }}
                        className="rounded-md border border-sky-700 px-4 py-2 text-sm font-semibold text-sky-700 hover:bg-sky-50 dark:text-sky-300 dark:hover:bg-neutral-800"
                    >
                        Ask agent
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            if (setupRequirement?.kind === 'error') {
                                void loadSetupRequirement();
                                return;
                            }
                            const state: ExplorerNavState = {
                                settingsDestination: {
                                    tab: 'projects',
                                    projectId: setupRequirement?.kind === 'variant'
                                        ? setupRequirement.projectId
                                        : undefined,
                                },
                            };
                            navigate(ROUTES.settings, { state });
                        }}
                        className="rounded-md bg-sky-700 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600 focus:outline-none focus:ring-2 focus:ring-sky-400"
                    >
                        {setupRequirement?.kind === 'error' ? 'Retry' : 'Go to settings'}
                    </button>
                </div>
            </ModalShell>

            <div className="flex flex-1 min-h-0">
            <main ref={mainContent} id="main-content" aria-label={tabLabels[tab] ?? 'Content'} className="relative flex-1 min-w-0 flex flex-col overflow-hidden">
            <div className="px-8 pt-4">
                <MessageBanner
                    type={bannerType}
                    message={bannerMessage}
                    isVisible={bannerVisible}
                    onClose={closeBanner}
                />
            </div>

            {isLoadingData && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40" role="status" aria-live="polite">
                    <div className="flex flex-col items-center gap-3 text-white">
                        <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin" aria-hidden="true"></div>
                        <span className="text-sm font-semibold">{loadingMessage}</span>
                    </div>
                </div>
            )}

            <div className="p-5 flex-1 overflow-auto">
                <Routes>
                <Route path={ROUTES.metrics} element={
                    <Metrics
                        packages={pkgs}
                        vulnerabilities={vulns}
                        goToVulnsTabWithFilter={goToVulnsTabWithFilter}
                        appendAssessment={appendAssessment}
                        patchVuln={patchVuln}
                        setTab={handleTabChange}
                        appendCVSS={appendCVSS}
                        projectId={currentProjectId}
                        onAgentContextChange={setMetricsAgentView}
                        onOpenAgent={() => setAgentOpen(true)}
                    />
                } />
                <Route path={ROUTES.packages} element={
                    <TablePackages
                        key={tablePreferenceScopeKey}
                        packages={pkgs}
                        vulnerabilities={vulns}
                        preferenceScopeKey={tablePreferenceScopeKey}
                        onAgentContextChange={setPackagesAgentView}
                        onShowVulns={showVulnsForPackage}
                        onLoadOutdatedPackages={hasOutdatedPackagesScope ? loadOutdatedPackages : undefined}
                        outdatedScopeKey={outdatedPackagesScopeKey}
                    />
                } />
                <Route path={ROUTES.vulnerabilities} element={
                    <TableVulnerabilities
                        key={tablePreferenceScopeKey}
                        appendAssessment={appendAssessment}
                        appendCVSS={appendCVSS}
                        patchVuln={patchVuln}
                        vulnerabilities={vulns}
                        preferenceScopeKey={tablePreferenceScopeKey}
                        filterLabel={vulnFilter?.label}
                        filterValue={vulnFilter?.value}
                        filterVulnerabilityIds={vulnFilter?.vulnerabilityIds}
                        variantId={currentVariantId}
                        projectId={currentProjectId}
                        baseVariantId={currentBaseVariantId}
                        compareOperation={currentOperation}
                        variantIds={currentVariantIds}
                        multiOperation={currentMultiOperation}
                        onRefreshComplete={handleRefreshComplete}
                        missingEuvdDataBannerDismissed={missingEuvdDataBannerDismissed}
                        onMissingEuvdDataBannerDismissedChange={setMissingEuvdDataBannerDismissed}
                        missingPublishedDateDataBannerDismissed={missingPublishedDateDataBannerDismissed}
                        onMissingPublishedDateDataBannerDismissedChange={setMissingPublishedDateDataBannerDismissed}
                        onAgentContextChange={setVulnerabilityAgentView}
                        onOpenAgent={() => setAgentOpen(true)}
                    />
                } />
                <Route path={ROUTES.scans} element={
                    <ScanHistory
                        onAgentContextChange={setScansAgentView}
                        variantId={currentVariantId}
                        projectId={currentVariantId ? undefined : currentProjectId}
                        variantIds={currentVariantIds}
                        onScanComplete={handleScanComplete}
                    />
                } />
                <Route path={ROUTES.review} element={
                    <Review variantId={currentVariantId} projectId={currentVariantId ? undefined : currentProjectId} onAssessmentChanged={handleAssessmentChanged} onAgentContextChange={setReviewAgentView} onOpenAgent={() => setAgentOpen(true)} />
                } />
                <Route path={ROUTES.exports} element={
                    <Exports variantId={currentVariantId} projectId={currentProjectId} variantIds={currentVariantIds} onAgentContextChange={setExportsAgentView} />
                } />
                <Route path={ROUTES.settings} element={
                    <Settings onAgentContextChange={setSettingsAgentView} initialTab={settingsDestination?.tab} onDataChanged={(message) => {
                        if (message) setLoadingMessage(message);
                        Config.get().then(config => setDefaultConfig(config)).catch(() => {});
                        loadSetupRequirement();
                        setSelectorKey(k => k + 1);
                        loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
                    }} projectId={settingsDestination ? settingsDestination.projectId : currentProjectId} onLoadingMessage={(msg) => {
                        if (msg) {
                            setLoadingMessage(msg);
                            setIsLoadingData(true);
                        } else {
                            setIsLoadingData(false);
                            setLoadingMessage("Loading data...");
                        }
                    }} />
                } />
                <Route path={ROUTES.ai} element={<AIContext onAgentContextChange={setAiAgentView} />} />
                <Route path="*" element={<NotFound />} />
                </Routes>
            </div>
            </main>
            {(agentOpen || agentMounted) && <aside ref={agentPanel} id="agent-panel" tabIndex={-1} role={agentOverlay ? 'dialog' : 'complementary'} aria-modal={agentOverlay && agentOpen ? true : undefined} aria-label="Agent chat" hidden={!agentOpen} onKeyDown={event => {
                if (event.target instanceof Element && event.target.closest('dialog[open]')) return;
                if (event.key === 'Escape') {
                    event.preventDefault();
                    event.stopPropagation();
                    setAgentOpen(false);
                }
                if (event.key === 'Tab' && agentOverlay) {
                    event.stopPropagation();
                    const controls = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex="0"]')).filter(element => element.getClientRects().length > 0);
                    const first = controls[0];
                    const last = controls[controls.length - 1];
                    if (event.shiftKey && (document.activeElement === first || document.activeElement === event.currentTarget)) {
                        event.preventDefault();
                        last?.focus();
                    } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === event.currentTarget)) {
                        event.preventDefault();
                        first?.focus();
                    }
                }
            }} className={`fixed inset-0 ${openAgentVulnerabilityId ? 'z-[90]' : 'z-[110]'} h-dvh w-full max-w-full border-l border-neutral-200 bg-white outline-none dark:border-neutral-700 dark:bg-neutral-950 lg:w-[400px] lg:shrink-0 xl:w-[440px] 2xl:w-[480px] ${agentContext.view?.openVulnerabilityId ? 'lg:inset-y-0 lg:right-0 lg:left-auto lg:shadow-2xl' : 'lg:static lg:h-auto'}`}>
                <AgentChat active={agentOpen} context={agentContext} onClose={() => setAgentOpen(false)} />
            </aside>}
            </div>
        </div>
    )
}

export default Explorer
