import { useState, useEffect, useCallback, useRef } from "react";
import NavigationBar from "../components/NavigationBar";
import MessageBanner from "../components/MessageBanner";
import VersionDisplay from "../components/VersionDisplay";
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
import Transfer from './Transfer';
import AIContext from './AIContext';
import Assessments, { removeDuplicateAssessments, STATUS_VEX_TO_GRAPH } from '../handlers/assessments';
import Config from "../handlers/config";
import type { AppConfig } from "../handlers/config";

const tabLabels: Record<string, string> = {
        metrics: 'Metrics',
        packages: 'SBOM',
        vulnerabilities: 'Vulnerabilities',
        scans: 'Scans',
        review: 'Review',
        transfer: 'Transfer',
        exports: 'Export',
        settings: 'Settings',
        ai: 'AI Context',
};

type Props = {
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
}

function Explorer({ darkMode, setDarkMode }: Readonly<Props>) {
    const [selectorKey, setSelectorKey] = useState(0);
    const [pkgs, setPkgs] = useState<Package[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const vulnsRef = useRef<Vulnerability[]>([]);
    const [filterLabel, setFilterLabel] = useState<"Source" | "Severity" | "Status" | "Package" | undefined>(undefined);
    const [filterValue, setFilterValue] = useState<string | undefined>(undefined);
    const [filterVulnerabilityIds, setFilterVulnerabilityIds] = useState<string[] | undefined>(undefined);
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
    const [currentVariantId, setCurrentVariantId] = useState<string | undefined>(undefined);
    const [currentProjectId, setCurrentProjectId] = useState<string | undefined>(undefined);
    const [currentBaseVariantId, setCurrentBaseVariantId] = useState<string | undefined>(undefined);
    const [currentOperation, setCurrentOperation] = useState<string | undefined>(undefined);
    const [currentVariantIds, setCurrentVariantIds] = useState<string[] | undefined>(undefined);
    const [currentMultiOperation, setCurrentMultiOperation] = useState<string | undefined>(undefined);

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
        Config.get()
            .then(config => {
                setDefaultConfig(config);
                const variantId = config.variant?.id || undefined;
                const projectId = variantId ? undefined : (config.project?.id || undefined);
                setCurrentVariantId(variantId);
                setCurrentProjectId(config.project?.id || undefined);
                loadData(variantId, projectId);
            })
            .catch(() => loadData(undefined));
    }, [loadData]);

    const handleApply = useCallback((projectId: string, variantId: string, compareVariantId: string, operation: string, variantIds: string[], multiOperation: string) => {
        const multiActive = !!(variantIds && variantIds.length >= 2);
        const effectiveVariantId = multiActive ? undefined : (compareVariantId || variantId || undefined);
        setCurrentVariantId(effectiveVariantId);
        setCurrentProjectId(projectId || undefined);
        // Track origin variant and operation separately for MultiEditBar intersection logic
        setCurrentBaseVariantId((!multiActive && compareVariantId) ? (variantId || undefined) : undefined);
        setCurrentOperation((!multiActive && compareVariantId) ? (operation || undefined) : undefined);
        setCurrentVariantIds(multiActive ? variantIds : undefined);
        setCurrentMultiOperation(multiActive ? (multiOperation || undefined) : undefined);
        loadData(
            multiActive ? undefined : (variantId || undefined),
            (multiActive || !variantId) ? (projectId || undefined) : undefined,
            multiActive ? undefined : (compareVariantId || undefined),
            multiActive ? undefined : (operation || undefined),
            multiActive ? variantIds : undefined,
            multiActive ? (multiOperation || undefined) : undefined,
        );
    }, [loadData]);

    const handleScanComplete = useCallback(() => {
        loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
    }, [loadData, currentVariantId, currentProjectId, currentVariantIds, currentMultiOperation]);

    const handleRefreshComplete = useCallback(() => {
        loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
    }, [loadData, currentVariantId, currentProjectId, currentVariantIds, currentMultiOperation]);


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

    function goToVulnsTabWithFilter(filterType: "Source" | "Severity" | "Status" | "Package", value: string) {
        setFilterLabel(filterType);
        setFilterValue(value);
        setTab('vulnerabilities');
    }

    function showVulnsForPackage(packageId: string, matchingVulnerabilityIds?: string[]) {
        setFilterVulnerabilityIds(matchingVulnerabilityIds);
        goToVulnsTabWithFilter("Package", packageId);
    }

    const [tab, setTab] = useState("metrics");

    // This function ensures vulns get reset when switching outside filtering context
    function handleTabChange(newTab: string) {
        if (newTab === 'vulnerabilities' && tab !== 'vulnerabilities') {
            setFilterLabel(undefined);
            setFilterValue(undefined);
            setFilterVulnerabilityIds(undefined);
        }
        setTab(newTab);
    }

    return (
        <div className="w-screen h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] flex flex-col overflow-hidden">
            <a
                href="#main-content"
                className="sr-only focus:not-sr-only focus:absolute focus:z-[100] focus:top-2 focus:left-2 focus:px-4 focus:py-2 focus:bg-cyan-800 focus:text-white focus:rounded focus:text-sm focus:font-semibold"
            >
                Skip to content
            </a>
            <header>
                <NavigationBar
                    key={selectorKey}
                    tab={tab}
                    changeTab={handleTabChange}
                    darkMode={darkMode}
                    setDarkMode={setDarkMode}
                    defaultProject={defaultConfig.project}
                    defaultVariant={defaultConfig.variant}
                    onApply={handleApply}
                />
            </header>

            <main id="main-content" aria-label={tabLabels[tab] ?? 'Content'} className="flex-1 flex flex-col overflow-hidden">
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
                {tab === 'metrics' &&
                <Metrics
                    packages={pkgs}
                    vulnerabilities={vulns}
                    goToVulnsTabWithFilter={goToVulnsTabWithFilter}
                    appendAssessment={appendAssessment}
                    patchVuln={patchVuln}
                    setTab={setTab}
                    appendCVSS={appendCVSS}
                    projectId={currentProjectId}
                />}
                {tab === 'packages' && <TablePackages packages={pkgs} vulnerabilities={vulns} onShowVulns={showVulnsForPackage} />}
                {tab === 'vulnerabilities' &&
                <TableVulnerabilities
                    appendAssessment={appendAssessment}
                    appendCVSS={appendCVSS}
                    patchVuln={patchVuln}
                    vulnerabilities={vulns}
                    filterLabel={filterLabel}
                    filterValue={filterValue}
                    filterVulnerabilityIds={filterVulnerabilityIds}
                    variantId={currentVariantId}
                    projectId={currentProjectId}
                    baseVariantId={currentBaseVariantId}
                    compareOperation={currentOperation}
                    onRefreshComplete={handleRefreshComplete}
                    missingEuvdDataBannerDismissed={missingEuvdDataBannerDismissed}
                    onMissingEuvdDataBannerDismissedChange={setMissingEuvdDataBannerDismissed}
                    missingPublishedDateDataBannerDismissed={missingPublishedDateDataBannerDismissed}
                    onMissingPublishedDateDataBannerDismissedChange={setMissingPublishedDateDataBannerDismissed}
                />}
                {tab === 'scans' && <ScanHistory variantId={currentVariantId} projectId={currentVariantId ? undefined : currentProjectId} onScanComplete={handleScanComplete} />}
                {tab === 'review' && <Review variantId={currentVariantId} projectId={currentVariantId ? undefined : currentProjectId} onAssessmentChanged={handleAssessmentChanged} />}
                {tab === 'exports' && <Exports variantId={currentVariantId} projectId={currentProjectId} />}
                {tab === 'transfer' && <Transfer projectId={currentProjectId} onDataChanged={(message) => {
                    if (message) setLoadingMessage(message);
                    loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
                }} />}
                {tab === 'settings' && <Settings onDataChanged={(message) => {
                    if (message) setLoadingMessage(message);
                    Config.get().then(config => setDefaultConfig(config)).catch(() => {});
                    setSelectorKey(k => k + 1);
                    loadData(currentVariantId, currentVariantId ? undefined : currentProjectId, undefined, undefined, currentVariantIds, currentMultiOperation);
                }} onLoadingMessage={(msg) => {
                    if (msg) {
                        setLoadingMessage(msg);
                        setIsLoadingData(true);
                    } else {
                        setIsLoadingData(false);
                        setLoadingMessage("Loading data...");
                    }
                }} />}
                {tab === 'ai' && <AIContext />}
            </div>
            </main>
            <footer>
                <VersionDisplay />
            </footer>
        </div>
    )
}

export default Explorer
