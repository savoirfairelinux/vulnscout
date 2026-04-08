import { useState, useEffect, useCallback, useRef } from "react";
import NavigationBar from "../components/NavigationBar";
import MessageBanner from "../components/MessageBanner";
import VersionDisplay from "../components/VersionDisplay";
import type { Package } from "../handlers/packages";
import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import type { PackageVulnerabilities } from "../handlers/patch_finder";
import type { NVDProgress } from "../handlers/nvd_progress";
import Packages from "../handlers/packages";
import Vulnerabilities from "../handlers/vulnerabilities";
import PatchFinderLogic from "../handlers/patch_finder";
import NVDProgressHandler from "../handlers/nvd_progress";
import TablePackages from "./TablePackages";
import TableVulnerabilities from "./TableVulnerabilities";
import PatchFinder from "./PatchFinder";
import Metrics from "./Metrics";
import Exports from "./Exports";
import ScanHistory from "./ScanHistory";
import Review from "./Review";
import Assessments, { removeDuplicateAssessments } from "../handlers/assessments";
import Config from "../handlers/config";
import type { AppConfig } from "../handlers/config";

type Props = {
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
}

function Explorer({ darkMode, setDarkMode }: Readonly<Props>) {
    // PatchFinder data (lazily loaded when navigating to patch-finder tab)
    const [pkgs, setPkgs] = useState<Package[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [patchInfo, setPatchInfo] = useState<PackageVulnerabilities>({});
    const [patchDbReady, setPatchDbReady] = useState<boolean>(false);
    const [nvdProgress, setNvdProgress] = useState<NVDProgress | null>(null);
    const [isLoadingPatchData, setIsLoadingPatchData] = useState<boolean>(false);
    // Stored apply params for lazy PatchFinder loading
    const lastApplyParamsRef = useRef<{variantId?: string, projectId?: string, compareVariantId?: string, operation?: string} | null>(null);

    const [filterLabel, setFilterLabel] = useState<"Source" | "Severity" | "Status" | "Package" | undefined>(undefined);
    const [filterValue, setFilterValue] = useState<string | undefined>(undefined);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);
    const [defaultConfig, setDefaultConfig] = useState<AppConfig>({ project: null, variant: null });
    const [currentVariantId, setCurrentVariantId] = useState<string | undefined>(undefined);
    const [currentProjectId, setCurrentProjectId] = useState<string | undefined>(undefined);
    const [currentBaseVariantId, setCurrentBaseVariantId] = useState<string | undefined>(undefined);
    const [currentOperation, setCurrentOperation] = useState<string | undefined>(undefined);
    const [tab, setTab] = useState("metrics");

    const triggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const loadPatchData = useCallback((vulns_list: Vulnerability[]) => {
        const active_status = ['Exploitable', 'Pending Assessment'];
        PatchFinderLogic
        .scan(vulns_list.filter(el => active_status.includes(el.simplified_status)).map(el => el.id))
        .then((patchData) => {
            setPatchInfo(patchData);
        })
        .catch((err) => {
            console.error(err);
            triggerBanner("Failed to load patch data", "error");
        });
    }, []);

    const checkPatchReady = useCallback((vulns_list: Vulnerability[]) => {
        Promise.all([
            PatchFinderLogic.status(),
            NVDProgressHandler.getProgress()
        ])
        .then(([patchData, progress]) => {
            setNvdProgress(progress);
            if (patchData.db_ready) {
                setPatchDbReady(true);
                loadPatchData(vulns_list);
            } else {
                setTimeout(() => checkPatchReady(vulns_list), progress.in_progress ? 3000 : 15000);
                setPatchDbReady(false);
            }
        })
        .catch((err) => {
            console.error(err);
            triggerBanner("Failed to load patch data", "error");
        });
    }, [loadPatchData]);

    // Load packages + vulns + assessments for PatchFinder only
    const loadDataForPatchFinder = useCallback((variantId?: string, projectId?: string, compareVariantId?: string, operation?: string) => {
        setIsLoadingPatchData(true);

        const assessPromise: Promise<Assessment[]> = (compareVariantId && variantId)
            ? Promise.all([
                Assessments.list(variantId, projectId),
                Assessments.list(compareVariantId, projectId),
              ]).then(([a1, a2]) => removeDuplicateAssessments([...a1, ...a2]))
            : Assessments.list(variantId, projectId);

        Promise.allSettled([
            Packages.list(variantId, projectId, compareVariantId, operation),
            Vulnerabilities.list(variantId, projectId, compareVariantId, operation),
            assessPromise,
        ]).then(([pkgsResult, vulnsResult, assessResult]) => {
            setIsLoadingPatchData(false);
            if (pkgsResult.status === 'rejected' || vulnsResult.status === 'rejected' || assessResult.status === 'rejected') {
                triggerBanner("Failed to load patch data", "error");
                return;
            }
            const enriched_vulns = Vulnerabilities.enrich_with_assessments(vulnsResult.value, assessResult.value);
            setVulns(enriched_vulns);
            setPkgs(Packages.enrich_with_vulns(pkgsResult.value, enriched_vulns));
            setTimeout(() => checkPatchReady(enriched_vulns), 100);
        });
    }, [checkPatchReady]);

    // On mount: fetch default project/variant from config
    useEffect(() => {
        Config.get()
            .then(config => {
                setDefaultConfig(config);
                const variantId = config.variant?.id || undefined;
                const projectId = variantId ? undefined : (config.project?.id || undefined);
                setCurrentVariantId(variantId);
                setCurrentProjectId(projectId);
                lastApplyParamsRef.current = { variantId, projectId };
            })
            .catch(() => {});
    }, []);

    const handleApply = useCallback((projectId: string, variantId: string, compareVariantId: string, operation: string) => {
        const effectiveVariantId = compareVariantId || variantId || undefined;
        const effectiveProjectId = effectiveVariantId ? undefined : (projectId || undefined);
        setCurrentVariantId(effectiveVariantId);
        setCurrentProjectId(effectiveProjectId);
        setCurrentBaseVariantId(compareVariantId ? (variantId || undefined) : undefined);
        setCurrentOperation(compareVariantId ? (operation || undefined) : undefined);
        // Store params so PatchFinder can lazily load them
        lastApplyParamsRef.current = {
            variantId: variantId || undefined,
            projectId: variantId ? undefined : projectId || undefined,
            compareVariantId: compareVariantId || undefined,
            operation: operation || undefined,
        };
        // New: if already on patch-finder tab, load immediately
        if (tab === 'patch-finder') {
            loadDataForPatchFinder(
                variantId || undefined,
                variantId ? undefined : projectId || undefined,
                compareVariantId || undefined,
                operation || undefined,
            );
        }
    }, [loadDataForPatchFinder, tab]);

    function goToVulnsTabWithFilter(filterType: "Source" | "Severity" | "Status" | "Package", value: string) {
        setFilterLabel(filterType);
        setFilterValue(value);
        setTab('vulnerabilities');
    }

    function showVulnsForPackage(packageId: string) {
        goToVulnsTabWithFilter("Package", packageId);
    }

    function handleTabChange(newTab: string) {
        if (newTab === 'vulnerabilities' && tab !== 'vulnerabilities') {
            setFilterLabel(undefined);
            setFilterValue(undefined);
        }
        // Lazy-load PatchFinder data on first navigation to that tab
        if (newTab === 'patch-finder' && tab !== 'patch-finder') {
            const params = lastApplyParamsRef.current;
            loadDataForPatchFinder(params?.variantId, params?.projectId, params?.compareVariantId, params?.operation);
        }
        setTab(newTab);
    }

    return (
        <div className="w-screen h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] flex flex-col overflow-hidden">
            <NavigationBar
                tab={tab}
                changeTab={handleTabChange}
                darkMode={darkMode}
                setDarkMode={setDarkMode}
                defaultProject={defaultConfig.project}
                defaultVariant={defaultConfig.variant}
                onApply={handleApply}
            />

            <div className="px-8 pt-4">
                <MessageBanner
                    type={bannerType}
                    message={bannerMessage}
                    isVisible={bannerVisible}
                    onClose={closeBanner}
                />
            </div>

            {isLoadingPatchData && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40">
                    <div className="flex flex-col items-center gap-3 text-white">
                        <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span className="text-sm font-semibold">Loading patch data...</span>
                    </div>
                </div>
            )}

            <div className="p-5 flex-1 overflow-auto">
                {tab === 'metrics' &&
                <Metrics
                    variantId={currentVariantId}
                    projectId={currentProjectId}
                    goToVulnsTabWithFilter={goToVulnsTabWithFilter}
                    appendAssessment={() => {}}
                    patchVuln={() => {}}
                    setTab={setTab}
                    appendCVSS={() => null}
                />}
                {tab === 'packages' &&
                <TablePackages
                    variantId={currentVariantId}
                    projectId={currentProjectId}
                    compareVariantId={currentBaseVariantId ? currentVariantId : undefined}
                    compareOperation={currentOperation}
                    onShowVulns={showVulnsForPackage}
                />}
                {tab === 'vulnerabilities' &&
                <TableVulnerabilities
                    variantId={currentBaseVariantId ? currentBaseVariantId : currentVariantId}
                    projectId={currentProjectId}
                    filterLabel={filterLabel}
                    filterValue={filterValue}
                    baseVariantId={currentBaseVariantId ? currentVariantId : undefined}
                    compareOperation={currentOperation}
                />}
                {tab === 'patch-finder' && <PatchFinder vulnerabilities={vulns} packages={pkgs} patchData={patchInfo} db_ready={patchDbReady} nvdProgress={nvdProgress} />}
                {tab === 'scans' && <ScanHistory variantId={currentVariantId} />}
                {tab === 'exports' && <Exports />}
                {tab === 'review' && <Review variantId={currentVariantId} projectId={currentProjectId} />}
            </div>
            <VersionDisplay />
        </div>
    )
}

export default Explorer
