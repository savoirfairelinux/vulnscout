import { useState, useEffect, useCallback } from "react";
import NavigationBar from "../components/NavigationBar";
import MessageBanner from "../components/MessageBanner";
import VersionDisplay from "../components/VersionDisplay";
import type { Package } from "../handlers/packages";
import type { CVSS, Vulnerability } from "../handlers/vulnerabilities";
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
import Assessments from "../handlers/assessments";
import Config from "../handlers/config";
import type { AppConfig } from "../handlers/config";

type Props = {
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
}

function Explorer({ darkMode, setDarkMode }: Readonly<Props>) {
    const [pkgs, setPkgs] = useState<Package[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [patchInfo, setPatchInfo] = useState<PackageVulnerabilities>({});
    const [patchDbReady, setPatchDbReady] = useState<boolean>(false);
    const [nvdProgress, setNvdProgress] = useState<NVDProgress | null>(null);
    const [filterLabel, setFilterLabel] = useState<"Source" | "Severity" | "Status" | "Package" | undefined>(undefined);
    const [filterValue, setFilterValue] = useState<string | undefined>(undefined);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);
    const [isLoadingData, setIsLoadingData] = useState<boolean>(true);
    const [defaultConfig, setDefaultConfig] = useState<AppConfig>({ project: null, variant: null });
    const [currentVariantId, setCurrentVariantId] = useState<string | undefined>(undefined);

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
        // Check both patch status and NVD progress
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
        })
    }, [loadPatchData]);

    const loadData = useCallback((variantId?: string, projectId?: string, compareVariantId?: string, operation?: string) => {
        // When compare is active, packages/assessments are scoped to the compare variant
        const activeVariantId = compareVariantId || variantId;
        setIsLoadingData(true);
        Promise.allSettled([
            Packages.list(activeVariantId, projectId),
            Vulnerabilities.list(variantId, projectId, compareVariantId, operation),
            Assessments.list(activeVariantId, projectId)
        ]).then(([pkgsResult, vulnsResult, assessResult]) => {
            setIsLoadingData(false);
            if (pkgsResult.status === 'rejected' || vulnsResult.status === 'rejected' || assessResult.status === 'rejected') {
                console.error(pkgsResult, vulnsResult);
                triggerBanner("Failed to load data", "error");
                return;
            }
            const enriched_vulns = Vulnerabilities.enrich_with_assessments(vulnsResult.value, assessResult.value);
            setVulns(enriched_vulns);
            setPkgs(Packages.enrich_with_vulns(pkgsResult.value, enriched_vulns));
            setTimeout(() => checkPatchReady(enriched_vulns), 100);
        });
    }, [checkPatchReady]);

    // On mount: fetch default project/variant from config, then load data
    useEffect(() => {
        Config.get()
            .then(config => {
                setDefaultConfig(config);
                const variantId = config.variant?.id || undefined;
                const projectId = variantId ? undefined : (config.project?.id || undefined);
                setCurrentVariantId(variantId);
                loadData(variantId, projectId);
            })
            .catch(() => loadData(undefined));
    }, [loadData]);

    const handleApply = useCallback((projectId: string, variantId: string, compareVariantId: string, operation: string) => {
        const effectiveVariantId = compareVariantId || variantId || undefined;
        setCurrentVariantId(effectiveVariantId);
        loadData(
            variantId || undefined,
            variantId ? undefined : projectId || undefined,
            compareVariantId || undefined,
            operation || undefined,
        );
    }, [loadData]);



    function appendAssessment(added: Assessment) {
        const updatedVulns = Vulnerabilities.append_assessment(vulns, added);
        setVulns(updatedVulns);

        // Update packages with the new vulnerability data
        setPkgs(Packages.enrich_with_vulns(pkgs, updatedVulns));

        // Update patch data if db is ready (status changes might affect patch relevance)
        if (patchDbReady) {
            loadPatchData(updatedVulns);
        }
    }

    function appendCVSS(vulnId: string, vector: string) {
        const cvss: CVSS | null = Vulnerabilities.calculate_cvss_from_vector(vector) ?? null;
        if (cvss !== null) {
            const updatedVulns = Vulnerabilities.append_cvss(vulns, vulnId, cvss);
            setVulns(updatedVulns);

            // Update packages with the new vulnerability data
            setPkgs(Packages.enrich_with_vulns(pkgs, updatedVulns));
            return cvss;
        }
        return null;
    }

    function patchVuln(vulnId: string, replace_vuln: Vulnerability) {
        const updatedVulns = vulns.map(vuln => {
            if (vuln.id === vulnId) {
                return replace_vuln;
            }
            return vuln;
        });
        setVulns(updatedVulns);

        // Update packages with the new vulnerability data
        setPkgs(Packages.enrich_with_vulns(pkgs, updatedVulns));

        // Update patch data if db is ready (status changes might affect patch relevance)
        if (patchDbReady) {
            loadPatchData(updatedVulns);
        }
    }

    function goToVulnsTabWithFilter(filterType: "Source" | "Severity" | "Status" | "Package", value: string) {
        setFilterLabel(filterType);
        setFilterValue(value);
        setTab('vulnerabilities');
    }

    function showVulnsForPackage(packageId: string) {
        goToVulnsTabWithFilter("Package", packageId);
    }

    const [tab, setTab] = useState("metrics");

    // This function ensures vulns get reset when switching outside filtering context
    function handleTabChange(newTab: string) {
        if (newTab === 'vulnerabilities' && tab !== 'vulnerabilities') {
            setFilterLabel(undefined);
            setFilterValue(undefined);
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

            {isLoadingData && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/40">
                    <div className="flex flex-col items-center gap-3 text-white">
                        <div className="w-10 h-10 border-4 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span className="text-sm font-semibold">Loading data...</span>
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
                />}
                {tab == 'packages' && <TablePackages packages={pkgs} onShowVulns={showVulnsForPackage} />}
                {tab === 'vulnerabilities' &&
                <TableVulnerabilities
                    appendAssessment={appendAssessment}
                    appendCVSS={appendCVSS}
                    patchVuln={patchVuln}
                    vulnerabilities={vulns}
                    filterLabel={filterLabel}
                    filterValue={filterValue}
                    variantId={currentVariantId}
                />}
                {tab == 'patch-finder' && <PatchFinder vulnerabilities={vulns} packages={pkgs} patchData={patchInfo} db_ready={patchDbReady} nvdProgress={nvdProgress} />}
                {tab == 'exports' && <Exports />}
            </div>
            <VersionDisplay />
        </div>
    )
}

export default Explorer
