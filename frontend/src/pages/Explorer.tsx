import { useState, useEffect, useCallback } from "react";
import NavigationBar from "../components/NavigationBar";
import MessageBanner from "../components/MessageBanner";
import type { Package } from "../handlers/packages";
import type { CVSS, Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import type { PackageVulnerabilities } from "../handlers/patch_finder";
import Packages from "../handlers/packages";
import Vulnerabilities from "../handlers/vulnerabilities";
import PatchFinderLogic from "../handlers/patch_finder";
import TablePackages from "./TablePackages";
import TableVulnerabilities from "./TableVulnerabilities";
import PatchFinder from "./PatchFinder";
import Metrics from "./Metrics";
import Exports from "./Exports";
import Assessments from "../handlers/assessments";

type Props = {
  darkMode: boolean;
  setDarkMode: (mode: boolean) => void;
}

function Explorer({ darkMode, setDarkMode }: Readonly<Props>) {
    const [pkgs, setPkgs] = useState<Package[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [patchInfo, setPatchInfo] = useState<PackageVulnerabilities>({});
    const [patchDbReady, setPatchDbReady] = useState<boolean>(false);
    const [filterLabel, setFilterLabel] = useState<"Source" | "Severity" | "Status" | undefined>(undefined);
    const [filterValue, setFilterValue] = useState<string | undefined>(undefined);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);

    const triggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const loadPatchData = useCallback((vulns_list: Vulnerability[]) => {
        const active_status = ['Exploitable', 'Community Analysis Pending'];
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
        PatchFinderLogic
        .status()
        .then((patchData) => {
            if (patchData.db_ready) {
                setPatchDbReady(true);
                loadPatchData(vulns_list);
            } else {
                setTimeout(() => checkPatchReady(vulns_list), 15000)
                setPatchDbReady(false);
            }
        })
        .catch((err) => {
            console.error(err);
            triggerBanner("Failed to load patch data", "error");
        })
    }, [loadPatchData]);

    useEffect(() => {
        Promise.allSettled([
            Packages.list(),
            Vulnerabilities.list(),
            Assessments.list()
        ]).then(([pkgs, vulns, assess]) => {
            if (pkgs.status === 'rejected' || vulns.status === 'rejected' || assess.status === 'rejected') {
                console.error(pkgs, vulns);
                triggerBanner("Failed to load data", "error");
                return;
            }
            const enriched_vulns = Vulnerabilities.enrich_with_assessments(vulns.value, assess.value);
            setVulns(enriched_vulns);
            setPkgs(
              Packages.enrich_with_vulns(pkgs.value, enriched_vulns)
            );
            setTimeout(() => checkPatchReady(enriched_vulns), 100)
        })
    }, [checkPatchReady]);



    function appendAssessment(added: Assessment) {
        setVulns(Vulnerabilities.append_assessment(vulns, added));
    }

    function appendCVSS(vulnId: string, vector: string) {
        const cvss: CVSS | null = Vulnerabilities.calculate_cvss_from_vector(vector) ?? null;
        if (cvss !== null) {
            setVulns(Vulnerabilities.append_cvss(vulns, vulnId, cvss));
            return cvss;
        }
        return null;
    }

    function patchVuln(vulnId: string, replace_vuln: Vulnerability) {
        setVulns(vulns.map(vuln => {
            if (vuln.id === vulnId) {
                return replace_vuln;
            }
            return vuln;
        }));
    }

    function goToVulnsTabWithFilter(filterType: "Source" | "Severity" | "Status", value: string) {
        setFilterLabel(filterType);
        setFilterValue(value);
        setTab('vulnerabilities');
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
            <NavigationBar tab={tab} changeTab={handleTabChange} darkMode={darkMode} setDarkMode={setDarkMode} />

            <div className="px-8 pt-4">
                <MessageBanner
                    type={bannerType}
                    message={bannerMessage}
                    isVisible={bannerVisible}
                    onClose={closeBanner}
                />
            </div>

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
                {tab == 'packages' && <TablePackages packages={pkgs} />}
                {tab === 'vulnerabilities' &&
                <TableVulnerabilities
                    appendAssessment={appendAssessment}
                    appendCVSS={appendCVSS}
                    patchVuln={patchVuln}
                    vulnerabilities={vulns}
                    filterLabel={filterLabel}
                    filterValue={filterValue}
                />}
                {tab == 'patch-finder' && <PatchFinder vulnerabilities={vulns} packages={pkgs} patchData={patchInfo} db_ready={patchDbReady} />}
                {tab == 'exports' && <Exports />}
            </div>
        </div>
    )
}

export default Explorer
