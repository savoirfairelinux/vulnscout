import { useState, useEffect } from "react";
import NavigationBar from "../components/NavigationBar";
import type { Package } from "../handlers/packages";
import type { Vulnerability } from "../handlers/vulnerabilities";
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

    useEffect(() => {
        Promise.allSettled([
            Packages.list(),
            Vulnerabilities.list(),
            Assessments.list()
        ]).then(([pkgs, vulns, assess]) => {
            if (pkgs.status === 'rejected' || vulns.status === 'rejected' || assess.status === 'rejected') {
                console.error(pkgs, vulns);
                alert("Failed to load data");
                return;
            }
            const enriched_vulns = Vulnerabilities.enrich_with_assessments(vulns.value, assess.value);
            setVulns(enriched_vulns);
            setPkgs(
              Packages.enrich_with_vulns(pkgs.value, enriched_vulns)
            );
            setTimeout(() => loadPatchData(enriched_vulns), 100)
        })
    }, []);

    function loadPatchData (vulns_list: Vulnerability[]) {
        const active_status = ['active', 'pending analysis']
        PatchFinderLogic
        .scan(vulns_list.filter(el => active_status.includes(el.simplified_status)).map(el => el.id))
        .then((patchData) => {
            setPatchInfo(patchData);
        })
        .catch((err) => {
            console.error(err);
            alert("Failed to load patch data");
        })
    }

    function appendAssessment(added: Assessment) {
        setVulns(Vulnerabilities.append_assessment(vulns, added));
    }

    function patchVuln(vulnId: string, replace_vuln: Vulnerability) {
        setVulns(vulns.map(vuln => {
            if (vuln.id === vulnId) {
                return replace_vuln;
            }
            return vuln;
        }));
    }

    const [tab, setTab] = useState("metrics");

    return (
        <div className="w-screen min-h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee]">
            <NavigationBar tab={tab} changeTab={setTab} darkMode={darkMode} setDarkMode={setDarkMode} />

            <div className="p-8">
                {tab == 'metrics' && <Metrics packages={pkgs} vulnerabilities={vulns} />}
                {tab == 'packages' && <TablePackages packages={pkgs} />}
                {tab == 'vulnerabilities' && <TableVulnerabilities appendAssessment={appendAssessment} patchVuln={patchVuln} vulnerabilities={vulns} />}
                {tab == 'patch-finder' && <PatchFinder vulnerabilities={vulns} packages={pkgs} patchData={patchInfo} />}
                {tab == 'exports' && <Exports />}
            </div>
        </div>
    )
}

export default Explorer
