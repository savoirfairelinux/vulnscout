type VulnCounts = { [key: string]: number }
type Severities = { [key: string]: {label: string, index: number} }
type Package = {
    id: string;
    name: string;
    version: string;
    cpe: string[];
    purl: string[];
    vulnerabilities: VulnCounts;
    maxSeverity: Severities;
    source: string[];
};

export type { Package, VulnCounts, Severities };
import type { Vulnerability } from "./vulnerabilities";
import { SEVERITY_ORDER } from "./vulnerabilities";

class Packages {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Package[]>} A promise that resolves to a list of packages
     */
    static async list(): Promise<Package[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/packages?format=list", {
            mode: "cors",
        });
        const data = await response.json();
        return data.map((pkg: Package) => ({
            ...pkg,
            id: pkg.id || `${pkg.name}@${pkg.version}`,
            vulnerabilities: {},
            maxSeverity: {},
            source: [],
        }));
    }

    static enrich_with_vulns(pkgs: Package[], vulns: Vulnerability[]): Package[] {
        return pkgs.map((pkg) => {
            const vulnerabilities = vulns.filter((vuln) => vuln.packages.includes(pkg.id));
            let severities: Severities = {};
            const counts: VulnCounts = vulnerabilities.reduce((acc, vuln) => {
                const status = vuln.simplified_status || "unknown";

                // compute max severity per status
                if (!severities[status]) {
                    severities[status] = {label: "NONE", index: 0};
                }
                const severity = {label: vuln.severity.severity, index: SEVERITY_ORDER.indexOf(vuln.severity.severity.toUpperCase())};
                if(severity.index > severities[status].index) severities[status] = severity;

                // count vulnerabilities per status
                acc[status] = acc[status] ? acc[status] + 1 : 1;
                return acc;
            }, {} as VulnCounts);
            return {
                ...pkg,
                vulnerabilities: counts,
                maxSeverity: severities,
                source: [...new Set(vulnerabilities.map((vuln) => vuln.found_by).flat())],
            };
        });
    }
}

export default Packages;
