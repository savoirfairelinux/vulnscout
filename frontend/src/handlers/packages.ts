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

const asPackage = (data: any): Package | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.name !== "string") return [];
    if (typeof data?.version !== "string") return [];
    let pkg: Package = {
        id: `${data.name}@${data.version}`,
        name: data.name,
        version: data.version,
        cpe: [],
        purl: [],
        vulnerabilities: {},
        maxSeverity: {},
        source: [],
    };
    if (typeof data?.id === "string" && data?.id != "") pkg.id = data.id;
    if (Array.isArray(data?.cpe)) {
        for (const cpe of data.cpe) if (typeof cpe === "string") pkg.cpe.push(cpe);
    }
    if (Array.isArray(data?.purl)) {
        for (const purl of data.purl) if (typeof purl === "string") pkg.purl.push(purl);
    }
    return pkg
};

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
        return data.flatMap(asPackage);
    }

    static enrich_with_vulns(pkgs: Package[], vulns: Vulnerability[]): Package[] {
        const vulns_per_pkg = vulns.reduce((acc, vuln) => {
            vuln.packages.forEach((pkg_id) => {
                if (!acc[pkg_id]) {
                    acc[pkg_id] = [];
                }
                acc[pkg_id].push(vuln);
            });
            return acc;
        }, {} as {[key: string]: Vulnerability[]});

        return pkgs.map((pkg) => {
            const vulnerabilities = vulns_per_pkg[pkg.id] || [];
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
