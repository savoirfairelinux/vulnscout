type Package = {
    id: string;
    name: string;
    version: string;
    cpe: string[];
    purl: string[];
    vulnerabilities: number;
    maxSeverity: string;
    source: string[];
};

export type { Package };
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
            vulnerabilities: 0,
            maxSeverity: "none",
            source: [],
        }));
    }

    static enrich_with_vulns(pkgs: Package[], vulns: Vulnerability[]): Package[] {
        return pkgs.map((pkg) => {
            const vulnerabilities = vulns.filter((vuln) => vuln.packages.includes(pkg.id));
            return {
                ...pkg,
                vulnerabilities: vulnerabilities.length,
                maxSeverity: vulnerabilities.reduce((max, vuln) => {
                    const severity = SEVERITY_ORDER.indexOf(vuln.severity.severity.toUpperCase());
                    return severity > SEVERITY_ORDER.indexOf(max.toUpperCase()) ? vuln.severity.severity : max;
                }, 'NONE'),
                source: [...new Set(vulnerabilities.map((vuln) => vuln.found_by))],
            };
        });
    }
}

export default Packages;
