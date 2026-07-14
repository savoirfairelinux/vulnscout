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
    variants: string[];
    sbom_documents: string[];
    supplier: string;
};

export type { Package, VulnCounts, Severities };
import type { Vulnerability } from "./vulnerabilities";
import { SEVERITY_ORDER, buildStatusSummary, getVulnerabilityStatusSummary } from "./vulnerabilities";

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
        variants: [],
        sbom_documents: [],
        supplier: "",
    };
    if (typeof data?.id === "string" && data?.id != "") pkg.id = data.id;
    if (Array.isArray(data?.cpe)) {
        for (const cpe of data.cpe) if (typeof cpe === "string") pkg.cpe.push(cpe);
    }
    if (Array.isArray(data?.purl)) {
        for (const purl of data.purl) if (typeof purl === "string") pkg.purl.push(purl);
    }
    if (Array.isArray(data?.variants)) {
        for (const v of data.variants) if (typeof v === "string") pkg.variants.push(v);
    }
    if (typeof data?.supplier === "string") pkg.supplier = data.supplier;
    if (Array.isArray(data?.sources)) {
        for (const s of data.sources) if (typeof s === "string") pkg.source.push(s);
    }
    if (Array.isArray(data?.sbom_documents)) {
        for (const d of data.sbom_documents) if (typeof d === "string") pkg.sbom_documents.push(d);
    }
    return pkg
};

class Packages {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Package[]>} A promise that resolves to a list of packages
     */
    static async list(variantId?: string, projectId?: string, compareVariantId?: string, operation?: string, variantIds?: string[], multiOperation?: string): Promise<Package[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/packages", window.location.href);
        url.searchParams.set('format', 'list');
        if (variantId && compareVariantId) {
            url.searchParams.set('variant_id', variantId);
            url.searchParams.set('compare_variant_id', compareVariantId);
            if (operation) url.searchParams.set('operation', operation);
        } else if (variantIds && variantIds.length >= 2) {
            url.searchParams.set('variant_ids', variantIds.join(','));
            if (multiOperation) url.searchParams.set('operation', multiOperation);
            if (projectId) url.searchParams.set('project_id', projectId);
        } else if (variantId) {
            url.searchParams.set('variant_id', variantId);
        } else if (projectId) {
            url.searchParams.set('project_id', projectId);
        }
        const response = await fetch(url.toString(), {
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
                const severity = {label: vuln.severity.severity, index: SEVERITY_ORDER.indexOf(vuln.severity.severity.toUpperCase())};

                // Build a summary scoped to this package + each variant:
                // keep only assessments that explicitly cover this package (or
                // carry no package list at all), then let buildStatusSummary
                // group by variant_id so each variant contributes exactly one
                // count — the last assessment for that (variant, package) pair.
                const pkgAssessments = vuln.assessments.filter(
                    (a) => a.packages.length === 0 || a.packages.includes(pkg.id)
                );
                const summary = pkgAssessments.length > 0
                    ? buildStatusSummary(pkgAssessments)
                    : getVulnerabilityStatusSummary(vuln);

                // Count this CVE as 1 toward its dominant status so the badge
                // always means "N distinct CVEs in this status", not
                // "N (CVE × variant) pairs". Variant-aware logic still drives
                // which status bucket each CVE lands in.
                const status = summary.dominant_status;
                if (!severities[status]) {
                    severities[status] = {label: "NONE", index: 0};
                }
                if (severity.index > severities[status].index) severities[status] = severity;
                acc[status] = (acc[status] || 0) + 1;
                return acc;
            }, {} as VulnCounts);
            return {
                ...pkg,
                vulnerabilities: counts,
                maxSeverity: severities,
                source: [...new Set([...pkg.source, ...vulnerabilities.map((vuln) => vuln.found_by).flat()])],
                // Keep variants package-scoped (from /api/packages enrichment).
                // vuln.variants is vulnerability-scoped and can include
                // variants unrelated to this exact package record.
                variants: pkg.variants,
                sbom_documents: pkg.sbom_documents,
            };
        });
    }
}

export default Packages;
