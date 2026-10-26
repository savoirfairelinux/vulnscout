import type { PackageVersionMetadata } from '../helpers/packageVersions';
import { asVersionEvidence } from '../helpers/packageVersions';

type VulnCounts = { [key: string]: number }
type Severities = { [key: string]: {label: string, index: number} }
type ComponentType = 'normal' | 'workspace' | 'built';
export type SourceFile = {
    spdx_id: string;
    path: string;
    document_id: string;
    document_name: string;
    scan_id: string;
    variant_id: string;
    variant_name: string;
    properties: Record<string, unknown>;
    builds: Record<string, unknown>[];
};

export const hasCompilationEvidence = (file: SourceFile): boolean => file.builds.some(build =>
    build.compiled !== false && !/^https?:\/\/openembedded\.org\/bitbake\//.test(String(build.build_type ?? '')));

type Package = PackageVersionMetadata & {
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
    outdated?: boolean;
    findingIds?: string[];
    findingVulnerabilityIds?: string[];
    component_types?: ComponentType[];
    source_file_count?: number | null;
    compiled_source_file_count?: number;
    compiled_sources_complete?: boolean;
};

export type { Package, VulnCounts, Severities };
import type { Vulnerability } from "./vulnerabilities";
import { SEVERITY_ORDER, buildStatusSummary, getVulnerabilityStatusSummary } from "./vulnerabilities";
import { asStringArray } from "./assessments";

const asPackage = (data: any): Package | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.name !== "string") return [];
    if (typeof data?.version !== "string") return [];
    let pkg: Package = {
        id: `${data.name}@${data.version}`,
        name: data.name,
        version: data.version,
        release_version: typeof data.release_version === 'string' || data.release_version === null
            ? data.release_version : undefined,
        source_revision: typeof data.source_revision === 'string' ? data.source_revision : null,
        version_evidence: Array.isArray(data.version_evidence) ? data.version_evidence.flatMap(asVersionEvidence) : [],
        version_conflict: data.version_conflict === true,
        revision_conflict: data.revision_conflict === true,
        cpe: [],
        purl: [],
        vulnerabilities: {},
        maxSeverity: {},
        source: [],
        variants: [],
        sbom_documents: [],
        supplier: "",
        outdated: data?.outdated === true,
        findingIds: asStringArray(data?.finding_ids),
        findingVulnerabilityIds: asStringArray(data?.vulnerability_ids),
        component_types: asStringArray(data?.component_types).filter(
            (value): value is ComponentType => value === 'normal' || value === 'workspace' || value === 'built'
        ),
        source_file_count: Number.isInteger(data.source_file_count) && data.source_file_count >= 0
            ? data.source_file_count : null,
        compiled_source_file_count: Number.isInteger(data.compiled_source_file_count) && data.compiled_source_file_count >= 0
            ? data.compiled_source_file_count : 0,
        compiled_sources_complete: data.compiled_sources_complete === true,
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

function packageListUrl(variantId?: string, projectId?: string, compareVariantId?: string, operation?: string,
    variantIds?: string[], multiOperation?: string): URL {
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
    return url;
}

function isSourceFile(value: unknown): value is SourceFile {
    if (typeof value !== 'object' || value === null) return false;
    const file = value as Record<string, unknown>;
    return ['spdx_id', 'path', 'document_id', 'document_name', 'scan_id', 'variant_id', 'variant_name']
        .every(key => typeof file[key] === 'string')
        && typeof file.properties === 'object' && file.properties !== null && !Array.isArray(file.properties)
        && Array.isArray(file.builds) && file.builds.every(build =>
            typeof build === 'object' && build !== null && !Array.isArray(build));
}

class Packages {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Package[]>} A promise that resolves to a list of packages
     */
    static async list(variantId?: string, projectId?: string, compareVariantId?: string, operation?: string, variantIds?: string[], multiOperation?: string, includeOutdated = false): Promise<Package[]> {
        const url = packageListUrl(variantId, projectId, compareVariantId, operation, variantIds, multiOperation);
        if (includeOutdated) {
            url.searchParams.set('include_outdated', 'true');
            url.searchParams.set('outdated_only', 'true');
        }
        const response = await fetch(url.toString(), {
            mode: "cors",
        });
        const data = await response.json();
        return data.flatMap(asPackage);
    }

    static async sourceFiles(packageId: string, variantId?: string, projectId?: string, variantIds?: string[],
        compareVariantId?: string, operation?: string): Promise<{ files: SourceFile[]; complete: boolean }> {
        const url = packageListUrl(variantId, projectId, compareVariantId, operation, variantIds, operation);
        url.searchParams.set('package_id', packageId);
        url.searchParams.set('include_source_files', 'true');
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error('Unable to load source files');
        const data = await response.json();
        if (!Array.isArray(data) || data.length !== 1) throw new Error('Package is no longer available in this scope');
        if (data[0].source_files === null) throw new Error('Source files were not recorded; reimport the original SBOMs');
        const files: unknown = data[0].source_files;
        if (!Array.isArray(files) || !files.every(isSourceFile)) throw new Error('Invalid source file response');
        return { files, complete: data[0].compiled_sources_complete === true };
    }

    static enrich_with_vulns(pkgs: Package[], vulns: Vulnerability[]): Package[] {
        const needsPackageIndex = pkgs.some(pkg => !pkg.outdated);
        const vulns_per_pkg = needsPackageIndex
            ? vulns.reduce((acc, vuln) => {
                vuln.packages.forEach((pkg_id) => {
                    if (!acc[pkg_id]) {
                        acc[pkg_id] = [];
                    }
                    acc[pkg_id].push(vuln);
                });
                return acc;
            }, {} as {[key: string]: Vulnerability[]})
            : {};
        const vulnsById = new Map(vulns.map(vulnerability => [vulnerability.id, vulnerability]));

        return pkgs.map((pkg) => {
            const vulnerabilities = pkg.outdated
                ? (pkg.findingVulnerabilityIds ?? []).flatMap(id => {
                    const vulnerability = vulnsById.get(id);
                    return vulnerability ? [vulnerability] : [];
                })
                : (vulns_per_pkg[pkg.id] || []);
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
            const knownVulnerabilityIds = new Set(vulnerabilities.map(vulnerability => vulnerability.id));
            const missingFindingCount = (pkg.findingVulnerabilityIds ?? [])
                .filter(vulnerabilityId => !knownVulnerabilityIds.has(vulnerabilityId)).length;
            if (missingFindingCount > 0) counts.unknown = (counts.unknown ?? 0) + missingFindingCount;
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
