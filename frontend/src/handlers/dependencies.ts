export type DependencyPackage = { id: string; name: string; version: string };
export type DependencyEdge = { package_id: string; dependency_id: string };
export type DependencyDocument = {
    id: string;
    source_name: string;
    variant_id: string;
    variant_name: string;
    dependencies_recorded: boolean;
    packages: DependencyPackage[];
    edges: DependencyEdge[];
};
export type DependencyCounts = {
    counts: Record<string, { in: number; out: number }>;
    // Packages known only from SBOMs never parsed with dependency support.
    unrecorded: string[];
};

function dependencyUrl(variantId?: string, projectId?: string, variantIds?: string[],
    compareVariantId?: string, operation?: string): URL | undefined {
    const url = new URL(import.meta.env.VITE_API_URL + '/api/package-dependencies', window.location.href);
    if (variantId && compareVariantId) {
        url.searchParams.set('variant_id', variantId);
        url.searchParams.set('compare_variant_id', compareVariantId);
    } else if (variantIds?.length) url.searchParams.set('variant_ids', variantIds.join(','));
    else if (variantId) url.searchParams.set('variant_id', variantId);
    else if (projectId) url.searchParams.set('project_id', projectId);
    else return undefined;
    if (operation) url.searchParams.set('operation', operation);
    return url;
}

export async function listDependencies(variantId?: string, projectId?: string, variantIds?: string[],
    compareVariantId?: string, operation?: string): Promise<DependencyDocument[]> {
    const url = dependencyUrl(variantId, projectId, variantIds, compareVariantId, operation);
    if (!url) return [];
    const response = await fetch(url.toString(), { mode: 'cors' });
    if (!response.ok) throw new Error('Unable to load dependencies');
    const data = await response.json();
    return data.documents;
}

export async function listDependencyCounts(variantId?: string, projectId?: string, variantIds?: string[],
    compareVariantId?: string, operation?: string): Promise<DependencyCounts> {
    const url = dependencyUrl(variantId, projectId, variantIds, compareVariantId, operation);
    if (!url) return { counts: {}, unrecorded: [] };
    url.searchParams.set('counts', '1');
    const response = await fetch(url.toString(), { mode: 'cors' });
    if (!response.ok) throw new Error('Unable to load dependency counts');
    const data = await response.json();
    return { counts: data.counts, unrecorded: data.unrecorded };
}
