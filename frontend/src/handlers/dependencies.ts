export type DependencyPackage = { id: string; name: string; version: string };
export type DependencyEdge = { package_id: string; dependency_id: string };
export type DependencyDocument = {
    id: string;
    source_name: string;
    packages: DependencyPackage[];
    edges: DependencyEdge[];
};

export async function listDependencies(variantId?: string, projectId?: string, variantIds?: string[],
    compareVariantId?: string, operation?: string): Promise<DependencyDocument[]> {
    const url = new URL(import.meta.env.VITE_API_URL + '/api/package-dependencies', window.location.href);
    if (variantId && compareVariantId) {
        url.searchParams.set('variant_id', variantId);
        url.searchParams.set('compare_variant_id', compareVariantId);
    } else if (variantIds?.length) url.searchParams.set('variant_ids', variantIds.join(','));
    else if (variantId) url.searchParams.set('variant_id', variantId);
    else if (projectId) url.searchParams.set('project_id', projectId);
    else return [];
    if (operation) url.searchParams.set('operation', operation);
    const response = await fetch(url.toString(), { mode: 'cors' });
    if (!response.ok) throw new Error('Unable to load dependencies');
    const data = await response.json();
    return data.documents;
}