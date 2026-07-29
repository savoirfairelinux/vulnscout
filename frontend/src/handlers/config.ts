type FrontendScope = {
    project_id: string;
    mode: 'select' | 'compare';
    variant_ids: string[];
    compare_base_id: string;
    compare_operation: 'difference' | 'intersection';
    compare_variant_id: string;
};

type AppConfig = {
    project: { id: string; name: string } | null;
    variant: { id: string; name: string } | null;
    product_name: string;
    author_name: string;
    client_name: string;
    contact_email: string;
    grype_memlimit: string;
};

export type { AppConfig, FrontendScope };

class Config {
    private static readonly _frontendScopeStorageKey = 'vulnscout.frontendScope';

    private static _normalizeFrontendScope(scope: unknown): FrontendScope | null {
        return scope
            && typeof scope === 'object'
            && typeof (scope as FrontendScope).project_id === 'string'
            && ((scope as FrontendScope).mode === 'select' || (scope as FrontendScope).mode === 'compare')
            && Array.isArray((scope as FrontendScope).variant_ids)
            && (scope as FrontendScope).variant_ids.every(id => typeof id === 'string')
            && typeof (scope as FrontendScope).compare_base_id === 'string'
            && ((scope as FrontendScope).compare_operation === 'difference' || (scope as FrontendScope).compare_operation === 'intersection')
            && typeof (scope as FrontendScope).compare_variant_id === 'string'
                ? scope as FrontendScope
                : null;
    }

    private static _normalizeConfig(data: any): AppConfig {
        return {
            project:
                data?.project &&
                typeof data.project.id === "string" &&
                typeof data.project.name === "string"
                    ? { id: data.project.id, name: data.project.name }
                    : null,
            variant:
                data?.variant &&
                typeof data.variant.id === "string" &&
                typeof data.variant.name === "string"
                    ? { id: data.variant.id, name: data.variant.name }
                    : null,
            product_name: typeof data?.product_name === "string" ? data.product_name : "",
            author_name:
                typeof data?.author_name === "string" && data.author_name.trim().length > 0
                    ? data.author_name
                    : "vulnscout",
            client_name: typeof data?.client_name === "string" ? data.client_name : "",
            contact_email: typeof data?.contact_email === "string" ? data.contact_email : "",
            grype_memlimit: typeof data?.grype_memlimit === "string" ? data.grype_memlimit : "",
        };
    }

    static getFrontendScope(): FrontendScope | null {
        try {
            const value = window.localStorage.getItem(Config._frontendScopeStorageKey);
            return value ? Config._normalizeFrontendScope(JSON.parse(value)) : null;
        } catch {
            return null;
        }
    }

    static setFrontendScope(scope: FrontendScope): void {
        window.localStorage.setItem(Config._frontendScopeStorageKey, JSON.stringify(scope));
    }

    static clearFrontendScope(): void {
        window.localStorage.removeItem(Config._frontendScopeStorageKey);
    }

    static isFrontendScopeAvailable(scope: FrontendScope, projectIds: string[], variantIds: string[]): boolean {
        if (!projectIds.includes(scope.project_id)) return false;
        const referencedVariantIds = scope.mode === 'compare'
            ? [scope.compare_base_id, scope.compare_variant_id]
            : scope.variant_ids;
        return referencedVariantIds.every(variantId => variantIds.includes(variantId));
    }

    static async get(): Promise<AppConfig> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config", {
            mode: "cors",
        });
        const data = await response.json();
        return Config._normalizeConfig(data);
    }

    static async patch(data: {
        product_name?: string;
        author_name?: string;
        client_name?: string;
        contact_email?: string;
        grype_memlimit?: string;
    }): Promise<AppConfig> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config", {
            method: "PATCH",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });

        if (!response.ok) {
            let errorMessage = `Failed to update config (${response.status})`;
            try {
                const json = await response.json();
                if (typeof json?.error === "string" && json.error.trim().length > 0) {
                    errorMessage = json.error;
                }
            } catch {
                // Keep default error message if response body is not JSON.
            }
            throw new Error(errorMessage);
        }

        const body = await response.json();
        return Config._normalizeConfig(body);
    }
}

export default Config;
