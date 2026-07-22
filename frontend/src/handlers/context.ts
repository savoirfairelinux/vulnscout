type ProjectContext = {
    project_id: string;
    description: string | null;
};

type VariantContextData = {
    variant_description: string | null;
    codebase_path: string | null;
    environment: string | null;
    threat_model: string | null;
    risks: string | null;
    other_info: string | null;
};

type VariantContext = VariantContextData & {
    variant_id: string;
};

type MergedContext = ProjectContext & VariantContext;

/** One variant's full context, as used by the import/export file format. */
type ContextEntry = {
    project_name: string;
    variant_name: string;
    description: string | null;
    variant_description: string | null;
    codebase_path: string | null;
    environment: string | null;
    threat_model: string | null;
    risks: string | null;
    other_info: string | null;
};

type ImportResultItem = {
    project_name: string | null;
    variant_name: string | null;
    reason?: string;
};

type ImportResult = {
    imported: ImportResultItem[];
    ignored: ImportResultItem[];
    failed: ImportResultItem[];
};

/** Versioned export envelope produced by the backend. */
type ContextExport = {
    version: string;
    exported_at: string;
    entries: ContextEntry[];
};

export type {
    ProjectContext,
    VariantContext,
    VariantContextData,
    MergedContext,
    ContextEntry,
    ImportResultItem,
    ImportResult,
    ContextExport,
};

class Context {
    static async get(projectId: string, variantId: string): Promise<MergedContext> {
        const url = `${import.meta.env.VITE_API_URL}/api/context?project_id=${encodeURIComponent(projectId)}&variant_id=${encodeURIComponent(variantId)}`;
        const res = await fetch(url, { mode: 'cors' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to load context (${res.status})`);
        return data as MergedContext;
    }

    static async getProject(projectId: string): Promise<ProjectContext> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/projects/${encodeURIComponent(projectId)}/context`,
            { mode: 'cors' }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to load project context (${res.status})`);
        return data as ProjectContext;
    }

    static async saveProject(projectId: string, description: string | null): Promise<ProjectContext> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/projects/${encodeURIComponent(projectId)}/context`,
            {
                mode: 'cors',
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description }),
            }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to save project context (${res.status})`);
        return data as ProjectContext;
    }

    static async saveVariant(variantId: string, fields: VariantContextData): Promise<VariantContext> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context`,
            {
                mode: 'cors',
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fields),
            }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to save variant context (${res.status})`);
        return data as VariantContext;
    }

    static async exportAll(): Promise<ContextExport> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/context/export`,
            { mode: 'cors' }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to export context (${res.status})`);
        return data as ContextExport;
    }

    static async exportVariant(projectId: string, variantId: string): Promise<ContextExport> {
        const url = `${import.meta.env.VITE_API_URL}/api/context/export?project_id=${encodeURIComponent(projectId)}&variant_id=${encodeURIComponent(variantId)}`;
        const res = await fetch(url, { mode: 'cors' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to export context (${res.status})`);
        return data as ContextExport;
    }

    static async importContext(entries: unknown): Promise<ImportResult> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/context/import`,
            {
                mode: 'cors',
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(entries),
            }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to import context (${res.status})`);
        return data as ImportResult;
    }
}

export default Context;
