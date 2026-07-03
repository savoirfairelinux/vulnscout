type ProjectContext = {
    project_id: string;
    description: string | null;
};

type VariantContextData = {
    variant_description: string | null;
    environment: string | null;
    threat_model: string | null;
    risks: string | null;
    other_info: string | null;
};

type VariantContext = VariantContextData & {
    variant_id: string;
    files: ContextFile[];
};

type MergedContext = ProjectContext & VariantContext;

type ContextFile = {
    id: string;
    original_name: string;
    description: string | null;
};

export type { ProjectContext, VariantContext, VariantContextData, MergedContext, ContextFile };

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

    static async uploadFile(variantId: string, file: File, description?: string | null): Promise<ContextFile> {
        const formData = new FormData();
        formData.append('file', file);
        if (description != null && description !== '') {
            formData.append('description', description);
        }
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context/files`,
            { mode: 'cors', method: 'POST', body: formData }
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to upload file (${res.status})`);
        return data as ContextFile;
    }

    static async deleteFile(variantId: string, fileId: string): Promise<void> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context/files/${encodeURIComponent(fileId)}`,
            { mode: 'cors', method: 'DELETE' }
        );
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            throw new Error(data.error || `Failed to delete file (${res.status})`);
        }
    }
}

export default Context;
