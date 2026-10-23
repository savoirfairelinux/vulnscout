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
    files?: ContextFile[];
    editor: VariantEditorData;
};

type EditorMode = 'stride' | 'free';
type CodebaseSource = 'paths' | 'references';
type Rating = 'low' | 'medium' | 'high' | null;

type StrideComponent = { id: string; name: string; description: string; trust_zone: string };

type StrideInteraction = {
    id: string;
    name: string;
    source_id: string;
    destination_id: string;
    interface: string;
    data: string;
    trust_boundary: string;
};

type StrideThreat = { id: string; category: string; description: string; target_ids: string[] };

type StrideRisk = {
    threat_id: string;
    likelihood: Rating;
    impact: Rating;
    mitigation: string;
    residual: string;
};

type StrideModel = {
    components: StrideComponent[];
    interactions: StrideInteraction[];
    threats: StrideThreat[];
    notes: string;
    risks: StrideRisk[];
    risk_notes: string;
};

type SystemFields = {
    scope: string | null;
    actors: string | null;
    entry_points: string | null;
    trust_boundaries: string | null;
};

/** Editor-shaped view of a variant's context, as returned by the backend. */
type VariantEditorData = {
    editor_mode: EditorMode;
    codebase_source: CodebaseSource;
    codebase_path: string | null;
    free: { threat_model: string | null; risks: string | null };
    system: SystemFields;
    stride: StrideModel;
    files: ContextFile[];
    updated_at: string | null;
};

/** Editable form state for a variant; null text is held as ''. */
type VariantDraft = {
    variant_description: string;
    environment: string;
    other_info: string;
    editor_mode: EditorMode;
    codebase_source: CodebaseSource;
    codebase_path: string;
    free: { threat_model: string; risks: string };
    system: Record<keyof SystemFields, string>;
    stride: StrideModel;
};

type ContextFile = {
    id: string;
    original_name: string;
    description: string | null;
};

type MergedContext = ProjectContext & VariantContext;

/** One variant's context, as used by the import/export file format. */
type VariantEntry = {
    variant_name: string;
    variant_description: string | null;
    codebase_path: string | null;
    environment: string | null;
    threat_model: string | null;
    risks: string | null;
    other_info: string | null;
    editor_mode?: EditorMode;
    codebase_source?: CodebaseSource;
    system?: SystemFields;
    stride?: StrideModel;
};

/** One project with its variants nested underneath. */
type ProjectEntry = {
    project_name: string;
    project_description: string | null;
    variants: VariantEntry[];
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
    projects: ProjectEntry[];
};

export type {
    ProjectContext,
    VariantContext,
    VariantContextData,
    MergedContext,
    VariantEntry,
    ProjectEntry,
    ImportResultItem,
    ImportResult,
    ContextExport,
    ContextFile,
    EditorMode,
    CodebaseSource,
    Rating,
    StrideComponent,
    StrideInteraction,
    StrideThreat,
    StrideRisk,
    StrideModel,
    SystemFields,
    VariantEditorData,
    VariantDraft,
};

/** Rejected variant save; `fields` maps field paths to validation messages. */
class ContextSaveError extends Error {
    fields: Record<string, string>;
    status: number;

    constructor(message: string, status: number, fields: Record<string, string> = {}) {
        super(message);
        this.name = 'ContextSaveError';
        this.status = status;
        this.fields = fields;
    }
}

export { ContextSaveError };

const blankToNull = (value: string): string | null => (value.trim() === '' ? null : value);

class Context {
    static async uploadFile(variantId: string, file: File, description: string): Promise<ContextFile> {
        const body = new FormData();
        body.append('file', file);
        if (description.trim()) body.append('description', description.trim());
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context/files`,
            { mode: 'cors', method: 'POST', body }
        );
        if (res.status === 413) {
            throw new Error(
                "Upload rejected as too large (HTTP 413). A server or proxy request-size limit may apply."
            );
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to upload reference (${res.status})`);
        return data as ContextFile;
    }

    static async deleteFile(variantId: string, fileId: string): Promise<void> {
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context/files/${encodeURIComponent(fileId)}`,
            { mode: 'cors', method: 'DELETE' }
        );
        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || `Failed to delete reference (${res.status})`);
        }
    }

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

    static async saveVariantEditor(variantId: string, draft: VariantDraft): Promise<VariantContext> {
        const payload = {
            variant_description: blankToNull(draft.variant_description),
            environment: blankToNull(draft.environment),
            other_info: blankToNull(draft.other_info),
            editor_mode: draft.editor_mode,
            codebase_source: draft.codebase_source,
            codebase_path: blankToNull(draft.codebase_path),
            free: {
                threat_model: blankToNull(draft.free.threat_model),
                risks: blankToNull(draft.free.risks),
            },
            system: {
                scope: blankToNull(draft.system.scope),
                actors: blankToNull(draft.system.actors),
                entry_points: blankToNull(draft.system.entry_points),
                trust_boundaries: blankToNull(draft.system.trust_boundaries),
            },
            stride: draft.stride,
        };
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/variants/${encodeURIComponent(variantId)}/context`,
            {
                mode: 'cors',
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            }
        );
        const data = await res.json();
        if (!res.ok) {
            throw new ContextSaveError(
                data.error || `Failed to save variant context (${res.status})`,
                res.status,
                data.fields ?? {},
            );
        }
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

    static async exportSelected(variantIds: string[]): Promise<ContextExport> {
        const query = encodeURIComponent(variantIds.join(','));
        const res = await fetch(
            `${import.meta.env.VITE_API_URL}/api/context/export?variant_ids=${query}`,
            { mode: 'cors' }
        );
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
