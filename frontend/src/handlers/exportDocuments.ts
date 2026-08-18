export type ExportDocument = {
    id: string;
    category: string[];
    extension: string;
};

export function asExportDocument(data: unknown): ExportDocument | [] {
    if (typeof data !== "object" || data === null || !("id" in data) || typeof data.id !== "string") {
        return [];
    }
    const category = "category" in data && Array.isArray(data.category)
        ? data.category.filter((entry): entry is string => typeof entry === "string")
        : [];
    const extension = "extension" in data && typeof data.extension === "string"
        ? data.extension
        : data.id.split(".").at(-1) ?? "unk";
    return { id: data.id, category, extension };
}

export async function listExportDocuments(): Promise<ExportDocument[]> {
    const response = await fetch(import.meta.env.VITE_API_URL + "/api/documents", { mode: "cors" });
    if (!response.ok) throw new Error(`Failed to load custom reports and assets (${response.status})`);
    const data: unknown = await response.json();
    return Array.isArray(data) ? data.flatMap(asExportDocument) : [];
}
