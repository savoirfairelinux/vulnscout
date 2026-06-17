type Variant = {
    id: string;
    name: string;
    project_id: string;
};

type CopyAssessmentsPreviewEntry = {
    source_assessment_id: string;
    source_finding_id: string;
    target_finding_id: string;
    vulnerability_id: string;
    source_package: string;
    target_package: string;
};

type CopyAssessmentsPreview = {
    count: number;
    skipped: number;
    message: string;
    entries: CopyAssessmentsPreviewEntry[];
};

type CopyAssessmentsPreviewUnsupported = {
    unsupported: true;
    status: number;
    message: string;
};

export type {
    Variant,
    CopyAssessmentsPreview,
    CopyAssessmentsPreviewEntry,
    CopyAssessmentsPreviewUnsupported,
};

class Variants {
    static async list(projectId: string): Promise<Variant[]> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/variants`,
            { mode: "cors" }
        );
        if (!response.ok) return [];
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data.filter(
            (v: any) =>
                typeof v?.id === "string" &&
                typeof v?.name === "string" &&
                typeof v?.project_id === "string"
        ) as Variant[];
    }

    static async listAll(): Promise<Variant[]> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants`,
            { mode: "cors" }
        );
        if (!response.ok) return [];
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data.filter(
            (v: any) =>
                typeof v?.id === "string" &&
                typeof v?.name === "string" &&
                typeof v?.project_id === "string"
        ) as Variant[];
    }

    static async listByVuln(vulnId: string): Promise<Variant[]> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnId)}/variants`,
            { mode: "cors" }
        );
        if (!response.ok) return [];
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data.filter(
            (v: any) =>
                typeof v?.id === "string" &&
                typeof v?.name === "string" &&
                typeof v?.project_id === "string"
        ) as Variant[];
    }

    static async rename(variantId: string, newName: string): Promise<Variant> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}/rename`,
            {
                mode: "cors",
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: newName }),
            }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Rename failed (${response.status})`);
        }
        return response.json();
    }

    static async create(projectId: string, name: string): Promise<Variant> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/variants`,
            {
                mode: "cors",
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name }),
            }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Create failed (${response.status})`);
        }
        return response.json();
    }

    static async delete(variantId: string): Promise<void> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/variants/${encodeURIComponent(variantId)}`,
            { mode: "cors", method: "DELETE" }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Delete failed (${response.status})`);
        }
    }

    static async uploadSBOM(
        projectId: string,
        variantId: string,
        files: File[],
    ): Promise<{ upload_id: string; scan_id: string; message: string }> {
        const formData = new FormData();
        for (const file of files) {
            formData.append("files", file);
        }
        formData.append("project_id", projectId);
        formData.append("variant_id", variantId);

        const response = await fetch(
            import.meta.env.VITE_API_URL + "/api/sbom/upload",
            { mode: "cors", method: "POST", body: formData }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Upload failed (${response.status})`);
        }
        return response.json();
    }

    static async getUploadStatus(uploadId: string): Promise<{ status: string; message: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/sbom/upload/${encodeURIComponent(uploadId)}/status`,
            { mode: "cors" }
        );
        if (!response.ok) {
            return { status: "error", message: "Failed to check upload status." };
        }
        return response.json();
    }

    static async copyAssessments(
        sourceVariantId: string,
        targetVariantId: string,
        ignorePackageVersion = false,
    ): Promise<{ copied: number; skipped: number; message: string }> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + "/api/variants/copy-assessments",
            {
                mode: "cors",
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    source_variant_id: sourceVariantId,
                    target_variant_id: targetVariantId,
                    ignore_package_version: ignorePackageVersion,
                }),
            }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Copy failed (${response.status})`);
        }
        return response.json();
    }

    static async previewCopyAssessments(
        sourceVariantId: string,
        targetVariantId: string,
        ignorePackageVersion = false,
    ): Promise<CopyAssessmentsPreview | CopyAssessmentsPreviewUnsupported> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + "/api/variants/copy-assessments/preview",
            {
                mode: "cors",
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    source_variant_id: sourceVariantId,
                    target_variant_id: targetVariantId,
                    ignore_package_version: ignorePackageVersion,
                }),
            }
        );
        if (!response.ok) {
            if (response.status === 404 || response.status === 405) {
                return {
                    unsupported: true,
                    status: response.status,
                    message: "Preview is unavailable on the current backend. Restart or redeploy the server to load the new preview endpoint.",
                };
            }
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Preview failed (${response.status})`);
        }
        return response.json();
    }
}

export default Variants;
