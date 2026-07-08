type Variant = {
    id: string;
    name: string;
    project_id: string;
};

/** One of the three copy-assessment matching modes. */
type CopyMatchMode = "exact" | "ignore_minor_version" | "ignore_version";

/** The user-visible fields of the source assessment, for display in the review popup. */
type CopyAssessmentsAssessmentDetails = {
    simplified_status: string;
    status: string;
    justification?: string | null;
    status_notes?: string | null;
    impact_statement?: string | null;
    workaround?: string | null;
    responses?: string[];
};

/** A single row in an exact-mode flat preview. */
type CopyAssessmentsPreviewEntry = {
    source_assessment_id: string;
    source_finding_id: string;
    target_finding_id: string;
    vulnerability_id: string;
    source_package: string;
    target_package: string;
    assessment_details?: CopyAssessmentsAssessmentDetails;
};

/** One candidate target finding within a review-popup group. */
type CopyAssessmentsPreviewCandidate = {
    target_finding_id: string;
    target_package: string;
    already_has_custom: boolean;
    selected: boolean;
};

/** One source-assessment group in alternative-mode preview (for the review popup). */
type CopyAssessmentsPreviewGroup = {
    source_assessment_id: string;
    source_finding_id: string;
    vulnerability_id: string;
    source_package: string;
    assessment_details?: CopyAssessmentsAssessmentDetails;
    candidates: CopyAssessmentsPreviewCandidate[];
};

/** Preview response from the backend. */
type CopyAssessmentsPreview = {
    count: number;
    skipped: number;
    skipped_count?: number;
    message: string;
    mode: CopyMatchMode;
    /** Present for exact mode. */
    entries?: CopyAssessmentsPreviewEntry[];
    /** Present for alternative modes. */
    groups?: CopyAssessmentsPreviewGroup[];
};

type CopyAssessmentsPreviewUnsupported = {
    unsupported: true;
    status: number;
    message: string;
};

/** One element in the selections array sent to the copy endpoint. */
type CopyAssessmentsSelection = {
    source_assessment_id: string;
    target_finding_id: string;
};

export type {
    Variant,
    CopyMatchMode,
    CopyAssessmentsAssessmentDetails,
    CopyAssessmentsPreview,
    CopyAssessmentsPreviewEntry,
    CopyAssessmentsPreviewCandidate,
    CopyAssessmentsPreviewGroup,
    CopyAssessmentsPreviewUnsupported,
    CopyAssessmentsSelection,
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

    static async listByVuln(vulnId: string, signal?: AbortSignal): Promise<Variant[]> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnId)}/variants`,
            { mode: "cors", signal }
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
        matchMode: CopyMatchMode = "exact",
        versionPrecision = 1,
        selections?: CopyAssessmentsSelection[],
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
                    match_mode: matchMode,
                    version_precision: versionPrecision,
                    ...(selections !== undefined ? { selections } : {}),
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
        matchMode: CopyMatchMode = "exact",
        versionPrecision = 1,
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
                    match_mode: matchMode,
                    version_precision: versionPrecision,
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
