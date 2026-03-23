type Variant = {
    id: string;
    name: string;
    project_id: string;
};

export type { Variant };

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
}

export default Variants;
