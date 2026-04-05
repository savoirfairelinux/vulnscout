type Project = {
    id: string;
    name: string;
};

export type { Project };

class Projects {
    static async list(): Promise<Project[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/projects", {
            mode: "cors",
        });
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data.filter(
            (p: any) => typeof p?.id === "string" && typeof p?.name === "string"
        ) as Project[];
    }

    static async rename(projectId: string, newName: string): Promise<Project> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/rename`,
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

    static async create(name: string): Promise<Project> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + "/api/projects",
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

    static async delete(projectId: string): Promise<void> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}`,
            { mode: "cors", method: "DELETE" }
        );
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Delete failed (${response.status})`);
        }
    }
}

export default Projects;
