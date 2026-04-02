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
}

export default Projects;
