type AppConfig = {
    project: { id: string; name: string } | null;
    variant: { id: string; name: string } | null;
};

export type { AppConfig };

class Config {
    static async get(): Promise<AppConfig> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config", {
            mode: "cors",
        });
        const data = await response.json();
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
        };
    }
}

export default Config;
