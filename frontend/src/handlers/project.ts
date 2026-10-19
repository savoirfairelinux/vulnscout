type Project = {
    id: string;
    name: string;
};

export type { Project };

export type NativeScanPreferences = {
    exclude_native: boolean;
    native_package_exceptions: string[];
};

export type ScanConfiguration = NativeScanPreferences & {
    native_packages: string[];
};

class Projects {
    static async saveScanConfigurations(configurations: Record<string, ScanConfiguration>): Promise<void> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/projects/scan-configurations", {
            mode: "cors",
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(Object.fromEntries(Object.entries(configurations).map(([id, configuration]) => [id, {
                exclude_native: configuration.exclude_native,
                native_package_exceptions: configuration.native_package_exceptions,
            }]))),
        });
        if (!response.ok) throw new Error(`Failed to save project scan configurations (${response.status}). Please retry.`);
    }

    static async scanConfiguration(projectId: string, configuration?: ScanConfiguration, signal?: AbortSignal): Promise<ScanConfiguration> {
        const response = await fetch(
            import.meta.env.VITE_API_URL + `/api/projects/${encodeURIComponent(projectId)}/scan-configuration`,
            {
                mode: "cors", signal,
                method: configuration ? "PUT" : "GET",
                ...(configuration ? {
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        exclude_native: configuration.exclude_native,
                        native_package_exceptions: configuration.native_package_exceptions,
                    }),
                } : {}),
            },
        );
        if (!response.ok) throw new Error(`Failed to ${configuration ? "save" : "load"} project scan configuration (${response.status})`);
        const data = await response.json();
        if (typeof data?.exclude_native !== "boolean"
            || !Array.isArray(data.native_package_exceptions)
            || !data.native_package_exceptions.every((name: unknown) => typeof name === "string")
            || !Array.isArray(data.native_packages)
            || !data.native_packages.every((name: unknown) => typeof name === "string")) {
            throw new Error("Invalid project scan configuration");
        }
        return data;
    }

    static async list(): Promise<Project[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/projects", {
            mode: "cors",
        });
        if (!response.ok) throw new Error(`Failed to list projects (${response.status})`);
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
