type AppConfig = {
    project: { id: string; name: string } | null;
    variant: { id: string; name: string } | null;
    author: string;
    product_name: string;
    author_name: string;
    client_name: string;
    contact_email: string;
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
            author: typeof data?.author === "string" && data.author.trim().length > 0
                ? data.author
                : "vulnscout",
            product_name: typeof data?.product_name === "string" ? data.product_name : "",
            author_name: typeof data?.author_name === "string"
                ? data.author_name
                : (typeof data?.author === "string" ? data.author : ""),
            client_name: typeof data?.client_name === "string" ? data.client_name : "",
            contact_email: typeof data?.contact_email === "string" ? data.contact_email : "",
        };
    }

    static async patch(data: {
        product_name?: string;
        author_name?: string;
        client_name?: string;
        contact_email?: string;
    }): Promise<AppConfig> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config", {
            method: "PATCH",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });

        if (!response.ok) {
            let errorMessage = `Failed to update config (${response.status})`;
            try {
                const json = await response.json();
                if (typeof json?.error === "string" && json.error.trim().length > 0) {
                    errorMessage = json.error;
                }
            } catch {
                // Keep default error message if response body is not JSON.
            }
            throw new Error(errorMessage);
        }

        const body = await response.json();
        return {
            project:
                body?.project &&
                typeof body.project.id === "string" &&
                typeof body.project.name === "string"
                    ? { id: body.project.id, name: body.project.name }
                    : null,
            variant:
                body?.variant &&
                typeof body.variant.id === "string" &&
                typeof body.variant.name === "string"
                    ? { id: body.variant.id, name: body.variant.name }
                    : null,
            author: typeof body?.author === "string" && body.author.trim().length > 0
                ? body.author
                : "vulnscout",
            product_name: typeof body?.product_name === "string" ? body.product_name : "",
            author_name: typeof body?.author_name === "string"
                ? body.author_name
                : (typeof body?.author === "string" ? body.author : ""),
            client_name: typeof body?.client_name === "string" ? body.client_name : "",
            contact_email: typeof body?.contact_email === "string" ? body.contact_email : "",
        };
    }
}

export default Config;
