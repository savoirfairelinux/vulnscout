type NvdApiKeyResponse = {
    ok: boolean;
    has_key: boolean;
    masked_key: string;
    error?: string;
    warning?: string;
};

class NvdApiKey {
    static async get(): Promise<{ has_key: boolean; masked_key: string }> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config/nvd-api-key", {
            mode: "cors",
        });
        const data = await response.json().catch(() => ({}));
        return {
            has_key: Boolean(data?.has_key),
            masked_key: typeof data?.masked_key === "string" ? data.masked_key : "",
        };
    }

    static async set(apiKey: string): Promise<NvdApiKeyResponse> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/config/nvd-api-key", {
            method: "PUT",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: apiKey }),
        });
        const data = await response.json().catch(() => ({}));
        return {
            ok: response.ok,
            has_key: Boolean(data?.has_key),
            masked_key: typeof data?.masked_key === "string" ? data.masked_key : "",
            error: typeof data?.error === "string" ? data.error : undefined,
            warning: typeof data?.warning === "string" ? data.warning : undefined,
        };
    }

    static async remove(): Promise<NvdApiKeyResponse> {
        return this.set("");
    }
}

export default NvdApiKey;
