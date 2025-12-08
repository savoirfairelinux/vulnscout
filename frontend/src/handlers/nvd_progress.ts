type NVDProgress = {
    in_progress: boolean;
    phase: string;
    current: number;
    total: number;
    message: string;
    last_update?: string;
    started_at?: string;
}

export type { NVDProgress };

class NVDProgressHandler {
    static async getProgress(): Promise<NVDProgress> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/nvd/progress", {
            mode: "cors"
        });
        const data = await response.json();
        return {
            in_progress: data?.in_progress ?? false,
            phase: data?.phase ?? 'idle',
            current: data?.current ?? 0,
            total: data?.total ?? 0,
            message: data?.message ?? '',
            last_update: data?.last_update,
            started_at: data?.started_at
        };
    }

    static getProgressPercentage(progress: NVDProgress): number {
        if (!progress.in_progress || progress.total === 0) {
            return progress.phase === 'completed' ? 1 : 0;
        }
        return Math.min(progress.current / progress.total, 1);
    }
}

export default NVDProgressHandler;
