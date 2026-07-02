type EUVDProgress = {
    in_progress: boolean;
    phase: string;
    current: number;
    total: number;
    message: string;
    last_update?: string;
    started_at?: string;
}

export type { EUVDProgress };

class EUVDProgressHandler {
    private static idleProgress(): EUVDProgress {
        return {
            in_progress: false,
            phase: 'idle',
            current: 0,
            total: 0,
            message: '',
        };
    }

    static async getProgress(): Promise<EUVDProgress> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/euvd/progress", {
            mode: "cors"
        });

        if (!response.ok) {
            // The endpoint returns 200 on supported backends; a non-OK reply
            // (e.g. 404 on an older deployment without EUVD support) is treated
            // as idle. Beyond a single fetch on mount, polling only runs during
            // an active refresh, so this won't spam requests.
            return EUVDProgressHandler.idleProgress();
        }

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

    static getProgressPercentage(progress: EUVDProgress): number {
        if (!progress.in_progress || progress.total === 0) {
            return progress.phase === 'completed' ? 1 : 0;
        }
        return Math.min(progress.current / progress.total, 1);
    }
}

export default EUVDProgressHandler;
