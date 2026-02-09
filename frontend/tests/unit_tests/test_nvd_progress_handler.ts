import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import NVDProgressHandler from '../../src/handlers/nvd_progress';
import type { NVDProgress } from '../../src/handlers/nvd_progress';


describe('NVDProgressHandler', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    describe('getProgress', () => {
        test('returns progress data when API responds with complete data', async () => {
            const mockData = {
                in_progress: true,
                phase: 'downloading',
                current: 50,
                total: 100,
                message: 'Downloading NVD data...',
                last_update: '2026-02-05T10:00:00Z',
                started_at: '2026-02-05T09:00:00Z'
            };

            fetchMock.mockResponseOnce(JSON.stringify(mockData));

            const progress = await NVDProgressHandler.getProgress();

            expect(progress).toEqual(mockData);
            expect(fetchMock).toHaveBeenCalledTimes(1);
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/nvd/progress'),
                expect.objectContaining({ mode: 'cors' })
            );
        });

        test('returns default values when API responds with partial data', async () => {
            const mockData = {
                in_progress: true,
                phase: 'processing'
            };

            fetchMock.mockResponseOnce(JSON.stringify(mockData));

            const progress = await NVDProgressHandler.getProgress();

            expect(progress.in_progress).toBe(true);
            expect(progress.phase).toBe('processing');
            expect(progress.current).toBe(0);
            expect(progress.total).toBe(0);
            expect(progress.message).toBe('');
            expect(progress.last_update).toBeUndefined();
            expect(progress.started_at).toBeUndefined();
        });

        test('returns default values when API responds with null data', async () => {
            fetchMock.mockResponseOnce(JSON.stringify(null));

            const progress = await NVDProgressHandler.getProgress();

            expect(progress.in_progress).toBe(false);
            expect(progress.phase).toBe('idle');
            expect(progress.current).toBe(0);
            expect(progress.total).toBe(0);
            expect(progress.message).toBe('');
        });

        test('returns default values when API responds with empty object', async () => {
            fetchMock.mockResponseOnce(JSON.stringify({}));

            const progress = await NVDProgressHandler.getProgress();

            expect(progress.in_progress).toBe(false);
            expect(progress.phase).toBe('idle');
            expect(progress.current).toBe(0);
            expect(progress.total).toBe(0);
            expect(progress.message).toBe('');
        });

        test('handles API response with only optional fields', async () => {
            const mockData = {
                in_progress: false,
                phase: 'completed',
                current: 100,
                total: 100,
                message: 'Download completed',
                last_update: '2026-02-05T11:00:00Z'
            };

            fetchMock.mockResponseOnce(JSON.stringify(mockData));

            const progress = await NVDProgressHandler.getProgress();

            expect(progress.in_progress).toBe(false);
            expect(progress.phase).toBe('completed');
            expect(progress.last_update).toBe('2026-02-05T11:00:00Z');
            expect(progress.started_at).toBeUndefined();
        });
    });

    describe('getProgressPercentage', () => {
        test('returns 0 when not in progress and phase is not completed', () => {
            const progress: NVDProgress = {
                in_progress: false,
                phase: 'idle',
                current: 0,
                total: 0,
                message: ''
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(0);
        });

        test('returns 1 when not in progress but phase is completed', () => {
            const progress: NVDProgress = {
                in_progress: false,
                phase: 'completed',
                current: 100,
                total: 100,
                message: 'Completed'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(1);
        });

        test('returns 0 when in progress but total is 0', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'processing',
                current: 0,
                total: 0,
                message: 'Starting...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(0);
        });

        test('returns correct percentage when in progress', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'downloading',
                current: 50,
                total: 100,
                message: 'Downloading...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(0.5);
        });

        test('returns correct percentage for partial progress', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'downloading',
                current: 25,
                total: 100,
                message: 'Downloading...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(0.25);
        });

        test('returns 1 when current exceeds total (caps at 1)', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'downloading',
                current: 120,
                total: 100,
                message: 'Downloading...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(1);
        });

        test('returns correct percentage for fractional values', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'processing',
                current: 33,
                total: 100,
                message: 'Processing...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(0.33);
        });

        test('returns 1 when current equals total and in progress', () => {
            const progress: NVDProgress = {
                in_progress: true,
                phase: 'finalizing',
                current: 100,
                total: 100,
                message: 'Finalizing...'
            };

            const percentage = NVDProgressHandler.getProgressPercentage(progress);
            expect(percentage).toBe(1);
        });
    });
});
