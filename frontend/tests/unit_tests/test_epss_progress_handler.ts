import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import EPSSProgressHandler from '../../src/handlers/epss_progress';
import type { EPSSProgress } from '../../src/handlers/epss_progress';


describe('EPSSProgressHandler', () => {

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
                message: 'Fetching EPSS scores...',
                last_update: '2026-02-05T10:00:00Z',
                started_at: '2026-02-05T09:00:00Z'
            };

            fetchMock.mockResponseOnce(JSON.stringify(mockData));

            const progress = await EPSSProgressHandler.getProgress();

            expect(progress).toEqual(mockData);
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/epss/progress'),
                expect.objectContaining({ mode: 'cors' })
            );
        });

        test('returns default values when API responds with partial data', async () => {
            fetchMock.mockResponseOnce(JSON.stringify({ in_progress: true, phase: 'processing' }));

            const progress = await EPSSProgressHandler.getProgress();

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

            const progress = await EPSSProgressHandler.getProgress();

            expect(progress.in_progress).toBe(false);
            expect(progress.phase).toBe('idle');
            expect(progress.current).toBe(0);
            expect(progress.total).toBe(0);
            expect(progress.message).toBe('');
        });
    });

    describe('getProgressPercentage', () => {
        test('returns 0 when not in progress and phase is not completed', () => {
            const progress: EPSSProgress = {
                in_progress: false,
                phase: 'idle',
                current: 0,
                total: 0,
                message: ''
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(0);
        });

        test('returns 1 when not in progress and phase is completed', () => {
            const progress: EPSSProgress = {
                in_progress: false,
                phase: 'completed',
                current: 100,
                total: 100,
                message: 'Done'
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(1);
        });

        test('returns 0 when in progress but total is 0', () => {
            const progress: EPSSProgress = {
                in_progress: true,
                phase: 'starting',
                current: 0,
                total: 0,
                message: 'Starting...'
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(0);
        });

        test('returns correct ratio when in progress', () => {
            const progress: EPSSProgress = {
                in_progress: true,
                phase: 'downloading',
                current: 40,
                total: 100,
                message: 'Fetching...'
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(0.4);
        });

        test('caps at 1 when current exceeds total', () => {
            const progress: EPSSProgress = {
                in_progress: true,
                phase: 'processing',
                current: 150,
                total: 100,
                message: 'Processing...'
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(1);
        });

        test('returns 1 when current equals total and in progress', () => {
            const progress: EPSSProgress = {
                in_progress: true,
                phase: 'finalizing',
                current: 100,
                total: 100,
                message: 'Finalizing...'
            };

            expect(EPSSProgressHandler.getProgressPercentage(progress)).toBe(1);
        });
    });
});
