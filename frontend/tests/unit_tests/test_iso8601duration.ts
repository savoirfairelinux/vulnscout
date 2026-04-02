import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import Iso8601Duration from "../../src/handlers/iso8601duration";

describe('Iso8601Duration', () => {
    // Silence console.warn noise during parsing edge-cases in constructor/parser
    let __warnBackup: typeof console.warn;
    beforeAll(() => {
        __warnBackup = console.warn;
        console.warn = (() => {}) as unknown as typeof console.warn;
    });
    afterAll(() => {
        console.warn = __warnBackup;
    });

    test('parse undefined', () => {
        const duration = new Iso8601Duration(undefined);
        expect(duration.total_seconds).toEqual(0);
    });
    test('parse empty string', () => {
        const duration = new Iso8601Duration('');
        expect(duration.total_seconds).toEqual(0);
    });
    test('parse 0d', () => {
        const duration = new Iso8601Duration('P0D');
        expect(duration.total_seconds).toEqual(0);
    });

    test('1 day is 8h', () => {
        const duration = new Iso8601Duration('P1D');
        expect(duration.total_seconds).toEqual(8 * 3600);
    });
    test('1d + 1h = 9h', () => {
        const duration = new Iso8601Duration('P1DT1H');
        expect(duration.total_seconds).toEqual(9 * 3600);
    });
    test('1 week = 5 days', () => {
        const d1 = new Iso8601Duration('P1W');
        const d2 = new Iso8601Duration('P5D');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });
    test('1 month = 4 weeks', () => {
        const d1 = new Iso8601Duration('P1M');
        const d2 = new Iso8601Duration('P4W');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });
    test('1 day = 8 hours', () => {
        const d1 = new Iso8601Duration('P1D');
        const d2 = new Iso8601Duration('PT8H');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });
    test('2 hours = 120 min', () => {
        const d1 = new Iso8601Duration('PT2H');
        const d2 = new Iso8601Duration('PT120M');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });
    test('1 week = 4d + 7h + 60m', () => {
        const d1 = new Iso8601Duration('P1W');
        const d2 = new Iso8601Duration('P4DT7H60M');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });

    test('gitlab single unit', () => {
        const duration = new Iso8601Duration('3d');
        expect(duration.total_seconds).toEqual(3 * 8 * 3600);
    });
    test('gitlab all units using decimals', () => {
        const d1 = new Iso8601Duration('1y 2mo 1w 3d 5.5h');
        const d2 = new Iso8601Duration('P1Y2M1W3DT5H30M');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });
    test('gitlab all units using minutes', () => {
        const d1 = new Iso8601Duration('1y 2m 1w 3d 5h 30m');
        const d2 = new Iso8601Duration('P1Y2M1W3DT5H30M');
        expect(d1.total_seconds).toEqual(d2.total_seconds);
    });

    test('parse not string as ISO 8601', () => {
        const duration = new Iso8601Duration(undefined);
        expect(() => {
            duration.parseIso8601(undefined as unknown as string);
        }).toThrow();
    });
    test('parse string missing `P` as ISO 8601', () => {
        const duration = new Iso8601Duration(undefined);
        expect(() => {
            duration.parseIso8601('hello');
        }).toThrow();
    });
    test('parse string `P` as ISO 8601', () => {
        expect(() => {
            new Iso8601Duration('P');
        }).toThrow();
    });
    test('parse not string as gitlab-like', () => {
        const duration = new Iso8601Duration(undefined);
        expect(() => {
            duration.parseGitlabLike(undefined as unknown as string);
        }).toThrow();
    });

    test('encode ISO ad Gitlab-like', () => {
        const duration = new Iso8601Duration('P1Y2M3W4DT5H6M');
        expect(duration.formatHumanShort()).toEqual('1y 2mo 3w 4d 5h 6m');
    });
    test('encode ISO ad Gitlab-like', () => {
        const duration = new Iso8601Duration('1y 2m 3w 4d 5h 30m');
        expect(duration.formatAsIso8601()).toEqual('P1Y2M3W4DT5H30M');
    });

    test('gitlab years standalone', () => {
        const duration = new Iso8601Duration('2years');
        expect(duration.total_seconds).toEqual(2 * 6912000);
    });
    test('gitlab months standalone (mo)', () => {
        const duration = new Iso8601Duration('3months');
        expect(duration.total_seconds).toEqual(3 * 576000);
    });
    test('gitlab weeks standalone', () => {
        const duration = new Iso8601Duration('2weeks');
        expect(duration.total_seconds).toEqual(2 * 144000);
    });
    test('gitlab hours standalone', () => {
        const duration = new Iso8601Duration('4hours');
        expect(duration.total_seconds).toEqual(4 * 3600);
    });
    test('gitlab minutes > 4 treated as minutes', () => {
        const duration = new Iso8601Duration('30m');
        expect(duration.total_seconds).toEqual(30 * 60);
    });
    test('gitlab minutes <= 4 treated as months', () => {
        const duration = new Iso8601Duration('3m');
        expect(duration.total_seconds).toEqual(3 * 576000);
    });
    test('formatHumanShort with individual units', () => {
        expect(new Iso8601Duration('2y').formatHumanShort()).toEqual('2y');
        expect(new Iso8601Duration('3mo').formatHumanShort()).toEqual('3mo');
        expect(new Iso8601Duration('1w').formatHumanShort()).toEqual('1w');
        expect(new Iso8601Duration('5d').formatHumanShort()).toEqual('5d');
        expect(new Iso8601Duration('PT8H').formatHumanShort()).toEqual('8h');
        expect(new Iso8601Duration('PT30M').formatHumanShort()).toEqual('30m');
    });
});
