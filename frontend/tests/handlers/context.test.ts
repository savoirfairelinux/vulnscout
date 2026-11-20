import Context, { ContextSaveError } from "../../src/handlers/context";
import type { AssessmentFormat } from "../../src/handlers/context";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

const FORMAT: AssessmentFormat = {
    sections: [{ id: 'confidence', enabled: true, label: 'Confidence' }, { id: 'verdict', enabled: false }],
    layout: 'lines',
    style_notes: 'Neutral tone.',
};

const reply = (status: number, body: unknown) => ({
    ok: status >= 200 && status < 300, status, json: async () => body,
} as Response);

beforeEach(() => mockFetch.mockReset());

describe("Context project assessment format", () => {
    it("saves only the assessment format", async () => {
        mockFetch.mockResolvedValueOnce(reply(200, { project_id: 'p 1', description: 'kept', assessment_format: FORMAT }));

        const saved = await Context.saveAssessmentFormat('p 1', FORMAT);

        const [url, init] = mockFetch.mock.calls[0];
        expect(url).toMatch(/\/api\/projects\/p%201\/context$/);
        expect(init.method).toBe('PUT');
        expect(JSON.parse(init.body)).toEqual({ assessment_format: FORMAT });
        expect(saved.assessment_format).toEqual(FORMAT);
        expect(saved.description).toBe('kept');
    });

    it("sends null to reset to the default presentation", async () => {
        mockFetch.mockResolvedValueOnce(reply(200, { project_id: 'p1', description: null, assessment_format: null }));
        await Context.saveAssessmentFormat('p1', null);
        expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ assessment_format: null });
    });

    it("reports validation errors with their field paths", async () => {
        const fields = { 'assessment_format.sections[1].label': 'must be at most 40 characters' };
        mockFetch.mockResolvedValueOnce(reply(400, { error: 'invalid', fields }));

        const error = await Context.saveAssessmentFormat('p1', FORMAT).catch((e: unknown) => e);

        expect(error).toBeInstanceOf(ContextSaveError);
        expect((error as ContextSaveError).status).toBe(400);
        expect((error as ContextSaveError).fields).toEqual(fields);
        expect((error as ContextSaveError).message).toBe('invalid');
    });

    it("falls back to a status message when the error reply is not JSON", async () => {
        mockFetch.mockResolvedValueOnce({ ok: false, status: 502, json: async () => { throw new Error('html'); } } as unknown as Response);
        await expect(Context.saveAssessmentFormat('p1', null)).rejects.toThrow('Failed to save the assessment format (502)');
    });

    it("the project description save leaves the format out of the request", async () => {
        mockFetch.mockResolvedValueOnce(reply(200, { project_id: 'p1', description: 'd', assessment_format: FORMAT }));
        const saved = await Context.saveProject('p1', 'd');
        expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ description: 'd' });
        expect(saved.assessment_format).toEqual(FORMAT);
    });
});
