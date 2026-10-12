import fetchMock from "jest-fetch-mock";
import Context from "../../src/handlers/context";
import {
    emptySharedContext, mergeSavedSection, nextSharedId, sharedDraft, updateSharedDraft,
} from "../../src/helpers/sharedContext";
import { emptyRisk, emptySystemComponent, emptySystemInteraction, emptyThreat } from "../../src/helpers/strideContext";
import type { SharedContext } from "../../src/helpers/sharedContext";

fetchMock.enableMocks();
beforeEach(() => fetchMock.resetMocks());
const choices = [{ id: "alpha", name: "Alpha" }, { id: "beta", name: "Beta" }];

test("identifier allocation reserves current, persisted and unavailable identifiers", () => {
    const saved = emptySharedContext();
    saved.components = [{ ...emptySystemComponent("C1"), variant_ids: ["alpha"] }];
    saved.interactions = [{ ...emptySystemInteraction("I1"), sourceId: "C2", destinationId: "C3", variant_ids: ["alpha"] }];
    saved.threats = [{ ...emptyThreat("T1"), targetIds: ["C4", "I2"], variant_ids: ["alpha"] }];
    saved.risks = [{ ...emptyRisk(), id: "R1", threatId: "T2", variant_ids: ["alpha"] }];
    saved.fields.environment = [{ id: "X1", value: "", variant_ids: ["alpha"] }];
    expect(nextSharedId("C", [emptySharedContext(), saved])).toBe("C5");
    expect(nextSharedId("I", [saved])).toBe("I3");
    expect(nextSharedId("T", [saved])).toBe("T3");
    expect(nextSharedId("R", [saved])).toBe("R2");
    expect(nextSharedId("X", [saved], ["X2"])).toBe("X3");
});

test("controlled drafts retain system and threat scopes and scope new records to current variants", () => {
    const document = emptySharedContext();
    document.components = [{ ...emptySystemComponent("C1"), variant_ids: ["alpha"] }];
    document.threats = [{ ...emptyThreat("T1"), targetIds: [], variant_ids: ["alpha"] }];
    document.fields.scope = [{ id: "X1", value: "Assets", variant_ids: ["alpha"] }];
    document.threat_notes = [{ id: "X2", value: "Assumption", variant_ids: ["alpha"] }];
    document.risk_notes = [{ id: "X3", value: "Uncertain", variant_ids: ["alpha"] }];
    const draft = sharedDraft(document);
    expect(draft.model.scope).toBe("Assets");
    expect(draft.model.notes).toBe("Assumption");
    expect(draft.register.notes).toBe("Uncertain");
    draft.model.components.push(emptySystemComponent("C2"));
    draft.model.interactions.push(emptySystemInteraction("I1"));
    draft.model.threats.push(emptyThreat("T2"));
    draft.register.risks.push(emptyRisk(), emptyRisk());
    const updated = updateSharedDraft(document, draft, choices);
    expect(updated.components[0].variant_ids).toEqual(["alpha"]);
    expect(updated.components[1].variant_ids).toEqual(["alpha", "beta"]);
    expect(updated.interactions[0].variant_ids).toEqual(["alpha", "beta"]);
    expect(updated.threats[1].targetIds).toEqual([]);
    expect(updated.risks.map(row => row.id)).toEqual(["R1", "R2"]);
});

test("risk identity is retained when selecting a different threat and a disjoint scope inherits the target scope", () => {
    const document = emptySharedContext();
    document.threats = [{ ...emptyThreat("T1"), targetIds: [], variant_ids: ["alpha"] }];
    document.risks = [{ ...emptyRisk(), id: "R4", variant_ids: ["beta"] }];
    const draft = sharedDraft(document);
    draft.register = { ...draft.register, risks: [{ ...draft.register.risks[0], threatId: "T1" }] };
    const updated = updateSharedDraft(document, draft, choices);
    expect(updated.risks[0].id).toBe("R4");
    expect(updated.risks[0].variant_ids).toEqual(["alpha"]);
    expect(document.risks[0].variant_ids).toEqual(["beta"]);
});

test("promoting a saved legacy risk scenario keeps its original variant scope", () => {
    const document = emptySharedContext();
    document.risks = [{ ...emptyRisk(), id: "R1", variant_ids: ["alpha"],
        legacyThreat: { category: "Tampering", description: "Unsigned updates" } }];
    const draft = sharedDraft(document);
    draft.model = { ...draft.model, threats: [{ id: "T1", category: "Tampering", description: "Unsigned updates" }] };
    draft.register = { ...draft.register, risks: [{ ...document.risks[0], threatId: "T1", legacyThreat: undefined }] };
    expect(updateSharedDraft(document, draft, choices).threats[0].variant_ids).toEqual(["alpha"]);
});

test.each(["context", "system", "threat_model", "risks"] as const)("merging a saved %s does not publish another section's draft", section => {
    const draft = emptySharedContext();
    const saved = emptySharedContext();
    for (const key of Object.keys(draft.fields) as (keyof SharedContext["fields"])[]) {
        draft.fields[key] = [{ id: "X1", value: "Draft", variant_ids: ["alpha"] }];
        saved.fields[key] = [{ id: "X2", value: "Saved", variant_ids: ["beta"] }];
    }
    draft.threats = [{ ...emptyThreat("T1"), variant_ids: ["alpha"], targetIds: [] }];
    saved.threats = [{ ...emptyThreat("T2"), variant_ids: ["beta"], targetIds: [] }];
    draft.risks = [{ ...emptyRisk(), id: "R1", variant_ids: ["alpha"] }];
    saved.risks = [{ ...emptyRisk(), id: "R2", variant_ids: ["beta"] }];
    const merged = mergeSavedSection(draft, saved, section);
    expect(merged.fields.environment[0].value).toBe(section === "context" ? "Saved" : "Draft");
    expect(merged.fields.scope[0].value).toBe(section === "system" ? "Saved" : "Draft");
    expect(merged.threats[0].id).toBe(section === "threat_model" ? "T2" : "T1");
    expect(merged.risks[0].id).toBe(section === "risks" ? "R2" : "R1");
});

test("shared HTTP load, scoped preview/save and mode conversion use explicit revisions", async () => {
    const document = emptySharedContext();
    const response = { project_id: "p", revision: 3, description: null, context: document, variants: [] };
    fetchMock.mockResponseOnce(JSON.stringify(response));
    expect(await Context.getShared("p/1")).toEqual(response);
    expect(fetchMock.mock.calls[0][0]).toContain("p%2F1/context/shared");
    fetchMock.mockResponseOnce(JSON.stringify({ changed_variant_ids: [], description_changed: false }));
    await Context.saveShared("p", "system", document, 3, "Unsaved description", true);
    expect(JSON.parse(fetchMock.mock.calls[1][1]!.body as string)).toEqual({
        section: "system", context: document, expected_revision: 3, dry_run: true,
    });
    fetchMock.mockResponseOnce(JSON.stringify(response));
    await Context.saveShared("p", "context", document, 3, "Project");
    expect(JSON.parse(fetchMock.mock.calls[2][1]!.body as string).description).toBe("Project");
    fetchMock.mockResponseOnce(JSON.stringify({ context: { ...document, editor_mode: "free" } }));
    expect((await Context.convertShared("p", document, "free")).editor_mode).toBe("free");
    expect(fetchMock.mock.calls[3][1]!.method).toBe("POST");
});

test.each([
    () => Context.getShared("p"), () => Context.saveShared("p", "context", emptySharedContext(), 0, null),
    () => Context.convertShared("p", emptySharedContext(), "free"),
])("shared HTTP errors surface backend messages", async action => {
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Conflict" }), { status: 409 });
    await expect(action()).rejects.toThrow("Conflict");
});

test("shared HTTP errors without messages identify load/update and status", async () => {
    fetchMock.mockResponseOnce("{}", { status: 500 });
    await expect(Context.getShared("p")).rejects.toThrow("Failed to load shared context (500)");
    fetchMock.mockResponseOnce("{}", { status: 500 });
    await expect(Context.convertShared("p", emptySharedContext(), "free")).rejects.toThrow("Failed to update shared context (500)");
});

test("legacy frontend context consumers remain usable", async () => {
    for (const action of [
        () => Context.get("p", "v"), () => Context.getProject("p"), () => Context.saveProject("p", "Project"),
        () => Context.saveVariant("v", { variant_description: null, codebase_path: null, environment: null,
            threat_model: "Original", risks: null, other_info: null }),
        () => Context.patchVariant("v", { environment: "Linux" }, { environment: null }),
        () => Context.exportAll(),
    ]) {
        fetchMock.mockResponseOnce(JSON.stringify({ value: "OK" }));
        expect(await action()).toEqual({ value: "OK" });
        fetchMock.mockResponseOnce(JSON.stringify({ error: "Failed" }), { status: 400 });
        await expect(action()).rejects.toThrow("Failed");
    }
});
