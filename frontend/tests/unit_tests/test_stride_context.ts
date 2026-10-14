import {
    THREAT_MODEL_FIELDS, STRIDE_CATEGORIES, emptyThreat, emptyRisk, emptyThreatModel, loadStrideContext,
    nextThreatId, parseRiskRegister, parseThreatModel, serializeRiskRegister, serializeThreatModel,
    emptySystemComponent, emptySystemInteraction, nextSystemId, systemElementLabel, prepareStrideSectionSave,
} from "../../src/helpers/strideContext";
import type { RiskRegister, StrideRisk, ThreatModel } from "../../src/helpers/strideContext";
import fixture from "../../../tests/fixtures/stride_context_v2.json";

test("shared interchange fixture matches the frontend Markdown codec", () => {
    const model = { ...fixture.variant.system, ...fixture.variant.threat_model } as ThreatModel;
    const register = fixture.variant.risks as RiskRegister;
    expect(serializeThreatModel(model, register.risks.map(risk => risk.threatId))).toBe(fixture.text.threatModel);
    expect(serializeRiskRegister(register)).toBe(fixture.text.risks);
    expect(parseThreatModel(fixture.text.threatModel)).toEqual(model);
    expect(parseRiskRegister(fixture.text.risks)).toEqual(register);
    expect(loadStrideContext(fixture.text, "free").mode).toBe("free");
    expect(loadStrideContext({ threatModel: "Opaque model", risks: "Opaque risks" }, "stride")).toMatchObject({
        mode: "stride", model: { notes: "Opaque model" }, register: { notes: "Opaque risks" },
    });
});

describe("STRIDE context text", () => {
    const model: ThreatModel = {
        ...emptyThreatModel(),
        scope: "Firmware, credentials and user data",
        entry_points: "Public API -> gateway -> device",
        trust_boundaries: "Untrusted network -> authenticated gateway",
        threats: [{ id: "T1", category: "Spoofing", description: "A client could impersonate another device" }],
    };
    const risk: StrideRisk = {
        ...emptyRisk(), threatId: "T1",
        likelihood: "Medium", impact: "High", mitigation: "Authenticate devices",
        decision: "Investigate key provisioning before accepting the residual risk",
    };
    const register: RiskRegister = { risks: [risk], notes: "Review again after the design changes." };
    const systemModel: ThreatModel = {
        ...model,
        components: [
            { ...emptySystemComponent("C1"), name: "Update server", description: "Serves firmware images", trustZone: "External service" },
            { ...emptySystemComponent("C2"), name: "OTA updater", description: "Writes firmware", trustZone: "Privileged firmware" },
        ],
        interactions: [{
            ...emptySystemInteraction("I1"), name: "Firmware download", sourceId: "C1", destinationId: "C2",
            protocol: "HTTPS", description: "Signed firmware image", trustBoundary: "Network to privileged firmware",
        }],
        threats: [{ ...model.threats[0], targetIds: ["C2", "I1"] }],
    };

    describe("section saves", () => {
        const saved = { threatModel: serializeThreatModel(systemModel), risks: serializeRiskRegister(register) };

        test("System saves keep persisted threats and notes, not their local edits", () => {
            const draft = loadStrideContext(saved);
            draft.model.components[0].name = "Renamed server";
            draft.model.threats[0].description = "Unsaved threat";
            draft.model.notes = "Unsaved notes";
            draft.register.risks[0].mitigation = "Unsaved mitigation";
            expect(parseThreatModel(prepareStrideSectionSave("system", draft, saved, saved))).toEqual({
                ...systemModel, components: [{ ...systemModel.components[0], name: "Renamed server" }, systemModel.components[1]],
            });
        });

        test("Threat model saves keep persisted architecture, not local System edits", () => {
            const draft = loadStrideContext(saved);
            draft.model.scope = "Unsaved scope";
            draft.model.components[0].name = "Unsaved rename";
            draft.model.threats[0].description = "Updated threat";
            draft.model.notes = "Updated notes";
            expect(parseThreatModel(prepareStrideSectionSave("threat_model", draft, saved, saved))).toEqual({
                ...systemModel, threats: [{ ...systemModel.threats[0], description: "Updated threat" }], notes: "Updated notes",
            });
        });

        test("Risk saves require new threats to be saved first, without publishing them", () => {
            const draft = loadStrideContext(saved);
            draft.model.threats.push({ id: "T2", category: "Tampering", description: "New threat" });
            draft.register.risks[0].threatId = "T2";
            expect(() => prepareStrideSectionSave("risks", draft, saved, saved)).toThrow("Save Threat model before Risks");
            const withThreat = { ...saved, threatModel: serializeThreatModel(draft.model) };
            expect(parseRiskRegister(prepareStrideSectionSave("risks", draft, saved, withThreat))?.risks[0].threatId).toBe("T2");
        });

        test("saved identifiers remain reserved while removals in other tabs are only drafts", () => {
            const blank = emptyThreatModel();
            expect(nextThreatId(blank, { risks: [], notes: "" }, saved)).toBe("T2");
            expect(nextSystemId(blank, "C", systemModel)).toBe("C3");
            expect(nextSystemId(blank, "I", systemModel)).toBe("I2");
            expect(nextThreatId(blank, { risks: [], notes: "" }, { threatModel: "Free", risks: "Free" })).toBe("T1");
            expect(nextThreatId(blank, { risks: [], notes: "" }, {
                threatModel: "", risks: serializeRiskRegister({ risks: [{ ...emptyRisk(), threatId: "T1" }], notes: "" }),
            })).toBe("T2");
        });

        test("clearing the last system content cannot silently erase a referenced incomplete threat", () => {
            const baseline = {
                threatModel: serializeThreatModel({
                    ...emptyThreatModel(), scope: "Device", threats: [{ id: "T1", category: "Spoofing", description: "" }],
                }),
                risks: serializeRiskRegister(register),
            };
            const draft = loadStrideContext(baseline);
            draft.model.scope = "";
            expect(() => prepareStrideSectionSave("system", draft, baseline, baseline)).toThrow("Save Risks first");
        });

        test("Threat saves require newly referenced System elements to be saved first", () => {
            const draft = loadStrideContext(saved);
            draft.model.components.push({ ...emptySystemComponent("C3"), name: "New component" });
            draft.model.threats[0].targetIds = ["C3"];
            expect(() => prepareStrideSectionSave("threat_model", draft, saved, saved)).toThrow("Save System before Threat model");
        });

        test("saved references prevent deletions until the referencing section is saved", () => {
            const draft = loadStrideContext(saved);
            draft.model.threats[0].targetIds = [];
            draft.model.components = [draft.model.components[0]];
            draft.model.interactions = [];
            expect(() => prepareStrideSectionSave("system", draft, saved, saved)).toThrow("Save Threat model before System");
            const unlinked = { ...saved, threatModel: prepareStrideSectionSave("threat_model", draft, saved, saved) };
            expect(() => prepareStrideSectionSave("system", draft, saved, unlinked)).not.toThrow();
            draft.model.threats = [];
            draft.register.risks = [];
            expect(() => prepareStrideSectionSave("threat_model", draft, saved, saved)).toThrow("Save Risks before Threat model");
            expect(() => prepareStrideSectionSave("threat_model", draft, saved, { ...saved, risks: "" })).not.toThrow();
        });

        test("previously missing references remain editable without inventing their targets", () => {
            const missing = {
                threatModel: serializeThreatModel({ ...systemModel, threats: [{ ...systemModel.threats[0], targetIds: ["C9"] }] }),
                risks: serializeRiskRegister({ risks: [{ ...emptyRisk(), threatId: "T9", impact: "High" }], notes: "" }),
            };
            const draft = loadStrideContext(missing);
            expect(() => prepareStrideSectionSave("system", draft, missing, missing)).not.toThrow();
            expect(() => prepareStrideSectionSave("threat_model", draft, missing, missing)).not.toThrow();
            expect(prepareStrideSectionSave("risks", draft, missing, missing)).toBe(missing.risks);
        });

        test("free mode saves text independently and System conversion is explicit", () => {
            const free = { threatModel: "Custom model", risks: "Custom risks" };
            const draft = loadStrideContext(free);
            const changed = { threatModel: "New model", risks: "New risks" };
            expect(prepareStrideSectionSave("threat_model", draft, changed, free)).toBe("New model");
            expect(prepareStrideSectionSave("risks", draft, changed, free)).toBe("New risks");
            expect(() => prepareStrideSectionSave("system", draft, changed, free)).toThrow("Advanced free mode");
            draft.mode = "stride";
            expect(() => prepareStrideSectionSave("system", draft, changed, free)).toThrow("Save Threat model first");
            expect(parseThreatModel(prepareStrideSectionSave("threat_model", draft, changed, free))?.notes).toBe("Custom model");
        });
    });

    test("system components, directed interactions and multiple threat targets round trip as readable text", () => {
        const text = serializeThreatModel(systemModel);
        expect(text).toContain("<!-- VulnScout STRIDE v2 -->");
        expect(text).toContain("## Component 1 / Name\n> Update server");
        expect(text).toContain("## Interaction 1 / Source component ID\n> C1");
        expect(text).toContain("## Threat 1 / Affected system elements\n> C2\n> I1");
        expect(parseThreatModel(text)).toEqual(systemModel);
        expect(loadStrideContext({ threatModel: text, risks: serializeRiskRegister(register) })).toEqual({
            mode: "stride", model: systemModel, register,
        });
        expect(systemElementLabel(systemModel, "C2")).toBe("Component C2: OTA updater");
        expect(systemElementLabel(systemModel, "I1")).toBe("Interaction I1: Firmware download");
        expect(systemElementLabel(systemModel, "C99")).toBeNull();
    });

    test("empty system drafts do not create content or upgrade otherwise unchanged legacy text", () => {
        const blank = {
            ...emptyThreatModel(), components: [emptySystemComponent("C1")], interactions: [emptySystemInteraction("I1")],
        };
        expect(serializeThreatModel(blank)).toBe("");
        const withDrafts = { ...model, components: blank.components, interactions: blank.interactions };
        expect(serializeThreatModel(withDrafts)).toBe(serializeThreatModel(model));
        expect(parseThreatModel(serializeThreatModel(model))).toEqual(model);
    });

    test("system-only context can be saved without inventing threats or risk evaluations", () => {
        const systemOnly = { ...systemModel, threats: [] };
        const text = serializeThreatModel(systemOnly);
        expect(parseThreatModel(text)).toEqual(systemOnly);
        const loaded = loadStrideContext({ threatModel: text, risks: "" });
        expect(loaded.model.threats).toEqual([emptyThreat("T1")]);
        expect(serializeThreatModel(loaded.model)).toBe(text);
        expect(serializeRiskRegister(loaded.register)).toBe("");
    });

    test("system text preserves whitespace and user headings without interpreting them as structure", () => {
        const value = "  Initial text\n\n## Threat 1 / ID\n> T99\n<!-- VulnScout STRIDE v2 -->\n ";
        const edited: ThreatModel = {
            ...systemModel,
            components: [{ ...systemModel.components[0], name: value, description: value, trustZone: value }],
            interactions: [{ ...systemModel.interactions[0], name: value, protocol: value, description: value, trustBoundary: value }],
        };
        expect(parseThreatModel(serializeThreatModel(edited))).toEqual(edited);
    });

    test("referenced system elements retain IDs even after their descriptive fields are cleared", () => {
        const cleared: ThreatModel = {
            ...model, components: [emptySystemComponent("C1"), emptySystemComponent("C2")],
            interactions: [{ ...emptySystemInteraction("I1"), sourceId: "C1", destinationId: "C2" }],
            threats: [{ ...model.threats[0], targetIds: ["C2", "I1"] }],
        };
        expect(parseThreatModel(serializeThreatModel(cleared))).toEqual(cleared);
        expect(systemElementLabel(cleared, "C1")).toBe("Component C1: (name needed)");
        expect(systemElementLabel(cleared, "I1")).toBe("Interaction I1: (name needed)");
        const emptyLinked = { ...cleared, interactions: [emptySystemInteraction("I1")] };
        expect(parseThreatModel(serializeThreatModel(emptyLinked))?.interactions).toEqual(emptyLinked.interactions);
    });

    test("missing system references are preserved and reserved rather than attached to new elements", () => {
        const missing: ThreatModel = {
            ...model, components: [], interactions: [{
                ...emptySystemInteraction("I2"), name: "Missing endpoints", sourceId: "C1", destinationId: "C9",
            }], threats: [{ ...model.threats[0], targetIds: ["C2", "I1"] }],
        };
        expect(parseThreatModel(serializeThreatModel(missing))).toEqual(missing);
        expect(nextSystemId(missing, "C")).toBe("C3");
        expect(nextSystemId(missing, "I")).toBe("I3");
    });

    test.each([
        serializeThreatModel(systemModel).replace("Component 1 / ID", "Component 2 / ID"),
        serializeThreatModel(systemModel).replace("> C1", "> bad-id"),
        serializeThreatModel(systemModel).replace("## Component 2 / ID\n> C2", "## Component 2 / ID\n> C1"),
        serializeThreatModel(systemModel).replace("Interaction 1 / ID", "Interaction 3 / ID"),
        serializeThreatModel(systemModel).replace("> I1", "> I0"),
        serializeThreatModel({
            ...systemModel, interactions: [systemModel.interactions[0], systemModel.interactions[0]],
        }),
        serializeThreatModel(systemModel).replace("## Interaction 1 / Source component ID\n> C1", "## Interaction 1 / Source component ID\n> T1"),
        serializeThreatModel(systemModel).replace("Threat 1 / Affected system elements", "Threat 1 / Unknown targets"),
        serializeThreatModel(systemModel).replace("## Threat 1 / Affected system elements\n> C2\n> I1", "## Threat 1 / Affected system elements\n> C2\n> C2"),
        serializeThreatModel(systemModel).replace("## Threat 1 / Affected system elements\n> C2\n> I1", "## Threat 1 / Affected system elements\n> T1"),
        serializeThreatModel(systemModel).replace("\n\n## Interaction 1 / Trust boundary\n> Network to privileged firmware", ""),
    ])("malformed system templates remain in free mode without losing their text: %s", text => {
        expect(parseThreatModel(text)).toBeNull();
        expect(loadStrideContext({ threatModel: text, risks: "" })).toMatchObject({
            mode: "free", model: { notes: text },
        });
    });

    test("blank or whitespace-only templates do not create mandatory model content or optional risks", () => {
        expect(serializeThreatModel(emptyThreatModel())).toBe("");
        expect(serializeThreatModel({ ...emptyThreatModel(), scope: " \n \t" })).toBe("");
        expect(serializeThreatModel({ ...emptyThreatModel(), threats: [emptyThreat("T1")] })).toBe("");
        expect(serializeThreatModel({
            ...emptyThreatModel(), threats: [{ id: "T1", category: "Spoofing", description: " \n " }],
        })).toBe("");
        expect(serializeRiskRegister({ risks: [emptyRisk()], notes: "" })).toBe("");
        expect(serializeRiskRegister({ risks: [emptyRisk(), emptyRisk()], notes: " \n " })).toBe("");
        expect(parseThreatModel(" \n ")).toEqual(emptyThreatModel());
        expect(parseRiskRegister(" \n ")).toEqual({ risks: [emptyRisk()], notes: "" });
        expect(loadStrideContext({ threatModel: "", risks: "" }).mode).toBe("stride");
    });

    test("editor drafts start with one empty threat and risk without adding saved content", () => {
        const loaded = loadStrideContext({ threatModel: "", risks: "" });
        expect(loaded.model.threats).toEqual([emptyThreat("T1")]);
        expect(loaded.register).toEqual({ risks: [emptyRisk()], notes: "" });
        expect(serializeThreatModel(loaded.model)).toBe("");
        expect(serializeRiskRegister(loaded.register)).toBe("");
        expect(emptyThreatModel().threats).toEqual([]);
        expect(parseThreatModel("")).toEqual(emptyThreatModel());
    });

    test("a saved model without threats gets an empty editor row without changing its serialization", () => {
        const saved = serializeThreatModel({ ...emptyThreatModel(), scope: "Device firmware" });
        const loaded = loadStrideContext({ threatModel: saved, risks: "" });
        expect(loaded.model.threats).toEqual([emptyThreat("T1")]);
        expect(serializeThreatModel(loaded.model)).toBe(saved);
    });

    test("the default empty threat reserves missing risk targets instead of repairing them by guessing", () => {
        const savedModel = serializeThreatModel({ ...emptyThreatModel(), scope: "Device firmware" });
        const savedRisks = serializeRiskRegister({
            risks: [{ ...emptyRisk(), threatId: "T1", impact: "High" }], notes: "",
        });
        const loaded = loadStrideContext({ threatModel: savedModel, risks: savedRisks });
        expect(loaded.model.threats).toEqual([emptyThreat("T2")]);
        expect(loaded.register.risks[0].threatId).toBe("T1");
        expect(serializeThreatModel(loaded.model, loaded.register.risks.map(risk => risk.threatId))).toBe(savedModel);
        expect(serializeRiskRegister(loaded.register)).toBe(savedRisks);
    });

    test("the threat model is readable text and restores architecture, threats and notes", () => {
        const complete: ThreatModel = {
            ...model, notes: "Assumptions under review",
            threats: STRIDE_CATEGORIES.map((category, index) => ({
                id: `T${index + 1}`, category: category.name, description: `Threat: ${category.name}`,
            })),
        };
        THREAT_MODEL_FIELDS.forEach(field => { complete[field.key] = `Details for ${field.label}`; });
        const text = serializeThreatModel(complete);
        expect(text).toContain("# STRIDE threat model");
        for (const category of STRIDE_CATEGORIES) expect(text).toContain(category.name);
        expect(parseThreatModel(text)).toEqual(complete);
        expect(parseThreatModel(` \n${text}\n `)).toEqual(complete);
        expect(serializeThreatModel(parseThreatModel(text)!)).toBe(text);
    });

    test.each([
        "\n\n## T - Tampering\n\nnew headings\n",
        "> quoted\n>> nested\n\n> ",
        "```markdown\n# STRIDE threat model\n```\n<!-- VulnScout STRIDE v1 -->",
        "  leading whitespace\ntrailing whitespace  \n\n",
        "Repository: C:\\sources\\firmware\nUnicode data: \u00e9",
    ])("field text round trips without confusing user text with template delimiters: %s", value => {
        const withText = { ...model, notes: value, threats: [{ id: "T1", category: "Spoofing" as const, description: value }] };
        expect(parseThreatModel(serializeThreatModel(withText))).toEqual(withText);
        const withRiskText = { risks: [{ ...risk, mitigation: value, decision: value }], notes: value };
        expect(parseRiskRegister(serializeRiskRegister(withRiskText))).toEqual(withRiskText);
    });

    test("multiple threats sharing a category retain their descriptions and order across saves", () => {
        const populated: ThreatModel = {
            ...model,
            threats: [
                emptyThreat("T1"),
                { id: "T2", category: "Spoofing", description: "Impersonate a device" },
                { id: "T3", category: "Spoofing", description: "Impersonate an administrator" },
                emptyThreat("T4"),
                { id: "T5", category: "Tampering", description: "Install unsigned firmware" },
            ],
        };
        const text = serializeThreatModel(populated);
        expect(text).toContain("## Threat 2 / STRIDE category\n> Spoofing");
        expect(text).not.toContain("Threat 4");
        expect(parseThreatModel(text)?.threats).toEqual(populated.threats.filter(threat => threat.description));
        expect(serializeThreatModel(parseThreatModel(text)!)).toBe(text);
    });

    test("partial threats are preserved with populated context without inventing a category or description", () => {
        const partial: ThreatModel = {
            ...model, threats: [
                { id: "T1", category: "", description: "Not yet categorized" },
                { id: "T2", category: "Tampering", description: "" },
            ],
        };
        expect(parseThreatModel(serializeThreatModel(partial))).toEqual(partial);
    });

    test("previous category text areas load as individual threats while retaining architecture and notes", () => {
        const legacy = `# STRIDE threat model

## System scope and assets
> Legacy firmware

## Actors and access
>

## Entry points and data flows
>

## Trust boundaries
>

## S - Spoofing
> Device impersonation
>
> Administrator impersonation

## T - Tampering
> Unsigned firmware updates

## R - Repudiation
>

## I - Information disclosure
>

## D - Denial of service
>

## E - Elevation of privilege
>

## Additional threat model notes
> Physical access is possible

<!-- VulnScout STRIDE v1 -->`;
        const loaded = parseThreatModel(legacy);
        expect(loaded).toEqual({
            ...emptyThreatModel(), scope: "Legacy firmware", notes: "Physical access is possible",
            threats: [
                { id: "T1", category: "Spoofing", description: "Device impersonation\n\nAdministrator impersonation" },
                { id: "T2", category: "Tampering", description: "Unsigned firmware updates" },
            ],
        });
        expect(loadStrideContext({ threatModel: legacy, risks: "" }).mode).toBe("stride");
        expect(parseThreatModel(serializeThreatModel(loaded!))).toEqual(loaded);
        expect(parseThreatModel(legacy.replace("S - Spoofing", "S - Unknown"))).toBeNull();
        expect(parseThreatModel(legacy.replace("> Legacy firmware", "Legacy firmware"))).toBeNull();
    });

    test("risks preserve threat references, ratings and decisions without duplicating threat descriptions", () => {
        const second: StrideRisk = { ...emptyRisk(), threatId: "T2" };
        const populated = { risks: [emptyRisk(), risk, emptyRisk(), second], notes: register.notes };
        const text = serializeRiskRegister(populated);
        expect(text).toContain("## Risk 2 / Threat ID\n> T2");
        expect(text).not.toContain("Risk 3");
        expect(text).not.toContain("STRIDE category");
        expect(text).not.toContain("Threat scenario");
        expect(parseRiskRegister(text)).toEqual({ risks: [risk, second], notes: register.notes });
        expect(serializeRiskRegister(parseRiskRegister(text)!)).toBe(text);
    });

    test("notes-only risk registers remain readable and editable with no invented risk row", () => {
        const notesOnly = { risks: [], notes: "Risks still under investigation" };
        expect(parseRiskRegister(serializeRiskRegister(notesOnly))).toEqual(notesOnly);
        expect(serializeRiskRegister(notesOnly)).not.toContain("Risk 1");
    });

    test.each([
        "Ordinary free-text context",
        "# STRIDE threat model\n\n## Spoofing\nAn attacker could impersonate a user",
        serializeThreatModel(model).replace("<!-- VulnScout STRIDE v1 -->", ""),
        serializeThreatModel(model).replace("## System scope and assets", "## Unknown field"),
        serializeThreatModel(model).replace("> Firmware", "Firmware"),
        serializeThreatModel(model).replace("> Firmware", ">Firmware"),
        serializeThreatModel(model).replace("## Actors and access\n>", "## Actors and access"),
        serializeThreatModel(model).replace("\n\n## Additional threat model notes\n>", ""),
        serializeThreatModel(model).replace("\n\n<!-- VulnScout", "\n\n## Unknown field\n> Keep me\n\n<!-- VulnScout"),
        serializeThreatModel(model).replace("Threat 1 / STRIDE category", "Threat 3 / STRIDE category"),
        serializeThreatModel(model).replace("Threat 1 / Description", "Threat 3 / Description"),
        serializeThreatModel(model).replace("> Spoofing", "> Custom category"),
        serializeThreatModel(model).replace("Threat 1 / ID", "Threat 3 / ID"),
        serializeThreatModel(model).replace("> T1", "> bad-id"),
        serializeThreatModel(model).replace("\n\n## Threat 1 / Description\n> A client could impersonate another device", ""),
        "# STRIDE threat model\n\n<!-- VulnScout STRIDE v1 -->",
    ])("unrecognized or malformed threat text remains in free mode without losing data: %s", text => {
        expect(parseThreatModel(text)).toBeNull();
        const loaded = loadStrideContext({ threatModel: text, risks: "original risks" });
        expect(loaded.mode).toBe("free");
        expect(loaded.model.notes).toBe(text);
        expect(loaded.register.notes).toBe("original risks");
    });

    test.each([
        "Ordinary free-text risks",
        serializeRiskRegister(register).replace("# STRIDE risk register", "# Another register"),
        serializeRiskRegister(register).replace("> T1", "> bad-reference"),
        serializeRiskRegister(register).replace("> Medium", "> Certain"),
        serializeRiskRegister(register).replace("> High", "> Critical"),
        serializeRiskRegister(register).replace("Risk 1 / Impact", "Risk 3 / Impact"),
        serializeRiskRegister(register).replace("Additional risk notes", "Other notes"),
        serializeRiskRegister(register).replace("\n\n## Risk 1 / Impact\n> High", ""),
        "# STRIDE risk register\n\n<!-- VulnScout STRIDE v1 -->",
    ])("unrecognized risk text is retained even when the threat model is structured: %s", text => {
        expect(parseRiskRegister(text)).toBeNull();
        const loaded = loadStrideContext({ threatModel: serializeThreatModel(model), risks: text });
        expect(loaded.mode).toBe("free");
        expect(loaded.model).toEqual(model);
        expect(loaded.register.notes).toBe(text);
    });

    test("an existing model, risks or both can select advanced mode without discarding the other structured field", () => {
        expect(loadStrideContext({ threatModel: "legacy model", risks: "" })).toMatchObject({
            mode: "free", model: { notes: "legacy model" },
        });
        const loaded = loadStrideContext({ threatModel: "legacy model", risks: serializeRiskRegister(register) });
        expect(loaded.mode).toBe("free");
        expect(loaded.register).toEqual(register);
        expect(loadStrideContext({ threatModel: serializeThreatModel(model), risks: serializeRiskRegister(register) }).mode)
            .toBe("stride");
    });

    test("threat IDs remain stable when empty or unrelated threats are omitted or removed", () => {
        const withEmpty: ThreatModel = { ...model, threats: [emptyThreat("T1"), { ...model.threats[0], id: "T2" }] };
        const parsed = parseThreatModel(serializeThreatModel(withEmpty))!;
        expect(parsed.threats[0].id).toBe("T2");
        const linked = { risks: [{ ...emptyRisk(), threatId: "T2" }], notes: "" };
        expect(loadStrideContext({
            threatModel: serializeThreatModel(withEmpty), risks: serializeRiskRegister(linked),
        }).register).toEqual(linked);
        expect(nextThreatId(parsed, { risks: [{ ...emptyRisk(), threatId: "T1" }], notes: "" })).toBe("T3");
        expect(parseThreatModel(serializeThreatModel({
            ...model, threats: [model.threats[0], { ...model.threats[0], description: "Duplicate ID" }],
        }))).toBeNull();
    });

    test("old numbered threats gain stable IDs and keep their descriptions", () => {
        const old = serializeThreatModel(model).replace("\n\n## Threat 1 / ID\n> T1", "");
        expect(parseThreatModel(old)).toEqual(model);
    });

    test("linked threats whose descriptions are cleared retain their identity when other model context exists", () => {
        const cleared: ThreatModel = { ...model, threats: [emptyThreat("T1")] };
        expect(parseThreatModel(serializeThreatModel(cleared, ["T1"]))).toEqual(cleared);
    });

    test("legacy risks retain their original scenarios and link only to a unique exact matching threat", () => {
        const legacy: StrideRisk = {
            ...emptyRisk(), impact: "High",
            legacyThreat: { category: "Spoofing", description: model.threats[0].description },
        };
        const legacyText = serializeRiskRegister({ risks: [legacy], notes: "" });
        expect(legacyText).toContain("STRIDE category");
        expect(parseRiskRegister(legacyText)?.risks[0]).toEqual(legacy);
        const loaded = loadStrideContext({ threatModel: serializeThreatModel(model), risks: legacyText });
        expect(loaded.register.risks).toEqual([{ ...emptyRisk(), threatId: "T1", impact: "High" }]);
        const ambiguous: ThreatModel = { ...model, threats: [model.threats[0], { ...model.threats[0], id: "T2" }] };
        expect(loadStrideContext({ threatModel: serializeThreatModel(ambiguous), risks: legacyText }).register.risks)
            .toEqual([legacy]);
        const different: ThreatModel = { ...model, threats: [{ ...model.threats[0], description: "Another scenario" }] };
        expect(loadStrideContext({ threatModel: serializeThreatModel(different), risks: legacyText }).register.risks)
            .toEqual([legacy]);
        expect(parseRiskRegister(legacyText.replace("> Spoofing", "> Unknown category"))).toBeNull();
        const mixed = { risks: [risk, legacy], notes: "Mixed old and linked entries" };
        expect(parseRiskRegister(serializeRiskRegister(mixed))).toEqual(mixed);
    });
});
