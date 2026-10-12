import {
    THREAT_MODEL_FIELDS, STRIDE_CATEGORIES, emptyThreat, emptyRisk, emptyThreatModel, loadStrideContext,
    nextThreatId, parseRiskRegister, parseThreatModel, serializeRiskRegister, serializeThreatModel,
} from "../../src/helpers/strideContext";
import type { RiskRegister, StrideRisk, ThreatModel } from "../../src/helpers/strideContext";

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
