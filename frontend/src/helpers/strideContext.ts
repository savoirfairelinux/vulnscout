export const STRIDE_CATEGORIES = [
    { key: "spoofing", name: "Spoofing", letter: "S",
        question: "Who or what could impersonate a trusted user, device or service?",
        example: "An unauthenticated device could impersonate a trusted sensor." },
    { key: "tampering", name: "Tampering", letter: "T",
        question: "Which data, firmware or configuration could be modified without authorization?",
        example: "An attacker could alter an unsigned firmware update." },
    { key: "repudiation", name: "Repudiation", letter: "R",
        question: "Which actions could be denied because trustworthy audit evidence is missing?",
        example: "Administrative configuration changes are not recorded in an audit log." },
    { key: "information_disclosure", name: "Information disclosure", letter: "I",
        question: "Which sensitive information could be exposed, and through which interface?",
        example: "Debug output could reveal credentials or customer data." },
    { key: "denial_of_service", name: "Denial of service", letter: "D",
        question: "How could an attacker interrupt service or exhaust resources?",
        example: "Repeated network requests could exhaust memory and stop the device." },
    { key: "elevation_of_privilege", name: "Elevation of privilege", letter: "E",
        question: "How could a lower-privileged actor gain permissions they should not have?",
        example: "An unprivileged process could gain administrator access through a local interface." },
] as const;

export const THREAT_MODEL_FIELDS = [
    { key: "scope", label: "System scope and assets",
        help: "What are you protecting, and what is outside the scope?",
        placeholder: "Device firmware, update service, credentials and customer data; manufacturing is out of scope." },
    { key: "actors", label: "Actors and access",
        help: "Who uses the system, and what access can an attacker obtain?",
        placeholder: "Customers, administrators and remote attackers; physical access is possible." },
    { key: "entry_points", label: "Entry points and data flows",
        help: "Record exposed interfaces and flow notes not captured by the interactions below.",
        placeholder: "Mobile app -> HTTPS API -> device; updates arrive over the network; local UART debug port." },
    { key: "trust_boundaries", label: "Trust boundaries",
        help: "Where does data or control cross between different levels of trust?",
        placeholder: "Public network -> authenticated API; unprivileged application -> privileged update service." },
] as const;

export type StrideCategory = (typeof STRIDE_CATEGORIES)[number]["name"];
export type SystemComponent = { id: string; name: string; description: string; trustZone: string };
export type SystemInteraction = {
    id: string; name: string; sourceId: string; destinationId: string;
    protocol: string; description: string; trustBoundary: string;
};
export type StrideThreat = {
    id: string; category: "" | StrideCategory; description: string; targetIds?: string[];
};
export type ThreatModel = Record<(typeof THREAT_MODEL_FIELDS)[number]["key"], string> & {
    components: SystemComponent[];
    interactions: SystemInteraction[];
    threats: StrideThreat[];
    notes: string;
};
export type RiskRating = "" | "Low" | "Medium" | "High";
export type StrideRisk = {
    threatId: string;
    legacyThreat?: { category: "" | StrideCategory; description: string };
    likelihood: RiskRating;
    impact: RiskRating;
    mitigation: string;
    decision: string;
};
export type RiskRegister = { risks: StrideRisk[]; notes: string };
export type StrideContextText = { threatModel: string; risks: string };

export const RISK_FIELDS = [
    { key: "threatId", label: "Threat ID" },
    { key: "likelihood", label: "Likelihood" },
    { key: "impact", label: "Impact" },
    { key: "mitigation", label: "Mitigation" },
    { key: "decision", label: "Residual risk / decision" },
] as const;

const END_MARKER = "<!-- VulnScout STRIDE v1 -->";
const SYSTEM_END_MARKER = "<!-- VulnScout STRIDE v2 -->";
const MODEL_TITLE = "# STRIDE threat model";
const RISKS_TITLE = "# STRIDE risk register";
export const COMPONENT_FIELDS = [
    { key: "name", label: "Name" }, { key: "description", label: "Description / role" },
    { key: "trustZone", label: "Trust zone" },
] as const;
export const INTERACTION_FIELDS = [
    { key: "name", label: "Name" }, { key: "sourceId", label: "Source component ID" },
    { key: "destinationId", label: "Destination component ID" }, { key: "protocol", label: "Interface / protocol" },
    { key: "description", label: "Data / commands" }, { key: "trustBoundary", label: "Trust boundary" },
] as const;

export function emptyThreatModel(): ThreatModel {
    return {
        scope: "", actors: "", entry_points: "", trust_boundaries: "",
        components: [], interactions: [], threats: [], notes: "",
    };
}

export function emptySystemComponent(id: string): SystemComponent {
    return { id, name: "", description: "", trustZone: "" };
}

export function emptySystemInteraction(id: string): SystemInteraction {
    return { id, name: "", sourceId: "", destinationId: "", protocol: "", description: "", trustBoundary: "" };
}

export function emptyThreat(id: string): StrideThreat {
    return { id, category: "", description: "" };
}

export function emptyRisk(): StrideRisk {
    return { threatId: "", likelihood: "", impact: "", mitigation: "", decision: "" };
}

export function hasThreatDraft(threat: StrideThreat): boolean {
    return Boolean(threat.category || threat.description.trim() || threat.targetIds?.length);
}

export function hasRiskContent(risk: StrideRisk): boolean {
    return RISK_FIELDS.some(field => risk[field.key].trim())
        || Boolean(risk.legacyThreat?.category || risk.legacyThreat?.description.trim());
}

export function nextThreatId(model: ThreatModel, register: RiskRegister): string {
    return nextId("T", [...model.threats.map(threat => threat.id), ...register.risks.map(risk => risk.threatId)]);
}

function nextId(prefix: string, ids: readonly string[]): string {
    const used = new Set(ids);
    let number = 1;
    while (used.has(`${prefix}${number}`)) number++;
    return `${prefix}${number}`;
}

export function nextSystemId(model: ThreatModel, prefix: "C" | "I"): string {
    return nextId(prefix, [
        ...model.components.map(component => component.id), ...model.interactions.map(interaction => interaction.id),
        ...model.interactions.flatMap(interaction => [interaction.sourceId, interaction.destinationId]),
        ...model.threats.flatMap(threat => threat.targetIds ?? []),
    ]);
}

export function systemElementLabel(model: ThreatModel, targetId: string): string | null {
    const component = model.components.find(element => element.id === targetId);
    if (component) return `Component ${component.id}: ${component.name.trim() || "(name needed)"}`;
    const interaction = model.interactions.find(element => element.id === targetId);
    if (interaction) return `Interaction ${interaction.id}: ${interaction.name.trim() || "(name needed)"}`;
    return null;
}

type Section = { label: string; value: string };

function serializeSections(title: string, sections: Section[], marker = END_MARKER): string {
    if (!sections.some(section => section.value.trim())) return "";
    // Quoted lines keep user-supplied headings and blank lines out of the template delimiters.
    const body = sections.map(section =>
        `## ${section.label}\n${section.value.split("\n").map(line => line ? `> ${line}` : ">").join("\n")}`);
    return [title, ...body, marker].join("\n\n");
}

function parseSections(text: string, title: string, marker = END_MARKER): Section[] | null {
    const blocks = text.trim().split("\n\n");
    if (blocks[0] !== title || blocks[blocks.length - 1] !== marker) return null;
    const sections: Section[] = [];
    for (const block of blocks.slice(1, -1)) {
        const [heading, ...lines] = block.split("\n");
        if (!heading.startsWith("## ") || lines.length === 0) return null;
        if (lines.some(line => line !== ">" && !line.startsWith("> "))) return null;
        sections.push({ label: heading.slice(3), value: lines.map(line => line === ">" ? "" : line.slice(2)).join("\n") });
    }
    return sections;
}

export function serializeThreatModel(model: ThreatModel, referencedIds: readonly string[] = []): string {
    const hasContent = THREAT_MODEL_FIELDS.some(field => model[field.key].trim())
        || model.notes.trim() || model.threats.some(threat => threat.description.trim())
        || model.components.some(component => COMPONENT_FIELDS.some(field => component[field.key].trim()))
        || model.interactions.some(interaction => INTERACTION_FIELDS.some(field => interaction[field.key].trim()));
    if (!hasContent) return "";
    const sections: Section[] = THREAT_MODEL_FIELDS.map(field => ({ label: field.label, value: model[field.key] }));
    const targets = model.threats.flatMap(threat => threat.targetIds ?? []);
    const componentReferences = [...targets,
        ...model.interactions.flatMap(interaction => [interaction.sourceId, interaction.destinationId])];
    const components = model.components.filter(component => componentReferences.includes(component.id)
        || COMPONENT_FIELDS.some(field => component[field.key].trim()));
    const interactions = model.interactions.filter(interaction => targets.includes(interaction.id)
        || INTERACTION_FIELDS.some(field => interaction[field.key].trim()));
    const hasSystem = components.length > 0 || interactions.length > 0 || targets.length > 0;
    components.forEach((component, index) => {
        sections.push({ label: `Component ${index + 1} / ID`, value: component.id },
            ...COMPONENT_FIELDS.map(field => ({
                label: `Component ${index + 1} / ${field.label}`, value: component[field.key],
            })));
    });
    interactions.forEach((interaction, index) => {
        sections.push({ label: `Interaction ${index + 1} / ID`, value: interaction.id },
            ...INTERACTION_FIELDS.map(field => ({
                label: `Interaction ${index + 1} / ${field.label}`, value: interaction[field.key],
            })));
    });
    model.threats.filter(threat => hasThreatDraft(threat) || referencedIds.includes(threat.id))
        .forEach((threat, index) => {
        sections.push(
            { label: `Threat ${index + 1} / ID`, value: threat.id },
            { label: `Threat ${index + 1} / STRIDE category`, value: threat.category },
            { label: `Threat ${index + 1} / Description`, value: threat.description },
        );
        if (hasSystem) sections.push({
            label: `Threat ${index + 1} / Affected system elements`, value: (threat.targetIds ?? []).join("\n"),
        });
    });
    sections.push({ label: "Additional threat model notes", value: model.notes });
    return serializeSections(MODEL_TITLE, sections, hasSystem ? SYSTEM_END_MARKER : END_MARKER);
}

export function parseThreatModel(text: string): ThreatModel | null {
    if (!text.trim()) return emptyThreatModel();
    const hasSystem = text.trim().endsWith(SYSTEM_END_MARKER);
    const marker = hasSystem ? SYSTEM_END_MARKER : END_MARKER;
    const sections = parseSections(text, MODEL_TITLE, marker);
    if (!sections || sections.length < THREAT_MODEL_FIELDS.length + 1) return null;
    const model = emptyThreatModel();
    for (const [index, field] of THREAT_MODEL_FIELDS.entries()) {
        if (sections[index].label !== field.label) return null;
        model[field.key] = sections[index].value;
    }
    const notes = sections[sections.length - 1];
    if (notes.label !== "Additional threat model notes") return null;
    model.notes = notes.value;
    let entries = sections.slice(THREAT_MODEL_FIELDS.length, -1);
    if (hasSystem) {
        let offset = 0;
        while (entries[offset]?.label.startsWith("Component ")) {
            const number = model.components.length + 1;
            const row = entries.slice(offset, offset + COMPONENT_FIELDS.length + 1);
            const labels = ["ID", ...COMPONENT_FIELDS.map(field => field.label)];
            if (row.length !== labels.length
                || row.some((section, index) => section.label !== `Component ${number} / ${labels[index]}`)
                || !/^C[1-9][0-9]*$/.test(row[0].value)
                || model.components.some(component => component.id === row[0].value)) return null;
            model.components.push({
                id: row[0].value, name: row[1].value, description: row[2].value, trustZone: row[3].value,
            });
            offset += labels.length;
        }
        while (entries[offset]?.label.startsWith("Interaction ")) {
            const number = model.interactions.length + 1;
            const row = entries.slice(offset, offset + INTERACTION_FIELDS.length + 1);
            const labels = ["ID", ...INTERACTION_FIELDS.map(field => field.label)];
            if (row.length !== labels.length
                || row.some((section, index) => section.label !== `Interaction ${number} / ${labels[index]}`)
                || !/^I[1-9][0-9]*$/.test(row[0].value)
                || model.interactions.some(interaction => interaction.id === row[0].value)
                || [row[2].value, row[3].value].some(value => value !== "" && !/^C[1-9][0-9]*$/.test(value))) return null;
            model.interactions.push({
                id: row[0].value, name: row[1].value, sourceId: row[2].value, destinationId: row[3].value,
                protocol: row[4].value, description: row[5].value, trustBoundary: row[6].value,
            });
            offset += labels.length;
        }
        entries = entries.slice(offset);
    }
    // Previously saved category text areas become individual threats without rewriting the stored text on load.
    if (!hasSystem && entries.length === STRIDE_CATEGORIES.length && entries.every((section, index) =>
        section.label === `${STRIDE_CATEGORIES[index].letter} - ${STRIDE_CATEGORIES[index].name}`)) {
        for (const [index, section] of entries.entries()) {
            if (section.value) model.threats.push({
                id: `T${model.threats.length + 1}`, category: STRIDE_CATEGORIES[index].name, description: section.value,
            });
        }
        return serializeSections(MODEL_TITLE, sections) === text.trim()
            && Boolean(serializeThreatModel(model, model.threats.map(threat => threat.id))) ? model : null;
    }
    const hasIds = hasSystem || entries[0]?.label === "Threat 1 / ID";
    const width = hasSystem ? 4 : hasIds ? 3 : 2;
    if (entries.length % width !== 0) return null;
    for (let offset = 0; offset < entries.length; offset += width) {
        const number = model.threats.length + 1;
        const id = hasIds ? entries[offset].value : `T${number}`;
        const category = entries[offset + (hasIds ? 1 : 0)];
        const description = entries[offset + (hasIds ? 2 : 1)];
        if (hasIds && entries[offset].label !== `Threat ${number} / ID`) return null;
        if (category.label !== `Threat ${number} / STRIDE category`
            || description.label !== `Threat ${number} / Description` || !isCategory(category.value)
            || !isThreatId(id) || model.threats.some(threat => threat.id === id)) return null;
        const targetSection = hasSystem ? entries[offset + 3] : undefined;
        const targetIds = targetSection?.value ? targetSection.value.split("\n") : [];
        if (hasSystem && (targetSection?.label !== `Threat ${number} / Affected system elements`
            || targetIds.some(value => !/^[CI][1-9][0-9]*$/.test(value))
            || new Set(targetIds).size !== targetIds.length)) return null;
        model.threats.push({
            id, category: category.value, description: description.value,
            ...(targetIds.length ? { targetIds } : {}),
        });
    }
    return serializeSections(MODEL_TITLE, sections, marker) === text.trim() ? model : null;
}

export function serializeRiskRegister(register: RiskRegister): string {
    const risks = register.risks.filter(hasRiskContent);
    const sections = risks.flatMap((risk, index) => {
        const fields: Section[] = risk.legacyThreat ? [
            { label: "STRIDE category", value: risk.legacyThreat.category },
            { label: "Threat scenario", value: risk.legacyThreat.description },
            ...RISK_FIELDS.slice(1).map(field => ({ label: field.label, value: risk[field.key] })),
        ] : RISK_FIELDS.map(field => ({ label: field.label, value: risk[field.key] }));
        return fields.map(field => ({ ...field, label: `Risk ${index + 1} / ${field.label}` }));
    });
    sections.push({ label: "Additional risk notes", value: register.notes });
    return serializeSections(RISKS_TITLE, sections);
}

function isCategory(value: string): value is StrideThreat["category"] {
    return value === "" || STRIDE_CATEGORIES.some(category => category.name === value);
}

function isThreatId(value: string): boolean {
    return /^T[1-9][0-9]*$/.test(value);
}

function isRating(value: string): value is RiskRating {
    return value === "" || value === "Low" || value === "Medium" || value === "High";
}

export function parseRiskRegister(text: string): RiskRegister | null {
    if (!text.trim()) return { risks: [emptyRisk()], notes: "" };
    const sections = parseSections(text, RISKS_TITLE);
    if (!sections || sections.length === 0) return null;
    const notes = sections[sections.length - 1];
    if (notes.label !== "Additional risk notes") return null;
    const risks: StrideRisk[] = [];
    for (let offset = 0; offset < sections.length - 1;) {
        const legacy = sections[offset].label === `Risk ${risks.length + 1} / STRIDE category`;
        const labels = legacy ? ["STRIDE category", "Threat scenario", ...RISK_FIELDS.slice(1).map(field => field.label)]
            : RISK_FIELDS.map(field => field.label);
        const row = sections.slice(offset, offset + labels.length);
        if (row.length !== labels.length) return null;
        if (row.some((section, index) =>
            section.label !== `Risk ${risks.length + 1} / ${labels[index]}`)) return null;
        const values = row.map(section => section.value);
        const start = legacy ? 2 : 1;
        const [likelihood, impact, mitigation, decision] = values.slice(start);
        if (!isRating(likelihood) || !isRating(impact)) return null;
        const risk = { ...emptyRisk(), likelihood, impact, mitigation, decision };
        if (legacy) {
            if (!isCategory(values[0])) return null;
            risks.push({ ...risk, legacyThreat: { category: values[0], description: values[1] } });
        } else {
            if (values[0] && !isThreatId(values[0])) return null;
            risks.push({ ...risk, threatId: values[0] });
        }
        offset += labels.length;
    }
    const register = { risks, notes: notes.value };
    return serializeRiskRegister(register) === text.trim() ? register : null;
}

export function loadStrideContext(text: StrideContextText) {
    const model = parseThreatModel(text.threatModel);
    const register = parseRiskRegister(text.risks);
    const risks = register?.risks.map(risk => {
        if (!risk.legacyThreat?.description) return risk;
        const matches = model?.threats.filter(threat => threat.category === risk.legacyThreat?.category
            && threat.description === risk.legacyThreat.description) ?? [];
        if (matches.length !== 1) return risk;
        return {
            threatId: matches[0].id, likelihood: risk.likelihood, impact: risk.impact,
            mitigation: risk.mitigation, decision: risk.decision,
        };
    });
    const loadedModel = model ?? { ...emptyThreatModel(), notes: text.threatModel };
    const loadedRegister = register && risks ? { ...register, risks } : { risks: [emptyRisk()], notes: text.risks };
    return {
        mode: model && register ? "stride" as const : "free" as const,
        model: loadedModel.threats.length ? loadedModel : {
            ...loadedModel, threats: [emptyThreat(nextThreatId(loadedModel, loadedRegister))],
        },
        register: loadedRegister,
    };
}
