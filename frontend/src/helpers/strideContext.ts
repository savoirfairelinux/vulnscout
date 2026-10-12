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
        help: "Describe interfaces and how data moves between components. Refer to your data-flow diagram if available.",
        placeholder: "Mobile app -> HTTPS API -> device; updates arrive over the network; local UART debug port." },
    { key: "trust_boundaries", label: "Trust boundaries",
        help: "Where does data or control cross between different levels of trust?",
        placeholder: "Public network -> authenticated API; unprivileged application -> privileged update service." },
] as const;

export type StrideCategory = (typeof STRIDE_CATEGORIES)[number]["name"];
export type StrideThreat = { id: string; category: "" | StrideCategory; description: string };
export type ThreatModel = Record<(typeof THREAT_MODEL_FIELDS)[number]["key"], string> & {
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
const MODEL_TITLE = "# STRIDE threat model";
const RISKS_TITLE = "# STRIDE risk register";

export function emptyThreatModel(): ThreatModel {
    return {
        scope: "", actors: "", entry_points: "", trust_boundaries: "", threats: [], notes: "",
    };
}

export function emptyThreat(id: string): StrideThreat {
    return { id, category: "", description: "" };
}

export function emptyRisk(): StrideRisk {
    return { threatId: "", likelihood: "", impact: "", mitigation: "", decision: "" };
}

export function nextThreatId(model: ThreatModel, register: RiskRegister): string {
    const used = new Set([...model.threats.map(threat => threat.id), ...register.risks.map(risk => risk.threatId)]);
    let number = 1;
    while (used.has(`T${number}`)) number++;
    return `T${number}`;
}

type Section = { label: string; value: string };

function serializeSections(title: string, sections: Section[]): string {
    if (!sections.some(section => section.value.trim())) return "";
    // Quoted lines keep user-supplied headings and blank lines out of the template delimiters.
    const body = sections.map(section =>
        `## ${section.label}\n${section.value.split("\n").map(line => line ? `> ${line}` : ">").join("\n")}`);
    return [title, ...body, END_MARKER].join("\n\n");
}

function parseSections(text: string, title: string): Section[] | null {
    const blocks = text.trim().split("\n\n");
    if (blocks[0] !== title || blocks[blocks.length - 1] !== END_MARKER) return null;
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
        || model.notes.trim() || model.threats.some(threat => threat.description.trim());
    if (!hasContent) return "";
    const sections: Section[] = THREAT_MODEL_FIELDS.map(field => ({ label: field.label, value: model[field.key] }));
    model.threats.filter(threat => threat.category || threat.description.trim() || referencedIds.includes(threat.id))
        .forEach((threat, index) => {
        sections.push(
            { label: `Threat ${index + 1} / ID`, value: threat.id },
            { label: `Threat ${index + 1} / STRIDE category`, value: threat.category },
            { label: `Threat ${index + 1} / Description`, value: threat.description },
        );
    });
    sections.push({ label: "Additional threat model notes", value: model.notes });
    return serializeSections(MODEL_TITLE, sections);
}

export function parseThreatModel(text: string): ThreatModel | null {
    if (!text.trim()) return emptyThreatModel();
    const sections = parseSections(text, MODEL_TITLE);
    if (!sections || sections.length < THREAT_MODEL_FIELDS.length + 1) return null;
    const model = emptyThreatModel();
    for (const [index, field] of THREAT_MODEL_FIELDS.entries()) {
        if (sections[index].label !== field.label) return null;
        model[field.key] = sections[index].value;
    }
    const notes = sections[sections.length - 1];
    if (notes.label !== "Additional threat model notes") return null;
    model.notes = notes.value;
    const entries = sections.slice(THREAT_MODEL_FIELDS.length, -1);
    // Previously saved category text areas become individual threats without rewriting the stored text on load.
    if (entries.length === STRIDE_CATEGORIES.length && entries.every((section, index) =>
        section.label === `${STRIDE_CATEGORIES[index].letter} - ${STRIDE_CATEGORIES[index].name}`)) {
        for (const [index, section] of entries.entries()) {
            if (section.value) model.threats.push({
                id: `T${model.threats.length + 1}`, category: STRIDE_CATEGORIES[index].name, description: section.value,
            });
        }
        return serializeSections(MODEL_TITLE, sections) === text.trim()
            && Boolean(serializeThreatModel(model, model.threats.map(threat => threat.id))) ? model : null;
    }
    const hasIds = entries[0]?.label === "Threat 1 / ID";
    const width = hasIds ? 3 : 2;
    if (entries.length % width !== 0) return null;
    for (let offset = 0; offset < entries.length; offset += width) {
        const number = model.threats.length + 1;
        const id = hasIds ? entries[offset].value : `T${number}`;
        const category = entries[offset + (hasIds ? 1 : 0)];
        const description = entries[offset + width - 1];
        if (hasIds && entries[offset].label !== `Threat ${number} / ID`) return null;
        if (category.label !== `Threat ${number} / STRIDE category`
            || description.label !== `Threat ${number} / Description` || !isCategory(category.value)
            || !isThreatId(id) || model.threats.some(threat => threat.id === id)) return null;
        model.threats.push({ id, category: category.value, description: description.value });
    }
    return serializeSections(MODEL_TITLE, sections) === text.trim() ? model : null;
}

export function serializeRiskRegister(register: RiskRegister): string {
    const risks = register.risks.filter(risk => RISK_FIELDS.some(field => risk[field.key].trim())
        || risk.legacyThreat?.category || risk.legacyThreat?.description.trim());
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
