import { emptyThreatModel } from "./strideContext";
import type {
    StrideDraft, StrideEditorMode, StrideRisk, StrideThreat, SystemComponent, SystemInteraction,
} from "./strideContext";

export type SharedSection = "context" | "system" | "threat_model" | "risks";
export type Scoped<T> = T & { variant_ids: string[] };
export type ScopedText = Scoped<{ id: string; value: string }>;
export type TextField = "variant_description" | "codebase_path" | "environment" | "other_info"
    | "scope" | "actors" | "entry_points" | "trust_boundaries";
export type TextCollection = "threat_notes" | "risk_notes" | "free_threat_model" | "free_risks";
export type SharedContext = {
    editor_mode: StrideEditorMode;
    fields: Record<TextField, ScopedText[]>;
    components: Scoped<SystemComponent>[];
    interactions: Scoped<SystemInteraction>[];
    threats: Scoped<StrideThreat & { targetIds: string[] }>[];
    risks: Scoped<StrideRisk & { id: string }>[];
} & Record<TextCollection, ScopedText[]>;
export type VariantChoice = { id: string; name: string };
export type SharedContextResponse = {
    project_id: string; description: string | null; revision: number;
    context: SharedContext; variants: VariantChoice[];
};
export type SavePreview = { changed_variant_ids: string[]; description_changed: boolean };

export const CONTEXT_FIELDS = ["variant_description", "codebase_path", "environment", "other_info"] as const;
export const SYSTEM_FIELDS = ["scope", "actors", "entry_points", "trust_boundaries"] as const;
export const COLLECTIONS = [
    "components", "interactions", "threats", "risks", "threat_notes", "risk_notes", "free_threat_model", "free_risks",
] as const;

export function emptySharedContext(): SharedContext {
    return {
        editor_mode: "stride", fields: {
            variant_description: [], codebase_path: [], environment: [], other_info: [],
            scope: [], actors: [], entry_points: [], trust_boundaries: [],
        }, components: [], interactions: [], threats: [], risks: [], threat_notes: [], risk_notes: [],
        free_threat_model: [], free_risks: [],
    };
}

export function nextSharedId(prefix: string, documents: SharedContext[], reserved: string[] = []): string {
    const used = new Set([...reserved, ...documents.flatMap(document => [
        ...Object.values(document.fields).flat().map(row => row.id),
        ...COLLECTIONS.flatMap(key => document[key].map(row => row.id)),
        ...document.threats.flatMap(row => row.targetIds),
        ...document.risks.map(row => row.threatId),
        ...document.interactions.flatMap(row => [row.sourceId, row.destinationId]),
    ])]);
    let number = 1;
    while (used.has(`${prefix}${number}`)) number++;
    return `${prefix}${number}`;
}

export function sharedDraft(document: SharedContext): StrideDraft {
    const model = {
        ...emptyThreatModel(), components: document.components,
        interactions: document.interactions, threats: document.threats,
        notes: document.threat_notes.map(row => row.value).join("\n\n"),
    };
    for (const key of SYSTEM_FIELDS) model[key] = document.fields[key].map(row => row.value).join("\n\n");
    return { mode: document.editor_mode, model, register: {
        risks: document.risks, notes: document.risk_notes.map(row => row.value).join("\n\n"),
    } };
}

export function updateSharedDraft(
    document: SharedContext, draft: StrideDraft, variants: VariantChoice[], saved: SharedContext = document,
): SharedContext {
    const scope = variants.map(variant => variant.id);
    let reserved = document;
    return {
        ...document,
        components: draft.model.components.map(row => ({
            ...row, variant_ids: document.components.find(saved => saved.id === row.id)?.variant_ids ?? scope,
        })),
        interactions: draft.model.interactions.map(row => ({
            ...row, variant_ids: document.interactions.find(saved => saved.id === row.id)?.variant_ids ?? scope,
        })),
        threats: draft.model.threats.map(row => ({
            ...row, targetIds: row.targetIds ?? [],
            variant_ids: document.threats.find(saved => saved.id === row.id)?.variant_ids
                ?? document.risks.find(previous => previous.legacyThreat && draft.register.risks.some(risk =>
                    risk.threatId === row.id && "id" in risk && risk.id === previous.id))?.variant_ids ?? scope,
        })),
        risks: draft.register.risks.map(row => {
            // Controlled risk rows retain identity even when an earlier row is removed.
            const previous = "id" in row ? document.risks.find(saved => saved.id === row.id) : undefined;
            const id = previous?.id ?? nextSharedId("R", [reserved, saved]);
            const threatScope = document.threats.find(threat => threat.id === row.threatId)?.variant_ids;
            let targets = previous?.variant_ids ?? scope;
            if (threatScope && previous?.threatId !== row.threatId) {
                const intersection = targets.filter(target => threatScope.includes(target));
                targets = intersection.length ? intersection : threatScope;
            }
            const result = { ...row, id, variant_ids: targets };
            reserved = { ...reserved, risks: [...reserved.risks, result] };
            return result;
        }),
    };
}

export function mergeSavedSection(draft: SharedContext, saved: SharedContext, section: SharedSection): SharedContext {
    const fields = section === "context" ? CONTEXT_FIELDS : section === "system" ? SYSTEM_FIELDS : [];
    const sectionCollections: Record<SharedSection, readonly (typeof COLLECTIONS)[number][]> = {
        context: [], system: ["components", "interactions"],
        threat_model: ["threats", "threat_notes", "free_threat_model"],
        risks: ["risks", "risk_notes", "free_risks"],
    };
    const collections = sectionCollections[section];
    const result = { ...draft, fields: { ...draft.fields } };
    for (const key of fields) result.fields[key] = saved.fields[key];
    return { ...result, ...Object.fromEntries(collections.map(key => [key, saved[key]])) };
}
