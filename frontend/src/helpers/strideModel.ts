import type {
    MergedContext, Rating, StrideModel, SystemFields, VariantDraft,
} from '../handlers/context';
import { splitCodebasePaths } from '../handlers/context';

export const STRIDE_CATEGORIES: readonly {
    key: string; label: string; letter: 'S' | 'T' | 'R' | 'I' | 'D' | 'E';
}[] = [
    { key: 'spoofing', label: 'Spoofing', letter: 'S' },
    { key: 'tampering', label: 'Tampering', letter: 'T' },
    { key: 'repudiation', label: 'Repudiation', letter: 'R' },
    { key: 'information_disclosure', label: 'Information disclosure', letter: 'I' },
    { key: 'denial_of_service', label: 'Denial of service', letter: 'D' },
    { key: 'elevation_of_privilege', label: 'Elevation of privilege', letter: 'E' },
];

export const RATING_OPTIONS: readonly {
    value: Rating; label: 'Not rated' | 'Low' | 'Medium' | 'High';
}[] = [
    { value: null, label: 'Not rated' },
    { value: 'low', label: 'Low' },
    { value: 'medium', label: 'Medium' },
    { value: 'high', label: 'High' },
];

const SYSTEM_KEYS: (keyof SystemFields)[] = ['scope', 'actors', 'entry_points', 'trust_boundaries'];

export function emptyStrideModel(): StrideModel {
    return { components: [], interactions: [], threats: [], risks: [] };
}

export function emptyDraft(): VariantDraft {
    return {
        variant_description: '',
        environment: '',
        other_info: '',
        codebase_source: 'references',
        codebase_paths: [],
        system: { scope: '', actors: '', entry_points: '', trust_boundaries: '' },
        stride: emptyStrideModel(),
    };
}

function cloneStride(model: StrideModel): StrideModel {
    return {
        components: model.components.map(c => ({ ...c })),
        interactions: model.interactions.map(i => ({ ...i })),
        threats: model.threats.map(t => ({ ...t, target_ids: [...t.target_ids] })),
        risks: model.risks.map(r => ({ ...r })),
    };
}

export function draftFromContext(ctx: MergedContext): VariantDraft {
    const editor = ctx.editor;
    return {
        variant_description: ctx.variant_description ?? '',
        environment: ctx.environment ?? '',
        other_info: ctx.other_info ?? '',
        codebase_source: editor.codebase_source,
        codebase_paths: splitCodebasePaths(editor.codebase_path),
        system: {
            scope: editor.system.scope ?? '',
            actors: editor.system.actors ?? '',
            entry_points: editor.system.entry_points ?? '',
            trust_boundaries: editor.system.trust_boundaries ?? '',
        },
        stride: cloneStride(editor.stride),
    };
}

/** Structural equality; drafts are plain JSON-like data. */
export function draftsEqual(a: VariantDraft, b: VariantDraft): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
}

/** Next free id for the prefix: max numeric suffix over rows and reserved ids, plus one. */
export function nextId(rows: { id: string }[], prefix: 'C' | 'I' | 'T', reserved: string[] = []): string {
    const pattern = new RegExp(`^${prefix}(\\d+)$`);
    const max = [...rows.map(r => r.id), ...reserved].reduce((acc, id) => {
        const match = pattern.exec(id);
        return match ? Math.max(acc, Number(match[1])) : acc;
    }, 0);
    return `${prefix}${max + 1}`;
}

export function isReferenced(model: StrideModel, id: string): boolean {
    return (
        model.interactions.some(i => i.source_id === id || i.destination_id === id) ||
        model.threats.some(t => t.target_ids.includes(id)) ||
        model.risks.some(r => r.threat_id === id)
    );
}

const hasText = (value: string): boolean => value.trim() !== '';

/** Mirrors the server: whether the STRIDE threat model renders to non-empty text. */
export function hasThreatModel(draft: VariantDraft): boolean {
    const { components, interactions, threats } = draft.stride;
    return (
        SYSTEM_KEYS.some(key => hasText(draft.system[key])) ||
        components.length > 0 ||
        interactions.length > 0 ||
        threats.length > 0
    );
}

/** Field path -> message for every blank required STRIDE field (paths match the server's). */
export function requiredFieldErrors(model: StrideModel): Record<string, string> {
    const errors: Record<string, string> = {};
    model.components.forEach((c, i) => {
        if (!hasText(c.name)) errors[`components[${i}].name`] = 'Enter a component name.';
    });
    model.interactions.forEach((row, i) => {
        if (!hasText(row.source_id)) errors[`interactions[${i}].source_id`] = 'Select a source component.';
        if (!hasText(row.destination_id)) errors[`interactions[${i}].destination_id`] = 'Select a destination component.';
    });
    model.threats.forEach((t, i) => {
        if (!hasText(t.category)) errors[`threats[${i}].category`] = 'Select a STRIDE category.';
        if (t.target_ids.length === 0) errors[`threats[${i}].target_ids`] = 'Select at least one target.';
    });
    model.risks.forEach((r, i) => {
        if (!hasText(r.threat_id)) errors[`risks[${i}].threat_id`] = 'Select a threat.';
    });
    return errors;
}
