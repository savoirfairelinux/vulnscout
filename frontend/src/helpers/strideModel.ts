import type {
    EditorMode, MergedContext, Rating, StrideModel, SystemFields, VariantDraft,
} from '../handlers/context';

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
    return { components: [], interactions: [], threats: [], notes: '', risks: [], risk_notes: '' };
}

export function emptyDraft(): VariantDraft {
    return {
        variant_description: '',
        environment: '',
        other_info: '',
        editor_mode: 'stride',
        codebase_source: 'paths',
        codebase_path: '',
        free: { threat_model: '', risks: '' },
        system: { scope: '', actors: '', entry_points: '', trust_boundaries: '' },
        stride: emptyStrideModel(),
    };
}

function cloneStride(model: StrideModel): StrideModel {
    return {
        components: model.components.map(c => ({ ...c })),
        interactions: model.interactions.map(i => ({ ...i })),
        threats: model.threats.map(t => ({ ...t, target_ids: [...t.target_ids] })),
        notes: model.notes,
        risks: model.risks.map(r => ({ ...r })),
        risk_notes: model.risk_notes,
    };
}

export function draftFromContext(ctx: MergedContext): VariantDraft {
    const editor = ctx.editor;
    return {
        variant_description: ctx.variant_description ?? '',
        environment: ctx.environment ?? '',
        other_info: ctx.other_info ?? '',
        editor_mode: editor.editor_mode,
        codebase_source: editor.codebase_source,
        codebase_path: editor.codebase_path ?? '',
        free: {
            threat_model: editor.free.threat_model ?? '',
            risks: editor.free.risks ?? '',
        },
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

/** Mirrors the server: whether the active mode's threat model renders to non-empty text. */
export function hasThreatModel(draft: VariantDraft): boolean {
    if (draft.editor_mode === 'free') return hasText(draft.free.threat_model);
    const { components, interactions, threats, notes } = draft.stride;
    return (
        SYSTEM_KEYS.some(key => hasText(draft.system[key])) ||
        components.length > 0 ||
        interactions.length > 0 ||
        threats.length > 0 ||
        hasText(notes)
    );
}

/** Switch mode; entering an empty STRIDE model seeds its notes from the free text. Free text is kept. */
export function switchEditorMode(draft: VariantDraft, mode: EditorMode): VariantDraft {
    if (mode === 'stride' && !hasThreatModel({ ...draft, editor_mode: 'stride' }) &&
        draft.stride.risks.length === 0 && !hasText(draft.stride.risk_notes)) {
        return {
            ...draft,
            editor_mode: mode,
            stride: { ...draft.stride, notes: draft.free.threat_model, risk_notes: draft.free.risks },
        };
    }
    return { ...draft, editor_mode: mode };
}
