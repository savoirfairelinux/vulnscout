import type { AiContextDraftValues, VariantDraft } from "../handlers/context";

type TextKey = 'variant_description' | 'environment' | 'other_info';
type SystemKey = keyof VariantDraft['system'];
type Section = keyof VariantDraft['stride'];

const TEXTS: [TextKey, string][] = [
    ['variant_description', 'Variant description'], ['environment', 'Environment'], ['other_info', 'Other information'],
];
const SYSTEM: [SystemKey, string][] = [
    ['scope', 'System scope'], ['actors', 'System actors'],
    ['entry_points', 'System entry points'], ['trust_boundaries', 'System trust boundaries'],
];
const SECTIONS: [Section, string][] = [
    ['components', 'component'], ['interactions', 'interaction'], ['threats', 'threat'], ['risks', 'risk'],
];

/** Queue key of the "Fill from document" action of a variant. */
export const contextImportKey = (variantId: string) => `context-import:${variantId}`;

/** The request the embedded agent receives for a "Fill from document" action. */
export function contextImportMessage({ projectId, projectName, variantId, variantName, fileName }: Readonly<{
    projectId: string; projectName: string; variantId: string; variantName: string; fileName: string;
}>): string {
    return [
        `Fill the threat model of variant "${variantName}" (variant_id ${variantId}) in project "${projectName}" (project_id ${projectId}) from the document "${fileName}".`,
        "Follow the ai-context-import skill in embedded mode: the document is this variant's import source, so read it with read_import_source.",
        'Store the result with propose_variant_threat_model. Never save the context: the user reviews the draft on the AI Context page, then saves or discards it.',
    ].join('\n');
}

/**
 * The editor draft an AI draft turns into: null Context texts keep the saved
 * value, and the codebase settings always come from the saved context.
 */
export function applyAiDraft(baseline: VariantDraft, values: AiContextDraftValues): VariantDraft {
    return {
        ...baseline,
        variant_description: values.variant_description ?? baseline.variant_description,
        environment: values.environment ?? baseline.environment,
        other_info: values.other_info ?? baseline.other_info,
        system: {
            scope: values.system.scope ?? '',
            actors: values.system.actors ?? '',
            entry_points: values.system.entry_points ?? '',
            trust_boundaries: values.system.trust_boundaries ?? '',
        },
        // Same key order as draftFromContext, so draftsEqual sees a no-op draft as equal.
        stride: {
            components: values.stride.components.map(row => ({ ...row })),
            interactions: values.stride.interactions.map(row => ({ ...row })),
            threats: values.stride.threats.map(row => ({ ...row, target_ids: [...row.target_ids] })),
            risks: values.stride.risks.map(row => ({ ...row, threat_ids: [...row.threat_ids] })),
        },
    };
}

/** "+2 components, ~1 risk (changes to Environment)": rows compared by id, then changed fields. */
export function draftChangeSummary(baseline: VariantDraft, draft: VariantDraft): string {
    const counts = SECTIONS.flatMap(([section, noun]) => {
        const before = new Map<string, string>(baseline.stride[section].map(row => [row.id, JSON.stringify(row)]));
        const after = new Map<string, string>(draft.stride[section].map(row => [row.id, JSON.stringify(row)]));
        const added = [...after.keys()].filter(id => !before.has(id)).length;
        const changed = [...after].filter(([id, row]) => before.has(id) && before.get(id) !== row).length;
        const removed = [...before.keys()].filter(id => !after.has(id)).length;
        const label = (n: number) => `${n} ${n === 1 ? noun : `${noun}s`}`;
        return [
            ...(added ? [`+${label(added)}`] : []),
            ...(changed ? [`~${label(changed)}`] : []),
            ...(removed ? [`-${label(removed)}`] : []),
        ];
    });
    const fields = [
        ...TEXTS.filter(([key]) => baseline[key] !== draft[key]).map(([, label]) => label),
        ...SYSTEM.filter(([key]) => baseline.system[key] !== draft.system[key]).map(([, label]) => label),
    ];
    const changes = fields.length ? `changes to ${fields.join(', ')}` : '';
    if (!counts.length) return changes || 'no changes';
    return changes ? `${counts.join(', ')} (${changes})` : counts.join(', ');
}
