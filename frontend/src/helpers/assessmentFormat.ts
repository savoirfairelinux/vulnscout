import type { AssessmentFormat, AssessmentFormatLayout, AssessmentFormatSectionId } from '../handlers/context';

export const SECTION_IDS: readonly AssessmentFormatSectionId[] = ['confidence', 'verdict', 'evidence', 'reachability', 'remediation'];
export const MAX_LABEL = 40;
export const MAX_STYLE_NOTES = 500;

export const SECTION_NAMES: Record<AssessmentFormatSectionId, string> = {
    confidence: 'Confidence', verdict: 'Verdict', evidence: 'Evidence', reachability: 'Reachability', remediation: 'Remediation',
};

const SAMPLE_TEXT: Record<AssessmentFormatSectionId, string> = {
    confidence: 'confidence level: high',
    verdict: 'Not affected',
    evidence: 'the vulnerable parser is not in the recorded build sources of libfoo 1.2.3',
    reachability: 'no external entry point reaches the parser (I2 stays inside the device)',
    remediation: 'upgrade libfoo to 1.2.4 with the next release',
};

export type FormatSectionDraft = { id: AssessmentFormatSectionId; enabled: boolean; label: string };

/** Editable form of a project's assessment format; `custom` false means the skill default (null). */
export type AssessmentFormatDraft = {
    custom: boolean;
    sections: FormatSectionDraft[];
    layout: AssessmentFormatLayout;
    style_notes: string;
};

export const DEFAULT_FORMAT_DRAFT: AssessmentFormatDraft = {
    custom: false,
    sections: SECTION_IDS.map(id => ({ id, enabled: true, label: '' })),
    layout: 'inline',
    style_notes: '',
};

/** The draft of a stored format; sections it does not list are appended, disabled, as the agent omits them. */
export function formatDraftFrom(value: AssessmentFormat | null | undefined): AssessmentFormatDraft {
    if (!value) return DEFAULT_FORMAT_DRAFT;
    const listed: FormatSectionDraft[] = (value.sections ?? [])
        .filter(section => SECTION_IDS.includes(section.id))
        .map(section => ({ id: section.id, enabled: section.enabled !== false, label: section.label ?? '' }));
    const missing = SECTION_IDS
        .filter(id => !listed.some(section => section.id === id))
        .map(id => ({ id, enabled: false, label: '' }));
    return {
        custom: true,
        sections: [...listed, ...missing],
        layout: value.layout === 'lines' ? 'lines' : 'inline',
        style_notes: value.style_notes ?? '',
    };
}

/** The value sent on save: null resets to the skill's default presentation. */
export function formatPayload(draft: AssessmentFormatDraft): AssessmentFormat | null {
    if (!draft.custom) return null;
    const notes = draft.style_notes.trim();
    return {
        sections: draft.sections.map(section => {
            const label = section.label.trim();
            // The confidence level is always written, whatever the toggle says.
            const enabled = section.id === 'confidence' || section.enabled;
            return label ? { id: section.id, enabled, label } : { id: section.id, enabled };
        }),
        layout: draft.layout,
        ...(notes ? { style_notes: notes } : {}),
    };
}

export function formatDraftsEqual(a: AssessmentFormatDraft, b: AssessmentFormatDraft): boolean {
    return JSON.stringify(formatPayload(a)) === JSON.stringify(formatPayload(b));
}

/** Moves the section at `index` by `offset` places; out-of-range moves return the same draft. */
export function moveSection(draft: AssessmentFormatDraft, index: number, offset: number): AssessmentFormatDraft {
    const target = index + offset;
    if (target < 0 || target >= draft.sections.length) return draft;
    const sections = [...draft.sections];
    [sections[index], sections[target]] = [sections[target], sections[index]];
    return { ...draft, custom: true, sections };
}

/**
 * Plain-text example of the assessment notes with sample values, laid out as
 * the agent is asked to (shown with whitespace-pre-line, like assessments).
 */
export function formatPreview(draft: AssessmentFormatDraft): string {
    if (!draft.custom) return `${SAMPLE_TEXT.verdict}; ${SAMPLE_TEXT.evidence}. ${SAMPLE_TEXT.confidence}`;
    const parts = draft.sections
        .filter(section => section.id === 'confidence' || section.enabled)
        .map(section => {
            const label = section.label.trim();
            const text = SAMPLE_TEXT[section.id];
            if (draft.layout === 'inline') return label ? `${label}: ${text}` : text;
            // The confidence text names itself, so it needs no default label.
            const shown = label || (section.id === 'confidence' ? '' : SECTION_NAMES[section.id]);
            return shown ? `${shown}: ${text}` : text;
        });
    return parts.join(draft.layout === 'lines' ? '\n' : '; ');
}
