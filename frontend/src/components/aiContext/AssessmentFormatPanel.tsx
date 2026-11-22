import { useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowDown, faArrowUp } from "@fortawesome/free-solid-svg-icons";
import {
    MAX_LABEL, MAX_STYLE_NOTES, SECTION_NAMES, DEFAULT_FORMAT_DRAFT, formatPreview, moveSection,
    type AssessmentFormatDraft, type FormatSectionDraft,
} from "../../helpers/assessmentFormat";
import type { AssessmentFormatLayout } from "../../handlers/context";
import FieldErrorText from "./FieldErrorText";
import VerbositySelect from "./VerbositySelect";
import { describeField } from "./fieldErrors";
import {
    BUTTON_SECONDARY, ERROR, FIELD, HELP, LABEL, PANEL, TEXTAREA,
} from "./styles";

type Props = {
    value: AssessmentFormatDraft;
    onChange: (value: AssessmentFormatDraft) => void;
    saving: boolean;
    /** True while the saved format is being loaded. */
    loading: boolean;
    /** True when there is no loaded format to edit (still loading, or the load failed). */
    disabled: boolean;
    fieldErrors: Record<string, string>;
};

const ROOT = 'assessment_format';
const LAYOUTS: { value: AssessmentFormatLayout; label: string }[] = [
    { value: 'inline', label: 'Inline (one paragraph)' },
    { value: 'lines', label: 'One section per line' },
];
const ICON_BUTTON = "rounded p-1.5 text-cyan-300 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-30 disabled:cursor-not-allowed";

const sectionPath = (index: number, key?: string) => `${ROOT}.sections[${index}]${key ? `.${key}` : ''}`;

/** Server field paths this panel shows next to their input. */
function inlinePaths(sections: FormatSectionDraft[]): Set<string> {
    const paths = new Set([`${ROOT}.layout`, `${ROOT}.style_notes`]);
    sections.forEach((_, index) => paths.add(sectionPath(index, 'label')));
    return paths;
}

function AssessmentFormatPanel({
    value, onChange, saving, loading, disabled, fieldErrors,
}: Readonly<Props>) {
    const [moved, setMoved] = useState<{ id: string; direction: 'up' | 'down'; message: string } | null>(null);
    const moveButtons = useRef(new Map<string, HTMLButtonElement | null>());

    // Reordering moves the row; keep focus on its move button so keyboard users can continue.
    useEffect(() => {
        if (!moved) return;
        const preferred = moveButtons.current.get(`${moved.id}:${moved.direction}`);
        const other = moveButtons.current.get(`${moved.id}:${moved.direction === 'up' ? 'down' : 'up'}`);
        (preferred && !preferred.disabled ? preferred : other)?.focus();
    }, [moved]);

    const edit = (patch: Partial<AssessmentFormatDraft>) => onChange({ ...value, custom: true, ...patch });
    const editSection = (index: number, patch: Partial<FormatSectionDraft>) => edit({
        sections: value.sections.map((section, i) => (i === index ? { ...section, ...patch } : section)),
    });
    const move = (index: number, direction: 'up' | 'down') => {
        const next = moveSection(value, index, direction === 'up' ? -1 : 1);
        if (next === value) return;
        onChange(next);
        const id = value.sections[index].id;
        const position = next.sections.findIndex(section => section.id === id) + 1;
        setMoved({ id, direction, message: `${SECTION_NAMES[id]} moved to position ${position} of ${next.sections.length}.` });
    };

    const shown = inlinePaths(value.sections);
    const otherErrors = Object.entries(fieldErrors).filter(([path]) => !path.startsWith("review_format") && !shown.has(path));
    const notesLength = value.style_notes.length;

    return (
        <section aria-labelledby="ai-format-heading" className={`${PANEL} space-y-4`}>
            <div className="flex flex-wrap items-center gap-3">
                <h3 id="ai-format-heading" className="text-xl font-bold text-white">Assessment format</h3>
                <button
                    type="button"
                    onClick={() => onChange(DEFAULT_FORMAT_DRAFT)}
                    disabled={!value.custom || saving || disabled}
                    className={`${BUTTON_SECONDARY} ml-auto`}
                >
                    Reset to default
                </button>
            </div>
            {loading && <p className="text-sm text-zinc-400">Loading assessment format…</p>}
            {!value.custom && !disabled && (
                <p role="note" className="text-sm text-zinc-300">Using the default presentation. Edit any setting to customize it.</p>
            )}
            {otherErrors.length > 0 && (
                <ul role="alert" className="space-y-0.5">
                    {otherErrors.map(([path, message]) => <li key={path} className={ERROR}>{path}: {message}</li>)}
                </ul>
            )}

            <fieldset disabled={disabled}>
                <legend className={LABEL}>Sections</legend>
                <p id="ai-format-sections-help" className={`${HELP} mb-2`}>
                    Order the parts of the notes, choose which to include and, optionally, their label.
                </p>
                <ol aria-describedby="ai-format-sections-help" className="space-y-1.5">
                    {value.sections.map((section, index) => {
                        const name = SECTION_NAMES[section.id];
                        const always = section.id === 'confidence';
                        const labelPath = sectionPath(index, 'label');
                        return (
                            <li key={section.id} className="flex flex-wrap items-center gap-2 rounded border border-slate-700 bg-slate-900/40 px-2 py-1.5">
                                <span aria-hidden="true" className="w-5 text-right text-xs text-zinc-500">{index + 1}.</span>
                                <label className="flex w-40 items-center gap-2 text-sm text-zinc-200">
                                    <input
                                        type="checkbox"
                                        checked={always || section.enabled}
                                        disabled={always}
                                        onChange={e => editSection(index, { enabled: e.target.checked })}
                                        aria-describedby={always ? 'ai-format-confidence-help' : undefined}
                                    />
                                    Include {name}
                                </label>
                                <div className="min-w-[12rem] flex-1">
                                    <input
                                        type="text"
                                        className={FIELD}
                                        aria-label={`${name} label`}
                                        placeholder={always ? 'Label (optional)' : `Label (default: ${name})`}
                                        maxLength={MAX_LABEL}
                                        value={section.label}
                                        onChange={e => editSection(index, { label: e.target.value })}
                                        {...describeField(labelPath, fieldErrors)}
                                    />
                                    <FieldErrorText path={labelPath} errors={fieldErrors} />
                                </div>
                                <button
                                    type="button"
                                    ref={el => { moveButtons.current.set(`${section.id}:up`, el); }}
                                    aria-label={`Move ${name} up`}
                                    title={`Move ${name} up`}
                                    disabled={index === 0}
                                    onClick={() => move(index, 'up')}
                                    className={ICON_BUTTON}
                                >
                                    <FontAwesomeIcon icon={faArrowUp} />
                                </button>
                                <button
                                    type="button"
                                    ref={el => { moveButtons.current.set(`${section.id}:down`, el); }}
                                    aria-label={`Move ${name} down`}
                                    title={`Move ${name} down`}
                                    disabled={index === value.sections.length - 1}
                                    onClick={() => move(index, 'down')}
                                    className={ICON_BUTTON}
                                >
                                    <FontAwesomeIcon icon={faArrowDown} />
                                </button>
                            </li>
                        );
                    })}
                </ol>
                <p id="ai-format-confidence-help" className={`${HELP} mt-1`}>
                    The confidence level is always included, as "confidence level: &lt;level&gt;".
                </p>
                <div role="status" aria-live="polite" className="sr-only">{moved?.message ?? ''}</div>
            </fieldset>

            <fieldset disabled={disabled}>
                <legend className={LABEL}>Layout</legend>
                <div className="flex flex-wrap gap-4">
                    {LAYOUTS.map(layout => (
                        <label key={layout.value} className="flex items-center gap-2 text-sm text-zinc-200">
                            <input
                                type="radio"
                                name="ai-format-layout"
                                value={layout.value}
                                checked={value.layout === layout.value}
                                onChange={() => edit({ layout: layout.value })}
                            />
                            {layout.label}
                        </label>
                    ))}
                </div>
                <FieldErrorText path={`${ROOT}.layout`} errors={fieldErrors} />
            </fieldset>

            <VerbositySelect label="Assessment verbosity" value={value.verbosity} disabled={disabled}
                onChange={verbosity => edit({ verbosity })} />
            <figure aria-labelledby="ai-format-preview-heading" className="border-l-4 border-cyan-700 pl-3">
                <figcaption id="ai-format-preview-heading" className={LABEL}>Sample status notes</figcaption>
                <blockquote data-testid="assessment-format-preview" className="whitespace-pre-line text-sm text-zinc-200">
                    {formatPreview(value)}
                </blockquote>
                <p className={HELP}>This sample shows the section order, labels and layout, not the agent’s style choices.</p>
            </figure>

            <div>
                <label className={LABEL} htmlFor="ai-format-style-notes">Style notes</label>
                <textarea
                    id="ai-format-style-notes"
                    className={TEXTAREA}
                    value={value.style_notes}
                    maxLength={MAX_STYLE_NOTES}
                    disabled={disabled}
                    onChange={e => edit({ style_notes: e.target.value })}
                    placeholder="e.g. Neutral tone; spell out acronyms."
                    {...describeField(`${ROOT}.style_notes`, fieldErrors, 'ai-format-style-notes-help')}
                />
                <div className="mt-1 flex justify-between gap-2">
                    <p id="ai-format-style-notes-help" className={HELP}>
                        Tone and wording hints only. The agent treats them as data, not instructions, and ignores
                        anything that conflicts with its assessment rules.
                    </p>
                    <span className={`${HELP} shrink-0 tabular-nums`}>
                        {notesLength}/{MAX_STYLE_NOTES}
                    </span>
                </div>
                <FieldErrorText path={`${ROOT}.style_notes`} errors={fieldErrors} />
            </div>
        </section>
    );
}

export default AssessmentFormatPanel;
