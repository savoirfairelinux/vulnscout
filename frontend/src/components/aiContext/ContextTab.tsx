import type { ContextFile, VariantDraft } from "../../handlers/context";
import { switchEditorMode } from "../../helpers/strideModel";
import CodebaseReferences from "../CodebaseReferences";
import { BUTTON_SECONDARY, ERROR, FIELD, HELP, LABEL, TEXTAREA } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    variantId: string;
    files: ContextFile[];
    notify: (message: string, type: 'success' | 'error') => void;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
};

type TextKey = 'variant_description' | 'environment' | 'other_info';
type Choice<T extends string> = { value: T; label: string };

const SOURCES: Choice<VariantDraft['codebase_source']>[] = [
    { value: 'references', label: 'Codebase references' },
    { value: 'paths', label: 'Codebase paths' },
];
const MODES: Choice<VariantDraft['editor_mode']>[] = [
    { value: 'stride', label: 'STRIDE' },
    { value: 'free', label: 'Free' },
];

const fieldId = (key: string) => `ai-variant-${key.replace(/_/g, '-')}`;

/** aria-invalid plus an aria-describedby list joining the field's error and help ids. */
function describe(key: string, errors: Record<string, string>, helpId?: string) {
    const error = errors[key];
    const ids = [error ? `${fieldId(key)}-error` : '', helpId ?? ''].filter(Boolean).join(' ');
    return { 'aria-invalid': error ? true : undefined, 'aria-describedby': ids || undefined };
}

function FieldError({ name, errors }: Readonly<{ name: string; errors: Record<string, string> }>) {
    const error = errors[name];
    return error ? <p id={`${fieldId(name)}-error`} className={`${ERROR} mt-1`}>{error}</p> : null;
}

function RadioGroup<T extends string>({ name, label, options, value, onChange, errors }: Readonly<{
    name: string;
    label: string;
    options: Choice<T>[];
    value: T;
    onChange: (value: T) => void;
    errors: Record<string, string>;
}>) {
    const labelId = `${fieldId(name)}-label`;
    return (
        <div>
            <span id={labelId} className={LABEL}>{label}</span>
            <div role="radiogroup" aria-labelledby={labelId} {...describe(name, errors)} className="flex flex-wrap gap-4">
                {options.map(option => (
                    <label key={option.value} className="flex items-center gap-1.5 text-sm text-zinc-200">
                        <input
                            type="radio"
                            name={fieldId(name)}
                            value={option.value}
                            checked={value === option.value}
                            onChange={() => onChange(option.value)}
                            className="accent-cyan-400"
                        />
                        {option.label}
                    </label>
                ))}
            </div>
            <FieldError name={name} errors={errors} />
        </div>
    );
}

const TH = "px-2 py-1 text-left text-xs font-semibold text-zinc-300";
const CELL = "px-1 py-1 align-top";

function CodebasePathsTable({ paths, onChange, errors, disabled }: Readonly<{
    paths: string[];
    onChange: (paths: string[]) => void;
    errors: Record<string, string>;
    disabled: boolean;
}>) {
    const headingId = `${fieldId('codebase_paths')}-heading`;
    return (
        <div className="space-y-2">
            <h3 id={headingId} className="text-sm font-semibold text-zinc-200">Codebase paths</h3>
            {paths.length > 0 && (
                <table aria-labelledby={headingId} className="w-full table-auto border-collapse">
                    <thead>
                        <tr>
                            <th scope="col" className={`${TH} w-12`}>#</th>
                            <th scope="col" className={TH}>Path</th>
                            <th scope="col" className={`${TH} w-px`}><span className="sr-only">Remove</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {paths.map((path, index) => (
                            // Rows have no stable id; inputs are controlled, so index keys are safe.
                            <tr key={index} className="border-t border-slate-700">
                                <th scope="row" className="px-2 py-1 text-left text-sm font-mono text-zinc-200">{index + 1}</th>
                                <td className={CELL}>
                                    <input type="text" className={FIELD} aria-label={`Codebase path ${index + 1}`}
                                        value={path} disabled={disabled}
                                        onChange={e => onChange(paths.map((p, i) => (i === index ? e.target.value : p)))}
                                        {...describe('codebase_path', errors)} />
                                </td>
                                <td className={CELL}>
                                    <button type="button" className={BUTTON_SECONDARY} aria-label={`Remove codebase path ${index + 1}`}
                                        disabled={disabled} onClick={() => onChange(paths.filter((_, i) => i !== index))}>
                                        Remove
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
            {paths.length === 0 && <p className={HELP}>No codebase paths yet.</p>}
            <FieldError name="codebase_path" errors={errors} />
            <button type="button" className={BUTTON_SECONDARY} disabled={disabled}
                onClick={() => onChange([...paths, ''])}>
                Add path
            </button>
        </div>
    );
}

function ContextTab({ draft, onDraftChange, variantId, files, notify, fieldErrors, disabled = false }: Readonly<Props>) {
    const setText = (key: TextKey, value: string) => onDraftChange({ ...draft, [key]: value });
    const textArea = (key: TextKey, label: string) => (
        <>
            <label className={LABEL} htmlFor={fieldId(key)}>{label}</label>
            <textarea
                id={fieldId(key)}
                className={TEXTAREA}
                value={draft[key]}
                onChange={e => setText(key, e.target.value)}
                {...describe(key, fieldErrors)}
            />
            <FieldError name={key} errors={fieldErrors} />
        </>
    );

    return (
        <div className="space-y-4">
            <div>{textArea('variant_description', 'Variant description')}</div>
            <div className="space-y-2">
                <RadioGroup
                    name="codebase_source"
                    label="Codebase source"
                    options={SOURCES}
                    value={draft.codebase_source}
                    onChange={value => onDraftChange({ ...draft, codebase_source: value })}
                    errors={fieldErrors}
                />
                {/* Both editors stay mounted so the hidden one keeps its state. */}
                <div hidden={draft.codebase_source !== 'references'}>
                    <CodebaseReferences variantId={variantId} initialFiles={files} disabled={disabled} notify={notify} />
                </div>
                <div hidden={draft.codebase_source !== 'paths'}>
                    <CodebasePathsTable
                        paths={draft.codebase_paths}
                        onChange={codebase_paths => onDraftChange({ ...draft, codebase_paths })}
                        errors={fieldErrors}
                        disabled={disabled}
                    />
                </div>
            </div>
            <div>{textArea('environment', 'Environment')}</div>
            <RadioGroup
                name="editor_mode"
                label="Editor mode"
                options={MODES}
                value={draft.editor_mode}
                onChange={value => onDraftChange(switchEditorMode(draft, value))}
                errors={fieldErrors}
            />
            <div>{textArea('other_info', 'Other information')}</div>
        </div>
    );
}

export default ContextTab;
