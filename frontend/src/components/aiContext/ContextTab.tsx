import type { ContextFile, VariantDraft } from "../../handlers/context";
import { switchEditorMode } from "../../helpers/strideModel";
import CodebaseReferences from "../CodebaseReferences";
import FieldErrorText from "./FieldErrorText";
import { describeField } from "./fieldErrors";
import { HELP, LABEL, TEXTAREA } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    variantId: string;
    files: ContextFile[];
    notify: (message: string, type: 'success' | 'error') => void;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
};

type TextKey = 'variant_description' | 'environment' | 'other_info' | 'codebase_path';
type Choice<T extends string> = { value: T; label: string };

const SOURCES: Choice<VariantDraft['codebase_source']>[] = [
    { value: 'paths', label: 'Codebase paths' },
    { value: 'references', label: 'Codebase references' },
];
const MODES: Choice<VariantDraft['editor_mode']>[] = [
    { value: 'stride', label: 'STRIDE' },
    { value: 'free', label: 'Free' },
];

const fieldId = (key: string) => `ai-variant-${key.replace(/_/g, '-')}`;

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
            <div role="radiogroup" aria-labelledby={labelId} {...describeField(name, errors)} className="flex flex-wrap gap-4">
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
            <FieldErrorText path={name} errors={errors} />
        </div>
    );
}

function ContextTab({ draft, onDraftChange, variantId, files, notify, fieldErrors, disabled = false }: Readonly<Props>) {
    const setText = (key: TextKey, value: string) => onDraftChange({ ...draft, [key]: value });
    const textArea = (key: TextKey, label: string, helpId?: string) => (
        <>
            <label className={LABEL} htmlFor={fieldId(key)}>{label}</label>
            <textarea
                id={fieldId(key)}
                className={TEXTAREA}
                value={draft[key]}
                onChange={e => setText(key, e.target.value)}
                {...describeField(key, fieldErrors, helpId)}
            />
            <FieldErrorText path={key} errors={fieldErrors} />
        </>
    );
    const pathsHelpId = `${fieldId('codebase_path')}-help`;

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
                <div hidden={draft.codebase_source !== 'paths'}>
                    {textArea('codebase_path', 'Codebase paths', pathsHelpId)}
                    <p id={pathsHelpId} className={`${HELP} mt-1`}>Separate several paths with ";".</p>
                </div>
                <div hidden={draft.codebase_source !== 'references'}>
                    <CodebaseReferences variantId={variantId} initialFiles={files} disabled={disabled} notify={notify} />
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
