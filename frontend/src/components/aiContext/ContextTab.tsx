import type { VariantDraft } from "../../handlers/context";
import CodebaseDirectory from "./CodebaseDirectory";
import FieldErrorText from "./FieldErrorText";
import { describeField } from "./fieldErrors";
import { LABEL, TEXTAREA } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    variantId: string;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
    /** Makes context fields read-only while the AI drafts the variant. */
    locked?: boolean;
};

type TextKey = 'variant_description' | 'environment' | 'other_info';

const fieldId = (key: string) => `ai-variant-${key.replace(/_/g, '-')}`;

function ContextTab({ draft, onDraftChange, variantId, fieldErrors, disabled = false, locked = false }: Readonly<Props>) {
    const setText = (key: TextKey, value: string) => onDraftChange({ ...draft, [key]: value });
    const textArea = (key: TextKey, label: string) => (
        <>
            <label className={LABEL} htmlFor={fieldId(key)}>{label}</label>
            <textarea
                id={fieldId(key)}
                className={TEXTAREA}
                value={draft[key]}
                onChange={e => setText(key, e.target.value)}
                disabled={locked}
                {...describeField(key, fieldErrors)}
            />
            <FieldErrorText path={key} errors={fieldErrors} />
        </>
    );

    return (
        <div className="space-y-4">
            <div>{textArea('variant_description', 'Variant description')}</div>
            <CodebaseDirectory
                key={variantId}
                variantId={variantId}
                disabled={disabled || locked}
            />
            <div>{textArea('environment', 'Environment')}</div>
            <div>{textArea('other_info', 'Other information')}</div>
        </div>
    );
}

export default ContextTab;
