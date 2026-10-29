import { useRef } from "react";
import type { VariantDraft, SystemFields } from "../../handlers/context";
import FieldErrorText from "./FieldErrorText";
import { describeField } from "./fieldErrors";
import SystemTables from "./SystemTables";
import { LABEL, TEXTAREA } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
};

const FIELDS: { key: keyof SystemFields; label: string }[] = [
    { key: 'scope', label: 'System scope and assets' },
    { key: 'actors', label: 'Actors and access' },
    { key: 'entry_points', label: 'Entry points and data flows' },
    { key: 'trust_boundaries', label: 'Trust boundaries' },
];

function SystemTab({ draft, onDraftChange, fieldErrors, disabled = false }: Readonly<Props>) {
    // Ids removed since this draft was loaded; never handed out again before a save.
    const removedIds = useRef<string[]>([]);
    return (
        <div className="space-y-4">
            {FIELDS.map(({ key, label }) => {
                const path = `system.${key}`;
                const id = `ai-variant-system-${key.replace(/_/g, '-')}`;
                return (
                    <div key={key}>
                        <label className={LABEL} htmlFor={id}>{label}</label>
                        <textarea
                            id={id}
                            className={TEXTAREA}
                            value={draft.system[key] ?? ''}
                            disabled={disabled}
                            onChange={e => onDraftChange({ ...draft, system: { ...draft.system, [key]: e.target.value } })}
                            {...describeField(path, fieldErrors)}
                        />
                        <FieldErrorText path={path} errors={fieldErrors} />
                    </div>
                );
            })}
            <SystemTables
                draft={draft}
                onDraftChange={onDraftChange}
                fieldErrors={fieldErrors}
                removedIds={removedIds}
                disabled={disabled}
            />
        </div>
    );
}

export default SystemTab;
