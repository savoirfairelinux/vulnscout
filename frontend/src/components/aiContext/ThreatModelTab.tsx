import { useRef } from "react";
import type { VariantDraft, StrideThreat } from "../../handlers/context";
import { STRIDE_CATEGORIES, nextId } from "../../helpers/strideModel";
import FieldErrorText from "./FieldErrorText";
import { describeField } from "./fieldErrors";
import { CELL, CELL_FIELD, RemoveButton, TH } from "./SystemTables";
import { BUTTON_SECONDARY, FIELD, HELP, LABEL, TEXTAREA } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
};

const REMOVE_HINT = 'Remove its risks first.';

function TargetList({ draft, threat, index, errors, disabled, onChange }: Readonly<{
    draft: VariantDraft; threat: StrideThreat; index: number; errors: Record<string, string>;
    disabled: boolean; onChange: (targetIds: string[]) => void;
}>) {
    const path = `threats[${index}].target_ids`;
    const options = [...draft.stride.components, ...draft.stride.interactions];
    const toggle = (id: string, checked: boolean) =>
        onChange(checked ? [...threat.target_ids, id] : threat.target_ids.filter(t => t !== id));
    return (
        <td className={CELL}>
            <fieldset {...describeField(path, errors)}>
                <legend className="sr-only">{`Threat ${threat.id} targets`}</legend>
                {options.length === 0 && <p className={HELP}>Add components or interactions first.</p>}
                {options.map(option => (
                    <label key={option.id} className="flex items-center gap-1.5 text-sm text-zinc-200">
                        <input type="checkbox" checked={threat.target_ids.includes(option.id)} disabled={disabled}
                            onChange={e => toggle(option.id, e.target.checked)} />
                        {`${option.id} ${option.name}`.trim()}
                    </label>
                ))}
            </fieldset>
            <FieldErrorText path={path} errors={errors} />
        </td>
    );
}

function ThreatRow({ draft, threat, index, errors, disabled, onEdit, onRemove }: Readonly<{
    draft: VariantDraft; threat: StrideThreat; index: number; errors: Record<string, string>; disabled: boolean;
    onEdit: (index: number, patch: Partial<StrideThreat>) => void; onRemove: (index: number) => void;
}>) {
    const categoryPath = `threats[${index}].category`;
    const descriptionPath = `threats[${index}].description`;
    return (
        <tr className="border-t border-slate-700">
            <th scope="row" className="px-2 py-1 text-left text-sm font-mono text-zinc-200">{threat.id}</th>
            <td className={CELL}>
                <select className={FIELD} aria-label={`Threat ${threat.id} STRIDE category`} value={threat.category}
                    disabled={disabled} onChange={e => onEdit(index, { category: e.target.value })}
                    {...describeField(categoryPath, errors)}>
                    {STRIDE_CATEGORIES.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}
                </select>
                <FieldErrorText path={categoryPath} errors={errors} />
            </td>
            <td className={CELL}>
                <textarea rows={2} className={CELL_FIELD} aria-label={`Threat ${threat.id} description`}
                    value={threat.description} disabled={disabled}
                    onChange={e => onEdit(index, { description: e.target.value })}
                    {...describeField(descriptionPath, errors)} />
                <FieldErrorText path={descriptionPath} errors={errors} />
            </td>
            <TargetList draft={draft} threat={threat} index={index} errors={errors} disabled={disabled}
                onChange={ids => onEdit(index, { target_ids: ids })} />
            <RemoveButton noun="threat" id={threat.id} hintId={`ai-variant-threats-${index}-blocked`}
                blocked={draft.stride.risks.some(r => r.threat_id === threat.id)} hint={REMOVE_HINT}
                disabled={disabled} onClick={() => onRemove(index)} />
        </tr>
    );
}

function ThreatModelTab({ draft, onDraftChange, fieldErrors, disabled = false }: Readonly<Props>) {
    const removedIds = useRef<string[]>([]);
    const { stride } = draft;
    const update = (patch: Partial<typeof stride>) => onDraftChange({ ...draft, stride: { ...stride, ...patch } });
    const add = () => update({
        threats: [...stride.threats, {
            id: nextId(stride.threats, 'T', removedIds.current), category: 'spoofing', description: '', target_ids: [],
        }],
    });
    const edit = (index: number, patch: Partial<StrideThreat>) =>
        update({ threats: stride.threats.map((t, i) => (i === index ? { ...t, ...patch } : t)) });
    const remove = (index: number) => {
        removedIds.current = [...removedIds.current, stride.threats[index].id];
        update({ threats: stride.threats.filter((_, i) => i !== index) });
    };
    return (
        <div className="space-y-4">
            <FieldErrorText path="threat_model" errors={fieldErrors} />
            <div className="space-y-2">
                <h3 id="ai-variant-threats-heading" className="text-sm font-semibold text-zinc-200">Threats</h3>
                <div className="overflow-x-auto">
                    <table aria-labelledby="ai-variant-threats-heading" className="w-full min-w-[40rem] table-auto border-collapse">
                        <thead>
                            <tr>
                                {['ID', 'STRIDE category', 'Description', 'Targets'].map(h => (
                                    <th key={h} scope="col" className={TH}>{h}</th>
                                ))}
                                <th scope="col" className={TH}><span className="sr-only">Remove</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {stride.threats.map((threat, index) => (
                                <ThreatRow key={threat.id} draft={draft} threat={threat} index={index}
                                    errors={fieldErrors} disabled={disabled} onEdit={edit} onRemove={remove} />
                            ))}
                        </tbody>
                    </table>
                </div>
                {stride.threats.length === 0 && <p className={HELP}>No threats yet.</p>}
                <button type="button" className={BUTTON_SECONDARY} disabled={disabled} onClick={add}>Add threat</button>
            </div>
            <div>
                <label className={LABEL} htmlFor="ai-variant-notes">Additional notes</label>
                <textarea id="ai-variant-notes" className={TEXTAREA} value={stride.notes} disabled={disabled}
                    onChange={e => update({ notes: e.target.value })} {...describeField('notes', fieldErrors)} />
                <FieldErrorText path="notes" errors={fieldErrors} />
            </div>
        </div>
    );
}

export default ThreatModelTab;
