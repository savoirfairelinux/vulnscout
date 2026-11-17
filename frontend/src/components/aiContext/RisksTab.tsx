import { useRef } from "react";
import type { Rating, StrideRisk, VariantDraft } from "../../handlers/context";
import { RATING_OPTIONS, nextId } from "../../helpers/strideModel";
import FieldErrorText from "./FieldErrorText";
import { RequiredMark, RequiredNote } from "./RequiredMark";
import { describeField } from "./fieldErrors";
import { CELL, CELL_FIELD, RemoveButton, TH } from "./SystemTables";
import { BUTTON_SECONDARY, FIELD, HELP } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    fieldErrors: Record<string, string>;
    disabled?: boolean;
};

const DESCRIPTION_PREVIEW = 40;
const HEADERS = ['Likelihood', 'Impact', 'Mitigation', 'Residual risk / decision'];

const threatLabel = (id: string, description: string) =>
    description.trim() === '' ? id : `${id}: ${description.trim().slice(0, DESCRIPTION_PREVIEW)}`;

function RatingSelect({ value, label, path, errors, disabled, onChange }: Readonly<{
    value: Rating; label: string; path: string; errors: Record<string, string>; disabled: boolean;
    onChange: (value: Rating) => void;
}>) {
    return (
        <td className={CELL}>
            <select className={FIELD} aria-label={label} value={value ?? ''} disabled={disabled}
                onChange={e => onChange(e.target.value === '' ? null : e.target.value as Rating)}
                {...describeField(path, errors)}>
                {RATING_OPTIONS.map(o => <option key={o.label} value={o.value ?? ''}>{o.label}</option>)}
            </select>
            <FieldErrorText path={path} errors={errors} />
        </td>
    );
}

function TextCell({ value, label, path, errors, disabled, onChange }: Readonly<{
    value: string; label: string; path: string; errors: Record<string, string>; disabled: boolean;
    onChange: (value: string) => void;
}>) {
    return (
        <td className={CELL}>
            <textarea rows={2} className={CELL_FIELD} aria-label={label} value={value} disabled={disabled}
                onChange={e => onChange(e.target.value)} {...describeField(path, errors)} />
            <FieldErrorText path={path} errors={errors} />
        </td>
    );
}

function ThreatList({ draft, risk, index, errors, disabled, onChange }: Readonly<{
    draft: VariantDraft; risk: StrideRisk; index: number; errors: Record<string, string>;
    disabled: boolean; onChange: (threatIds: string[]) => void;
}>) {
    const path = `risks[${index}].threat_ids`;
    const toggle = (id: string, checked: boolean) =>
        onChange(checked ? [...risk.threat_ids, id] : risk.threat_ids.filter(t => t !== id));
    return (
        <td className={CELL}>
            <fieldset {...describeField(path, errors)}>
                <legend className="sr-only">{`Risk ${risk.id} threats`}</legend>
                {draft.stride.threats.map(threat => (
                    <label key={threat.id} className="flex items-center gap-1.5 text-sm text-zinc-200">
                        <input type="checkbox" checked={risk.threat_ids.includes(threat.id)} disabled={disabled}
                            onChange={e => toggle(threat.id, e.target.checked)} />
                        {threatLabel(threat.id, threat.description)}
                    </label>
                ))}
            </fieldset>
            <FieldErrorText path={path} errors={errors} />
        </td>
    );
}

function RiskRow({ draft, risk, index, errors, disabled, onEdit, onRemove }: Readonly<{
    draft: VariantDraft; risk: StrideRisk; index: number; errors: Record<string, string>; disabled: boolean;
    onEdit: (index: number, patch: Partial<StrideRisk>) => void; onRemove: (index: number) => void;
}>) {
    const label = `Risk ${risk.id}`;
    const path = (field: string) => `risks[${index}].${field}`;
    const common = { errors, disabled };
    return (
        <tr className="border-t border-slate-700">
            <th scope="row" className="px-2 py-1 text-left text-sm font-mono text-zinc-200">{risk.id}</th>
            <TextCell {...common} value={risk.description} label={`${label} description`} path={path('description')}
                onChange={v => onEdit(index, { description: v })} />
            <ThreatList draft={draft} risk={risk} index={index} errors={errors} disabled={disabled}
                onChange={ids => onEdit(index, { threat_ids: ids })} />
            <RatingSelect {...common} value={risk.likelihood} label={`${label} likelihood`} path={path('likelihood')}
                onChange={v => onEdit(index, { likelihood: v })} />
            <RatingSelect {...common} value={risk.impact} label={`${label} impact`} path={path('impact')}
                onChange={v => onEdit(index, { impact: v })} />
            <TextCell {...common} value={risk.mitigation} label={`${label} mitigation`} path={path('mitigation')}
                onChange={v => onEdit(index, { mitigation: v })} />
            <TextCell {...common} value={risk.residual} label={`${label} residual risk / decision`}
                path={path('residual')} onChange={v => onEdit(index, { residual: v })} />
            <RemoveButton noun="risk" id={risk.id} hintId={`ai-variant-risks-${index}-blocked`} blocked={false}
                disabled={disabled} onClick={() => onRemove(index)} />
        </tr>
    );
}

function RisksTab({ draft, onDraftChange, fieldErrors, disabled = false }: Readonly<Props>) {
    const removedIds = useRef<string[]>([]);
    const { stride } = draft;
    const update = (patch: Partial<typeof stride>) => onDraftChange({ ...draft, stride: { ...stride, ...patch } });
    const noThreats = stride.threats.length === 0;
    const add = () => update({
        risks: [...stride.risks, {
            id: nextId(stride.risks, 'R', removedIds.current), description: '', threat_ids: [],
            likelihood: null, impact: null, mitigation: '', residual: '',
        }],
    });
    const edit = (index: number, patch: Partial<StrideRisk>) =>
        update({ risks: stride.risks.map((r, i) => (i === index ? { ...r, ...patch } : r)) });
    const remove = (index: number) => {
        removedIds.current = [...removedIds.current, stride.risks[index].id];
        update({ risks: stride.risks.filter((_, i) => i !== index) });
    };
    return (
        <div className="space-y-4">
            <div className="space-y-2">
                <h3 id="ai-variant-risks-heading" className="text-sm font-semibold text-zinc-200">Risks</h3>
                <RequiredNote />
                <div className="overflow-x-auto">
                    <table aria-labelledby="ai-variant-risks-heading" className="w-full min-w-[40rem] table-auto border-collapse">
                        <thead>
                            <tr>
                                <th scope="col" className={TH}>ID</th>
                                <th scope="col" className={TH}>Description</th>
                                <th scope="col" className={TH}>Threats<RequiredMark /></th>
                                {HEADERS.map(h => <th key={h} scope="col" className={TH}>{h}</th>)}
                                <th scope="col" className={TH}><span className="sr-only">Remove</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {stride.risks.map((risk, index) => (
                                <RiskRow key={risk.id} draft={draft} risk={risk} index={index} errors={fieldErrors}
                                    disabled={disabled} onEdit={edit} onRemove={remove} />
                            ))}
                        </tbody>
                    </table>
                </div>
                {stride.risks.length === 0 && <p className={HELP}>No risks yet.</p>}
                <FieldErrorText path="risks" errors={fieldErrors} />
                <button type="button" className={BUTTON_SECONDARY} disabled={disabled || noThreats}
                    aria-describedby={noThreats ? 'ai-variant-risks-add-hint' : undefined} onClick={add}>
                    Add risk
                </button>
                {noThreats && <p id="ai-variant-risks-add-hint" className={HELP}>Add a threat first.</p>}
            </div>
        </div>
    );
}

export default RisksTab;
