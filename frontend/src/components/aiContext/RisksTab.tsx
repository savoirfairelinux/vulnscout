import type { Rating, StrideRisk, VariantDraft } from "../../handlers/context";
import { RATING_OPTIONS } from "../../helpers/strideModel";
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

const DESCRIPTION_PREVIEW = 40;
const HEADERS = ['Threat', 'Likelihood', 'Impact', 'Mitigation', 'Residual risk / decision'];

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

function RiskRow({ draft, risk, index, errors, disabled, onEdit, onRemove }: Readonly<{
    draft: VariantDraft; risk: StrideRisk; index: number; errors: Record<string, string>; disabled: boolean;
    onEdit: (index: number, patch: Partial<StrideRisk>) => void; onRemove: (index: number) => void;
}>) {
    const n = index + 1;
    const path = (field: string) => `risks[${index}].${field}`;
    const common = { errors, disabled };
    return (
        <tr className="border-t border-slate-700">
            <td className={CELL}>
                <select className={FIELD} aria-label={`Risk ${n} threat`} value={risk.threat_id} disabled={disabled}
                    onChange={e => onEdit(index, { threat_id: e.target.value })}
                    {...describeField(path('threat_id'), errors)}>
                    {draft.stride.threats.map(t => (
                        <option key={t.id} value={t.id}>{threatLabel(t.id, t.description)}</option>
                    ))}
                </select>
                <FieldErrorText path={path('threat_id')} errors={errors} />
            </td>
            <RatingSelect {...common} value={risk.likelihood} label={`Risk ${n} likelihood`} path={path('likelihood')}
                onChange={v => onEdit(index, { likelihood: v })} />
            <RatingSelect {...common} value={risk.impact} label={`Risk ${n} impact`} path={path('impact')}
                onChange={v => onEdit(index, { impact: v })} />
            <TextCell {...common} value={risk.mitigation} label={`Risk ${n} mitigation`} path={path('mitigation')}
                onChange={v => onEdit(index, { mitigation: v })} />
            <TextCell {...common} value={risk.residual} label={`Risk ${n} residual risk / decision`}
                path={path('residual')} onChange={v => onEdit(index, { residual: v })} />
            <RemoveButton noun="risk" id={String(n)} hintId={`ai-variant-risks-${index}-blocked`} blocked={false}
                disabled={disabled} onClick={() => onRemove(index)} />
        </tr>
    );
}

function StrideRisks({ draft, onDraftChange, fieldErrors, disabled }: Readonly<Required<Props>>) {
    const { stride } = draft;
    const update = (patch: Partial<typeof stride>) => onDraftChange({ ...draft, stride: { ...stride, ...patch } });
    const noThreats = stride.threats.length === 0;
    const add = () => update({
        risks: [...stride.risks, {
            threat_id: stride.threats[0].id, likelihood: null, impact: null, mitigation: '', residual: '',
        }],
    });
    const edit = (index: number, patch: Partial<StrideRisk>) =>
        update({ risks: stride.risks.map((r, i) => (i === index ? { ...r, ...patch } : r)) });
    return (
        <div className="space-y-4">
            <div className="space-y-2">
                <h3 id="ai-variant-risks-heading" className="text-sm font-semibold text-zinc-200">Risks</h3>
                <div className="overflow-x-auto">
                    <table aria-labelledby="ai-variant-risks-heading" className="w-full min-w-[40rem] table-auto border-collapse">
                        <thead>
                            <tr>
                                {HEADERS.map(h => <th key={h} scope="col" className={TH}>{h}</th>)}
                                <th scope="col" className={TH}><span className="sr-only">Remove</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {stride.risks.map((risk, index) => (
                                <RiskRow key={index} draft={draft} risk={risk} index={index} errors={fieldErrors}
                                    disabled={disabled} onEdit={edit}
                                    onRemove={i => update({ risks: stride.risks.filter((_, j) => j !== i) })} />
                            ))}
                        </tbody>
                    </table>
                </div>
                {stride.risks.length === 0 && <p className={HELP}>No risks yet.</p>}
                <button type="button" className={BUTTON_SECONDARY} disabled={disabled || noThreats}
                    aria-describedby={noThreats ? 'ai-variant-risks-add-hint' : undefined} onClick={add}>
                    Add risk
                </button>
                {noThreats && <p id="ai-variant-risks-add-hint" className={HELP}>Add a threat first.</p>}
            </div>
            <div>
                <label className={LABEL} htmlFor="ai-variant-risk-notes">Additional risk notes</label>
                <textarea id="ai-variant-risk-notes" className={TEXTAREA} value={stride.risk_notes} disabled={disabled}
                    onChange={e => update({ risk_notes: e.target.value })} {...describeField('risk_notes', fieldErrors)} />
                <FieldErrorText path="risk_notes" errors={fieldErrors} />
            </div>
        </div>
    );
}

function RisksTab({ draft, onDraftChange, fieldErrors, disabled = false }: Readonly<Props>) {
    if (draft.editor_mode === 'stride') {
        return <StrideRisks draft={draft} onDraftChange={onDraftChange} fieldErrors={fieldErrors} disabled={disabled} />;
    }
    return (
        <div>
            <label className={LABEL} htmlFor="ai-variant-free-risks">Risks</label>
            <textarea id="ai-variant-free-risks" className={`${TEXTAREA} min-h-[160px]`} value={draft.free.risks}
                disabled={disabled}
                onChange={e => onDraftChange({ ...draft, free: { ...draft.free, risks: e.target.value } })}
                {...describeField('risks', fieldErrors)} />
            <FieldErrorText path="risks" errors={fieldErrors} />
        </div>
    );
}

export default RisksTab;
