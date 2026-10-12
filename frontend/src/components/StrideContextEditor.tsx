import { useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
    STRIDE_CATEGORIES, THREAT_MODEL_FIELDS, emptyThreat, emptyRisk, loadStrideContext, nextThreatId,
    serializeThreatModel, serializeRiskRegister,
} from "../helpers/strideContext";
import type { RiskRegister, StrideContextText, StrideRisk, StrideThreat, ThreatModel } from "../helpers/strideContext";

type Props = StrideContextText & {
    activeSection: "threat_model" | "risks";
    tabIdPrefix: string;
    modeContainer: HTMLElement | null;
    disabled: boolean;
    error?: string;
    onChange: (text: StrideContextText) => void;
};

const labelClass = "block text-sm text-zinc-300 mb-1";
const inputClass = "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
const textareaClass = inputClass + " resize-y min-h-[80px]";
const buttonClass = "rounded px-3 py-1.5 text-sm border border-slate-500 text-cyan-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed";

export default function StrideContextEditor({
    activeSection, tabIdPrefix, modeContainer, threatModel, risks, disabled, error, onChange,
}: Readonly<Props>) {
    const id = useId();
    const [draft, setDraft] = useState(() => loadStrideContext({ threatModel, risks }));
    const freeModeSnapshot = useRef<StrideContextText | null>(null);
    const errorId = `${id}-error`;
    const publish = (model: ThreatModel, register: RiskRegister) => onChange({
        threatModel: serializeThreatModel(model, register.risks.map(risk => risk.threatId)),
        risks: serializeRiskRegister(register),
    });
    const updateModel = (changes: Partial<ThreatModel>) => {
        const model = { ...draft.model, ...changes };
        setDraft({ ...draft, model });
        publish(model, draft.register);
    };
    const updateRegister = (register: RiskRegister) => {
        setDraft({ ...draft, register });
        publish(draft.model, register);
    };
    const updateRisk = (index: number, changes: Partial<StrideRisk>) => updateRegister({
        ...draft.register,
        risks: draft.register.risks.map((risk, row) => row === index ? { ...risk, ...changes } : risk),
    });
    const updateThreat = (index: number, changes: Partial<StrideThreat>) => updateModel({
        threats: draft.model.threats.map((threat, row) => row === index ? { ...threat, ...changes } : threat),
    });
    const selectRiskThreat = (index: number, threatId: string) => updateRegister({
        ...draft.register,
        risks: draft.register.risks.map((risk, row) => row === index ? {
            threatId, likelihood: risk.likelihood, impact: risk.impact,
            mitigation: risk.mitigation, decision: risk.decision,
        } : risk),
    });
    const addLegacyThreat = (index: number, risk: StrideRisk) => {
        const legacy = risk.legacyThreat;
        if (!legacy) return;
        const threatId = nextThreatId(draft.model, draft.register);
        const model = { ...draft.model, threats: [...draft.model.threats, { id: threatId, ...legacy }] };
        const register = {
            ...draft.register,
            risks: draft.register.risks.map((entry, row) => row === index ? {
                threatId, likelihood: entry.likelihood, impact: entry.impact,
                mitigation: entry.mitigation, decision: entry.decision,
            } : entry),
        };
        setDraft({ ...draft, model, register });
        publish(model, register);
    };

    return (
        <div className="space-y-4">
            {/* Place the shared selector in Context without resetting local editor drafts. */}
            {modeContainer && createPortal(
                <div>
                    <label className={labelClass} htmlFor={`${id}-mode`}>Editor mode</label>
                    <p id={`${id}-mode-help`} className="text-xs text-zinc-400 mb-1">
                        Applies to both Threat model and Risks.
                    </p>
                    <select
                        id={`${id}-mode`}
                        className={inputClass}
                        value={draft.mode}
                        disabled={disabled}
                        aria-describedby={`${id}-mode-help`}
                        onChange={event => {
                            if (event.target.value === "free") {
                                freeModeSnapshot.current = { threatModel, risks };
                                setDraft({ ...draft, mode: "free" });
                            }
                            else {
                                if (freeModeSnapshot.current?.threatModel === threatModel
                                    && freeModeSnapshot.current.risks === risks) {
                                    setDraft({ ...draft, mode: "stride" });
                                    return;
                                }
                                const next = loadStrideContext({ threatModel, risks });
                                setDraft({ ...next, mode: "stride" });
                                if (next.mode === "free") publish(next.model, next.register);
                            }
                        }}
                    >
                        <option value="stride">STRIDE template (recommended)</option>
                        <option value="free">Advanced free mode</option>
                    </select>
                </div>, modeContainer,
            )}

            {draft.mode === "free" ? (
                <>
                    <p className="text-xs text-zinc-400">
                        Use your own format. Switching to STRIDE keeps existing free text as additional notes.
                    </p>
                    <div
                        role="tabpanel" id={`${tabIdPrefix}-threat_model-panel`}
                        aria-labelledby={`${tabIdPrefix}-threat_model-tab`} tabIndex={0}
                        hidden={activeSection !== "threat_model"}
                    >
                        <label className={labelClass} htmlFor={`${id}-threat-model`}>
                            Threat Model <span className="text-red-500">*</span>
                        </label>
                        <textarea
                            id={`${id}-threat-model`} aria-label="Threat Model" className={textareaClass}
                            value={threatModel} disabled={disabled}
                            aria-invalid={Boolean(error)} aria-describedby={error ? errorId : undefined}
                            placeholder="Describe the threat criteria for CVEs..."
                            onChange={event => onChange({ threatModel: event.target.value, risks })}
                        />
                    </div>
                    <div
                        role="tabpanel" id={`${tabIdPrefix}-risks-panel`}
                        aria-labelledby={`${tabIdPrefix}-risks-tab`} tabIndex={0}
                        hidden={activeSection !== "risks"}
                    >
                        <label className={labelClass} htmlFor={`${id}-risks`}>Risks</label>
                        <textarea
                            id={`${id}-risks`} aria-label="Risks" className={textareaClass}
                            value={risks} disabled={disabled} placeholder="Describe known risks..."
                            onChange={event => onChange({ threatModel, risks: event.target.value })}
                        />
                    </div>
                </>
            ) : (
                <>
                    <div
                        role="tabpanel" id={`${tabIdPrefix}-threat_model-panel`}
                        aria-labelledby={`${tabIdPrefix}-threat_model-tab`} tabIndex={0}
                        hidden={activeSection !== "threat_model"} className="space-y-4"
                    >
                        <fieldset disabled={disabled} className="space-y-4" aria-describedby={error ? errorId : undefined}>
                            <legend className="text-lg font-semibold text-white mb-3">
                                Threat Model <span className="text-red-500">*</span>
                            </legend>
                            {THREAT_MODEL_FIELDS.map(field => (
                                <div key={field.key}>
                                    <label className={labelClass} htmlFor={`${id}-${field.key}`}>{field.label}</label>
                                    <p id={`${id}-${field.key}-help`} className="text-xs text-zinc-400 mb-1">{field.help}</p>
                                    <textarea
                                        id={`${id}-${field.key}`} className={textareaClass}
                                        value={draft.model[field.key]}
                                        aria-describedby={`${id}-${field.key}-help`} aria-invalid={Boolean(error)}
                                        placeholder={field.placeholder}
                                        onChange={event => updateModel({ [field.key]: event.target.value })}
                                    />
                                </div>
                            ))}
                            <p className="text-xs text-zinc-400">
                                Add one entry per threat. Several threats can share the same STRIDE category.
                                Consider all six categories; an empty list does not mean no threats exist.
                            </p>
                            {draft.model.threats.map((threat, index) => {
                                const category = STRIDE_CATEGORIES.find(item => item.name === threat.category);
                                const helpId = `${id}-threat-${index}-help`;
                                const linked = draft.register.risks.some(risk => risk.threatId === threat.id);
                                return (
                                    <fieldset key={threat.id} className="rounded-lg border border-slate-600 p-3 space-y-3">
                                        <legend className="text-sm font-semibold text-white px-1">Threat {index + 1}</legend>
                                        <div>
                                            <label className={labelClass} htmlFor={`${id}-threat-${index}-category`}>STRIDE category</label>
                                            <select
                                                id={`${id}-threat-${index}-category`} className={inputClass} value={threat.category}
                                                aria-label={`Threat ${index + 1} STRIDE category`}
                                                onChange={event => {
                                                    const selected = STRIDE_CATEGORIES.find(item => item.name === event.target.value);
                                                    updateThreat(index, { category: selected?.name ?? "" });
                                                }}
                                            >
                                                <option value="">Choose a STRIDE category</option>
                                                {STRIDE_CATEGORIES.map(item =>
                                                    <option key={item.key} value={item.name}>{item.letter} - {item.name}</option>)}
                                            </select>
                                        </div>
                                        <div>
                                            <label className={labelClass} htmlFor={`${id}-threat-${index}-description`}>Description</label>
                                            <p id={helpId} className="text-xs text-zinc-400 mb-1">
                                                {category?.question ?? "Describe the actor, action and affected asset or interface."}
                                            </p>
                                            <textarea
                                                id={`${id}-threat-${index}-description`} className={textareaClass}
                                                value={threat.description} aria-label={`Threat ${index + 1} description`}
                                                aria-describedby={helpId}
                                                placeholder={category?.example ?? "Describe a concrete threat to the system."}
                                                onChange={event => updateThreat(index, { description: event.target.value })}
                                            />
                                        </div>
                                        <button
                                            type="button" className={buttonClass} aria-label={`Remove threat ${index + 1}`}
                                            disabled={linked}
                                            aria-describedby={linked ? `${id}-threat-${index}-linked` : undefined}
                                            onClick={() => updateModel({
                                                threats: draft.model.threats.filter((_, row) => row !== index),
                                            })}
                                        >Remove threat</button>
                                        {linked && (
                                            <p id={`${id}-threat-${index}-linked`} className="text-xs text-zinc-400">
                                                Reassign or remove this threat&apos;s linked risks before deleting it.
                                            </p>
                                        )}
                                    </fieldset>
                                );
                            })}
                            <button
                                type="button" className={buttonClass}
                                onClick={() => updateModel({
                                    threats: [...draft.model.threats, emptyThreat(nextThreatId(draft.model, draft.register))],
                                })}
                            >Add threat</button>
                            <div>
                                <label className={labelClass} htmlFor={`${id}-notes`}>Additional notes</label>
                                <p id={`${id}-notes-help`} className="text-xs text-zinc-400 mb-1">
                                    Record assumptions, exclusions or existing notes that do not fit the threat entries.
                                </p>
                                <textarea
                                    id={`${id}-notes`} className={textareaClass} value={draft.model.notes}
                                    aria-describedby={`${id}-notes-help`}
                                    placeholder="Physical debug access is disabled in production; verify this assumption."
                                    onChange={event => updateModel({ notes: event.target.value })}
                                />
                            </div>
                        </fieldset>
                    </div>
                    <div
                        role="tabpanel" id={`${tabIdPrefix}-risks-panel`}
                        aria-labelledby={`${tabIdPrefix}-risks-tab`} tabIndex={0}
                        hidden={activeSection !== "risks"}
                    >
                        <fieldset disabled={disabled} className="space-y-4">
                            <legend className="text-lg font-semibold text-white mb-3">Risks</legend>
                            <p className="text-xs text-zinc-400">
                                Select a threat from the Threat model tab, then evaluate its likelihood, impact and
                                mitigation or acceptance decision. Ratings are qualitative, not CVSS scores.
                            </p>
                            {draft.register.risks.map((risk, index) => {
                                const selectedThreat = draft.model.threats.find(threat => threat.id === risk.threatId);
                                const hasThreats = draft.model.threats.some(threat => threat.description.trim());
                                return (
                                    <fieldset key={index} className="rounded-lg border border-slate-600 p-3 space-y-3">
                                        <legend className="text-sm font-semibold text-white px-1">Risk {index + 1}</legend>
                                        <div>
                                            <label className={labelClass} htmlFor={`${id}-risk-${index}-threat`}>Threat</label>
                                            <select
                                                id={`${id}-risk-${index}-threat`} className={inputClass} value={risk.threatId}
                                                aria-label={`Risk ${index + 1} threat`}
                                                disabled={!hasThreats}
                                                onChange={event => selectRiskThreat(index, event.target.value)}
                                            >
                                                <option value="">{hasThreats ? "Select a threat" : "Add and describe a threat in Threat model first"}</option>
                                                {risk.threatId && !selectedThreat && (
                                                    <option value={risk.threatId} disabled>Unavailable threat ({risk.threatId})</option>
                                                )}
                                                {draft.model.threats.map((threat, threatIndex) => (
                                                    <option key={threat.id} value={threat.id} disabled={!threat.description.trim()}>
                                                        Threat {threatIndex + 1} - {threat.category || "Uncategorized"}: {threat.description.trim().replace(/\s+/g, " ").slice(0, 100) || "(description needed)"}
                                                    </option>
                                                ))}
                                            </select>
                                        </div>
                                        {selectedThreat && (
                                            <div role="note" aria-label={`Risk ${index + 1} selected threat`} className="text-sm text-zinc-300 whitespace-pre-wrap break-words">
                                                <p className="font-semibold">{selectedThreat.category || "Uncategorized"}</p>
                                                <p>{selectedThreat.description || "Complete this threat's description in Threat model."}</p>
                                            </div>
                                        )}
                                        {risk.threatId && !selectedThreat && (
                                            <p role="status" className="text-xs text-amber-300">
                                                The linked threat {risk.threatId} is missing. Select another threat to reconnect this risk.
                                            </p>
                                        )}
                                        {risk.legacyThreat && (
                                            <div className="text-sm text-zinc-300">
                                                <p role="status" className="text-xs text-amber-300">
                                                    This existing risk is not linked to a threat. Select one above or add its saved scenario as a threat.
                                                </p>
                                                <p className="font-semibold">{risk.legacyThreat.category || "Uncategorized"}</p>
                                                <p className="whitespace-pre-wrap break-words">{risk.legacyThreat.description}</p>
                                                {risk.legacyThreat.description.trim() && (
                                                    <button type="button" className={buttonClass}
                                                        aria-label={`Add risk ${index + 1} scenario as threat`}
                                                        onClick={() => addLegacyThreat(index, risk)}
                                                    >Add saved scenario as threat</button>
                                                )}
                                            </div>
                                        )}
                                        <div className="grid gap-3 sm:grid-cols-2">
                                            {(["likelihood", "impact"] as const).map(field => (
                                                <div key={field}>
                                                    <label className={labelClass} htmlFor={`${id}-risk-${index}-${field}`}>
                                                        {field === "likelihood" ? "Likelihood" : "Impact"}
                                                    </label>
                                                    <select
                                                        id={`${id}-risk-${index}-${field}`} className={inputClass} value={risk[field]}
                                                        aria-label={`Risk ${index + 1} ${field}`}
                                                        onChange={event => {
                                                            const value = event.target.value;
                                                            if (value === "" || value === "Low" || value === "Medium" || value === "High")
                                                                updateRisk(index, { [field]: value });
                                                        }}
                                                    >
                                                        <option value="">Not assessed</option>
                                                        <option value="Low">Low</option>
                                                        <option value="Medium">Medium</option>
                                                        <option value="High">High</option>
                                                    </select>
                                                </div>
                                            ))}
                                        </div>
                                        <div>
                                            <label className={labelClass} htmlFor={`${id}-risk-${index}-mitigation`}>Mitigation</label>
                                            <textarea
                                                id={`${id}-risk-${index}-mitigation`} className={textareaClass} value={risk.mitigation}
                                                aria-label={`Risk ${index + 1} mitigation`}
                                                placeholder="Require signed updates and verify signatures before installation."
                                                onChange={event => updateRisk(index, { mitigation: event.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className={labelClass} htmlFor={`${id}-risk-${index}-decision`}>Residual risk / decision</label>
                                            <textarea
                                                id={`${id}-risk-${index}-decision`} className={textareaClass} value={risk.decision}
                                                aria-label={`Risk ${index + 1} residual risk / decision`}
                                                placeholder="What remains after mitigation? Accept, investigate or reduce it; note the rationale."
                                                onChange={event => updateRisk(index, { decision: event.target.value })}
                                            />
                                        </div>
                                        <button
                                            type="button" className={buttonClass} aria-label={`Remove risk ${index + 1}`}
                                            onClick={() => updateRegister({
                                                ...draft.register, risks: draft.register.risks.filter((_, row) => row !== index),
                                            })}
                                        >Remove risk</button>
                                    </fieldset>
                                );
                            })}
                            <button
                                type="button" className={buttonClass}
                                onClick={() => updateRegister({ ...draft.register, risks: [...draft.register.risks, emptyRisk()] })}
                            >Add risk</button>
                            <div>
                                <label className={labelClass} htmlFor={`${id}-risk-notes`}>Additional risk notes</label>
                                <textarea
                                    id={`${id}-risk-notes`} className={textareaClass} value={draft.register.notes}
                                    placeholder="Existing notes, uncertainty or cross-cutting risks."
                                    onChange={event => updateRegister({ ...draft.register, notes: event.target.value })}
                                />
                            </div>
                        </fieldset>
                    </div>
                </>
            )}
            {error && activeSection === "threat_model" && <p id={errorId} role="alert" className="text-red-500 text-xs">{error}</p>}
        </div>
    );
}
