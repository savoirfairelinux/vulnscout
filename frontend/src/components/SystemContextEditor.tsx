import {
    COMPONENT_FIELDS, INTERACTION_FIELDS, THREAT_MODEL_FIELDS,
    emptySystemComponent, emptySystemInteraction, nextSystemId,
} from "../helpers/strideContext";
import type { SystemComponent, SystemInteraction, ThreatModel } from "../helpers/strideContext";

type Props = {
    model: ThreatModel;
    savedModel?: ThreatModel;
    idPrefix: string;
    disabled: boolean;
    onChange: (model: ThreatModel) => void;
};

const labelClass = "block text-sm text-zinc-300 mb-1";
const inputClass = "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed";
const textareaClass = inputClass + " resize-y min-h-[80px]";
const buttonClass = "rounded px-3 py-1.5 text-sm border border-slate-500 text-cyan-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed";

export default function SystemContextEditor({ model, savedModel, idPrefix, disabled, onChange }: Readonly<Props>) {
    const updateComponent = (index: number, changes: Partial<SystemComponent>) => onChange({
        ...model, components: model.components.map((component, row) => row === index ? { ...component, ...changes } : component),
    });
    const updateInteraction = (index: number, changes: Partial<SystemInteraction>) => onChange({
        ...model, interactions: model.interactions.map((interaction, row) => row === index ? { ...interaction, ...changes } : interaction),
    });
    return (
        <fieldset disabled={disabled} className="space-y-4">
            <legend className="text-lg font-semibold text-white mb-3">System</legend>
            {THREAT_MODEL_FIELDS.map(field => (
                <div key={field.key}>
                    <label className={labelClass} htmlFor={`${idPrefix}-${field.key}`}>{field.label}</label>
                    <p id={`${idPrefix}-${field.key}-help`} className="text-xs text-zinc-400 mb-1">{field.help}</p>
                    <textarea
                        id={`${idPrefix}-${field.key}`} className={textareaClass} value={model[field.key]}
                        aria-describedby={`${idPrefix}-${field.key}-help`} placeholder={field.placeholder}
                        onChange={event => onChange({ ...model, [field.key]: event.target.value })}
                    />
                </div>
            ))}
            <section aria-labelledby={`${idPrefix}-components-title`} className="space-y-3">
                <h3 id={`${idPrefix}-components-title`} className="text-base font-semibold text-white">Components and actors</h3>
                <p className="text-xs text-zinc-400">
                    Name security-relevant device parts, services, data stores and external actors—not every SBOM package.
                </p>
                {model.components.map((component, index) => {
                    const linked = model.interactions.some(interaction =>
                        interaction.sourceId === component.id || interaction.destinationId === component.id)
                        || model.threats.some(threat => threat.targetIds?.includes(component.id));
                    return (
                        <fieldset key={component.id} className="rounded-lg border border-slate-600 p-3 space-y-3">
                            <legend className="text-sm font-semibold text-white px-1">Component {index + 1} ({component.id})</legend>
                            {COMPONENT_FIELDS.map(field => (
                                <div key={field.key}>
                                    <label className={labelClass} htmlFor={`${idPrefix}-${component.id}-${field.key}`}>{field.label}</label>
                                    {field.key === "description" ? (
                                        <textarea
                                            id={`${idPrefix}-${component.id}-${field.key}`} className={textareaClass}
                                            aria-label={`Component ${index + 1} ${field.label.toLowerCase()}`}
                                            value={component[field.key]}
                                            onChange={event => updateComponent(index, { [field.key]: event.target.value })}
                                        />
                                    ) : (
                                        <input
                                            id={`${idPrefix}-${component.id}-${field.key}`} className={inputClass}
                                            aria-label={`Component ${index + 1} ${field.label.toLowerCase()}`}
                                            value={component[field.key]}
                                            placeholder={field.key === "name" ? "e.g. OTA updater" : "e.g. privileged firmware"}
                                            onChange={event => updateComponent(index, { [field.key]: event.target.value })}
                                        />
                                    )}
                                </div>
                            ))}
                            <button type="button" className={buttonClass} disabled={linked}
                                aria-label={`Remove component ${index + 1}`}
                                aria-describedby={linked ? `${idPrefix}-${component.id}-linked` : undefined}
                                onClick={() => onChange({ ...model, components: model.components.filter((_, row) => row !== index) })}
                            >Remove component</button>
                            {linked && <p id={`${idPrefix}-${component.id}-linked`} className="text-xs text-zinc-400">
                                Reassign or remove this component&apos;s interactions and threat references before deleting it.
                            </p>}
                        </fieldset>
                    );
                })}
                <button type="button" className={buttonClass} onClick={() => onChange({
                    ...model, components: [...model.components, emptySystemComponent(nextSystemId(model, "C", savedModel))],
                })}>Add component</button>
            </section>
            <section aria-labelledby={`${idPrefix}-interactions-title`} className="space-y-3">
                <h3 id={`${idPrefix}-interactions-title`} className="text-base font-semibold text-white">Interactions</h3>
                <p className="text-xs text-zinc-400">
                    Describe directed data or command flows between components, including interfaces and crossed trust boundaries.
                </p>
                {model.interactions.map((interaction, index) => {
                    const linked = model.threats.some(threat => threat.targetIds?.includes(interaction.id));
                    const missing = [...new Set([interaction.sourceId, interaction.destinationId])].filter(targetId =>
                        targetId && !model.components.some(component => component.id === targetId));
                    return (
                        <fieldset key={interaction.id} className="rounded-lg border border-slate-600 p-3 space-y-3">
                            <legend className="text-sm font-semibold text-white px-1">Interaction {index + 1} ({interaction.id})</legend>
                            {INTERACTION_FIELDS.map(field => {
                                const endpoint = field.key === "sourceId" || field.key === "destinationId";
                                const label = field.key === "sourceId" ? "Source component"
                                    : field.key === "destinationId" ? "Destination component" : field.label;
                                return (
                                    <div key={field.key}>
                                        <label className={labelClass} htmlFor={`${idPrefix}-${interaction.id}-${field.key}`}>{label}</label>
                                        {endpoint ? (
                                            <select
                                                id={`${idPrefix}-${interaction.id}-${field.key}`} className={inputClass}
                                                aria-label={`Interaction ${index + 1} ${label.toLowerCase()}`}
                                                value={interaction[field.key]}
                                                onChange={event => updateInteraction(index, { [field.key]: event.target.value })}
                                            >
                                                <option value="">Select a component</option>
                                                {interaction[field.key] && !model.components.some(component => component.id === interaction[field.key]) && (
                                                    <option value={interaction[field.key]} disabled>Unavailable component ({interaction[field.key]})</option>
                                                )}
                                                {model.components.map(component => (
                                                    <option key={component.id} value={component.id} disabled={!component.name.trim()}>
                                                        {component.id}: {component.name.trim() || "(name needed)"}
                                                    </option>
                                                ))}
                                            </select>
                                        ) : field.key === "description" ? (
                                            <textarea
                                                id={`${idPrefix}-${interaction.id}-${field.key}`} className={textareaClass}
                                                aria-label={`Interaction ${index + 1} ${label.toLowerCase()}`}
                                                value={interaction[field.key]}
                                                onChange={event => updateInteraction(index, { [field.key]: event.target.value })}
                                            />
                                        ) : (
                                            <input
                                                id={`${idPrefix}-${interaction.id}-${field.key}`} className={inputClass}
                                                aria-label={`Interaction ${index + 1} ${label.toLowerCase()}`}
                                                value={interaction[field.key]}
                                                onChange={event => updateInteraction(index, { [field.key]: event.target.value })}
                                            />
                                        )}
                                    </div>
                                );
                            })}
                            {missing.length > 0 && <p role="status" className="text-xs text-amber-300">
                                Missing component references: {missing.join(", ")}. Select existing components to reconnect this interaction.
                            </p>}
                            <button type="button" className={buttonClass} disabled={linked}
                                aria-label={`Remove interaction ${index + 1}`}
                                aria-describedby={linked ? `${idPrefix}-${interaction.id}-linked` : undefined}
                                onClick={() => onChange({ ...model, interactions: model.interactions.filter((_, row) => row !== index) })}
                            >Remove interaction</button>
                            {linked && <p id={`${idPrefix}-${interaction.id}-linked`} className="text-xs text-zinc-400">
                                Remove this interaction&apos;s threat references before deleting it.
                            </p>}
                        </fieldset>
                    );
                })}
                <button type="button" className={buttonClass} onClick={() => onChange({
                    ...model, interactions: [...model.interactions, emptySystemInteraction(nextSystemId(model, "I", savedModel))],
                })}>Add interaction</button>
            </section>
        </fieldset>
    );
}
