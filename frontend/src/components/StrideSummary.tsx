import {
    RISK_FIELDS, STRIDE_CATEGORIES, hasRiskContent, hasThreatDraft, systemElementLabel,
} from "../helpers/strideContext";
import type { RiskRegister, StrideRisk, ThreatModel } from "../helpers/strideContext";
import type { ReactNode } from "react";

type Props = {
    model: ThreatModel; register: RiskRegister;
    scopeLabel?: (kind: "threats" | "risks", index: number) => ReactNode;
};

const cellClass = "border-t border-slate-700 px-3 py-2 align-top whitespace-pre-wrap break-words";
const headerClass = "px-3 py-2 text-left font-semibold text-zinc-200";
const tableClass = "w-full border-collapse text-left text-sm text-zinc-300";
const regionClass = "max-w-full overflow-x-auto rounded border border-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-400";
const riskFields = RISK_FIELDS.slice(1);
const riskHeaders = riskFields.map(field => field.label);

function RiskSummaryCells({ risk }: Readonly<{ risk?: StrideRisk }>) {
    return <>{riskFields.map(field => {
        let value = "Not evaluated";
        if (risk) {
            const text = risk[field.key];
            value = text.trim() ? text
                : field.key === "likelihood" || field.key === "impact" ? "Not rated" : "Not recorded";
        }
        return <td key={field.key} className={cellClass}>{value}</td>;
    })}</>;
}

function SystemTargets({ model, targetIds }: Readonly<{ model: ThreatModel; targetIds: readonly string[] }>) {
    if (targetIds.length === 0) return <>No system reference</>;
    return <ul className="space-y-2">
        {targetIds.map(targetId => {
            const label = systemElementLabel(model, targetId);
            const interaction = model.interactions.find(element => element.id === targetId);
            return <li key={targetId}>
                {label ?? <span role="status" className="text-amber-300">Unavailable system element ({targetId})</span>}
                {interaction && (
                    <div className="text-xs text-zinc-400">
                        <p>
                            {interaction.sourceId
                                ? systemElementLabel(model, interaction.sourceId) ?? `Unavailable component (${interaction.sourceId})`
                                : "Source not specified"}
                            {" -> "}
                            {interaction.destinationId
                                ? systemElementLabel(model, interaction.destinationId) ?? `Unavailable component (${interaction.destinationId})`
                                : "Destination not specified"}
                            {interaction.protocol.trim() && ` (${interaction.protocol})`}
                        </p>
                        {interaction.trustBoundary.trim() && <p>Trust boundary: {interaction.trustBoundary}</p>}
                    </div>
                )}
            </li>;
        })}
    </ul>;
}

export default function StrideSummary({ model, register, scopeLabel }: Readonly<Props>) {
    const risks = register.risks.map((risk, index) => ({ risk, number: index + 1 }))
        .filter(entry => hasRiskContent(entry.risk));
    const threats = model.threats.filter(threat => hasThreatDraft(threat)
        || risks.some(entry => entry.risk.threatId === threat.id));
    const unlinkedRisks = risks.filter(entry => !model.threats.some(threat => threat.id === entry.risk.threatId));
    const uncategorized = threats.filter(threat => !threat.category);
    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white">Summary</h2>
            <p className="text-sm text-zinc-400">
                Read-only overview of the current context, including unsaved edits. Ratings are qualitative, not CVSS scores.
            </p>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-sm text-zinc-300">
                {[
                    ["Named components", model.components.filter(component => component.name.trim()).length],
                    ["Named interactions", model.interactions.filter(interaction => interaction.name.trim()).length],
                    ["Described threats", threats.filter(threat => threat.description.trim()).length],
                    ["Risk entries", risks.length],
                ].map(([label, count]) => <div key={label}>
                    <dt className="text-zinc-400">{label}</dt>
                    <dd className="font-semibold text-white">{count}</dd>
                </div>)}
            </dl>
            <div role="region" aria-label="STRIDE category overview" tabIndex={0} className={regionClass}>
                <table className={tableClass}>
                    <caption className="p-3 text-left font-semibold text-white">Recorded threats by STRIDE category</caption>
                    <thead><tr>{["Category", "Described threats", "Drafts without a description"].map(label =>
                        <th key={label} scope="col" className={headerClass}>{label}</th>)}</tr></thead>
                    <tbody>{STRIDE_CATEGORIES.map(category => {
                        const entries = threats.filter(threat => threat.category === category.name);
                        return <tr key={category.key}>
                            <th scope="row" className={cellClass + " font-medium"}>{category.letter} - {category.name}</th>
                            <td className={cellClass}>{entries.filter(threat => threat.description.trim()).length}</td>
                            <td className={cellClass}>{entries.filter(threat => !threat.description.trim()).length}</td>
                        </tr>;
                    })}</tbody>
                </table>
            </div>
            <p className="text-xs text-zinc-400">
                These counts do not indicate completed review. Zero recorded threats does not mean a category is safe or not applicable.
            </p>
            {uncategorized.length > 0 && <p role="status" className="text-sm text-amber-300">
                Threats without a STRIDE category: {uncategorized.map(threat => threat.id).join(", ")}.
            </p>}
            {threats.length === 0 ? (
                <p className="text-sm text-zinc-400">No threat entries recorded yet. Add threats in Threat model to build this summary.</p>
            ) : (
                <div role="region" aria-label="Threat and risk summary" tabIndex={0} className={regionClass}>
                    <table className={tableClass + " min-w-[1000px]"}>
                        <caption className="p-3 text-left font-semibold text-white">Threats and linked risk evaluations</caption>
                        <thead><tr>{["Threat", ...(scopeLabel ? ["Threat variants"] : []), "STRIDE category", "Affected system elements",
                            "Risk", ...(scopeLabel ? ["Risk variants"] : []), ...riskHeaders].map(label =>
                            <th key={label} scope="col" className={headerClass}>{label}</th>)}</tr></thead>
                        {threats.map(threat => {
                            const number = model.threats.findIndex(entry => entry.id === threat.id) + 1;
                            const linked = risks.filter(entry => entry.risk.threatId === threat.id);
                            const rows = linked.length > 0 ? linked : [undefined];
                            return <tbody key={threat.id}>{rows.map((entry, index) => (
                                <tr key={entry?.number ?? "none"}>
                                    {index === 0 && <>
                                        <th scope="rowgroup" rowSpan={rows.length} className={cellClass + " min-w-[180px] font-normal"}>
                                            <p className="font-semibold text-white">Threat {number} ({threat.id})</p>
                                            {threat.description.trim() ? threat.description : "Description missing (draft)"}
                                        </th>
                                        {scopeLabel && <td rowSpan={rows.length} className={cellClass}>{scopeLabel("threats", number - 1)}</td>}
                                        <td rowSpan={rows.length} className={cellClass}>{threat.category || "Uncategorized"}</td>
                                        <td rowSpan={rows.length} className={cellClass + " min-w-[220px]"}>
                                            <SystemTargets model={model} targetIds={threat.targetIds ?? []} />
                                        </td>
                                    </>}
                                    <td className={cellClass}>{entry ? `Risk ${entry.number}` : "No linked risk"}</td>
                                    {scopeLabel && <td className={cellClass}>{entry ? scopeLabel("risks", entry.number - 1) : "Not evaluated"}</td>}
                                    <RiskSummaryCells risk={entry?.risk} />
                                </tr>
                            ))}</tbody>;
                        })}
                    </table>
                </div>
            )}
            {unlinkedRisks.length > 0 && (
                <div role="region" aria-label="Unlinked risk summary" tabIndex={0} className={regionClass}>
                    <table className={tableClass + " min-w-[900px]"}>
                        <caption className="p-3 text-left font-semibold text-white">Risks with unlinked or unavailable threats</caption>
                        <thead><tr>{["Risk", ...(scopeLabel ? ["Variants"] : []), "Threat reference", "Saved scenario", ...riskHeaders].map(label =>
                            <th key={label} scope="col" className={headerClass}>{label}</th>)}</tr></thead>
                        <tbody>{unlinkedRisks.map(entry => <tr key={entry.number}>
                            <th scope="row" className={cellClass + " font-medium"}>Risk {entry.number}</th>
                            {scopeLabel && <td className={cellClass}>{scopeLabel("risks", entry.number - 1)}</td>}
                            <td className={cellClass}>
                                {entry.risk.threatId
                                    ? <span role="status" className="text-amber-300">Unavailable threat ({entry.risk.threatId})</span>
                                    : "No linked threat"}
                            </td>
                            <td className={cellClass}>
                                {entry.risk.legacyThreat ? <>
                                    <p className="font-semibold">{entry.risk.legacyThreat.category || "Uncategorized"}</p>
                                    {entry.risk.legacyThreat.description.trim()
                                        ? entry.risk.legacyThreat.description : "Description not recorded"}
                                </> : "No saved scenario"}
                            </td>
                            <RiskSummaryCells risk={entry.risk} />
                        </tr>)}</tbody>
                    </table>
                </div>
            )}
            {model.notes.trim() && <section>
                <h3 className="font-semibold text-white">Additional threat model notes</h3>
                <p className="text-sm text-zinc-300 whitespace-pre-wrap break-words">{model.notes}</p>
            </section>}
            {register.notes.trim() && <section>
                <h3 className="font-semibold text-white">Additional risk notes</h3>
                <p className="text-sm text-zinc-300 whitespace-pre-wrap break-words">{register.notes}</p>
            </section>}
        </div>
    );
}
