import { useState, useEffect } from "react";
import EditAssessment from "./EditAssessment";
import ModeledRiskLinks from "./ModeledRiskLinks";
import Assessments, { describeThreatTargets, displayModelId, initialStatusNotes } from "../handlers/assessments";
import type { EditAssessmentData } from "./EditAssessment";
import type { AiAssessmentEdits, Assessment, RiskReference, RiskLinkPreview, TargetRiskEdit } from "../handlers/assessments";

type Props = {
    assessment: Assessment;
    variantNames?: Record<string, string>;
    /** Persist the edited content and approve the suggestion. */
    onConfirm: (edits: AiAssessmentEdits) => void;
    /** Discard the edits and leave edit mode. */
    onCancel: () => void;
    saving?: boolean;
    replaced?: boolean;
    errorMessage?: string | null;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
}

function toAiAssessmentEdits(data: EditAssessmentData, original: Assessment): AiAssessmentEdits {
    // Never silently downgrade an editor confirmation to an unconditional approval.
    const edits: AiAssessmentEdits = { expected_fingerprint: original.approval_fingerprint ?? "" };
    if (data.justification !== undefined && data.justification !== (original.justification || ""))
        edits.justification = data.justification;
    const hasImpactField = ['not_affected', 'false_positive'].includes(original.status);
    if (hasImpactField &&
        data.impact_statement !== (original.impact_statement || "")) edits.impact_statement = data.impact_statement;
    if (data.status_notes !== initialStatusNotes(original)) {
        edits.status_notes = data.status_notes;
        if (!hasImpactField && !original.status_notes && original.impact_statement)
            edits.impact_statement = "";
    }
    if (data.workaround !== (original.workaround || "")) edits.workaround = data.workaround;
    return edits;
}

function parseAdditionalLink(item: string): RiskReference | null {
    const match = /^(R[1-9]\p{Nd}*(?:\\n)?)(?:\/(T[1-9]\p{Nd}*(?:\\n)?))?$/u.exec(item.trim());
    if (!match) return null;
    return { risk_id: match[1].replace(/\\n$/, '\n'),
        ...(match[2] && { threat_id: match[2].replace(/\\n$/, '\n') }) };
}

/** Edit the content of a pending AI assessment before approving it.
 *  Targets are not editable here: the suggestion keeps its packages/variants. */
function EditAiAssessment({
    assessment,
    variantNames,
    onConfirm,
    onCancel,
    saving = false,
    replaced = false,
    errorMessage,
    onFieldsChange,
    triggerBanner,
}: Readonly<Props>) {
    const [additions, setAdditions] = useState<Record<string, string>>({});
    const [removed, setRemoved] = useState<Record<string, boolean>>({});
    const [previews, setPreviews] = useState<Record<string, { current: RiskLinkPreview; confirmed: boolean } | string | null>>({});
    const [contentChanged, setContentChanged] = useState(false);
    const edits: TargetRiskEdit[] = [];
    let invalid = false;
    const controls = (assessment.targets ?? []).map(t => {
        if (!t.variant_id || t.risk_links_out_of_scope) return null;
        const key = JSON.stringify([t.variant_id, t.package]);
        const linkKey = (link: RiskReference) => JSON.stringify([key, link.risk_id, link.threat_id]);
        const confirmedRevision = (link: RiskReference) => {
            const state = previews[linkKey(link)];
            return state && typeof state === 'object' && state.confirmed ? state.current.revision : undefined;
        };
        const saved = t.risk_links ?? [];
        const retained = saved.filter(link => !removed[linkKey(link)]);
        const text = additions[key] ?? '';
        const added: RiskReference[] = [];
        for (const item of text.trim() ? text.split(',') : []) {
            const link = parseAdditionalLink(item);
            if (link) added.push(link);
            else invalid = true;
        }
        if (text.trim() || retained.length !== saved.length || retained.some(confirmedRevision)) {
            const kept = retained.map(link => {
                const { risk_id, threat_id } = link;
                const confirmed_revision = confirmedRevision(link);
                return { risk_id, ...(threat_id && { threat_id }), ...(confirmed_revision && { confirmed_revision }) };
            });
            edits.push({ package: t.package, variant_id: t.variant_id, risk_links: [...kept, ...added] });
        }
        const label = `${variantNames?.[t.variant_id] ?? t.variant_id} · ${t.package}`;
        return <div key={key} className="my-2">
            <label className="block">{label}
                <input aria-label={`Additional modeled risk IDs for ${label}`} value={text}
                    placeholder="R1/T2, R3" className="mx-2 px-2 bg-gray-700"
                    onChange={event => setAdditions({ ...additions, [key]: event.target.value })} />
            </label>
            <ModeledRiskLinks links={t.risk_links} />
            {saved.map(link => {
                const k = linkKey(link);
                const id = displayModelId(link.risk_id) + (link.threat_id ? `/${displayModelId(link.threat_id)}` : '');
                const keep = <label className="block">
                    <input type="checkbox" checked={!removed[k]} onChange={event =>
                        setRemoved({ ...removed, [k]: !event.target.checked })} /> Keep {id}
                </label>;
                if (!link.stale || removed[k]) return <div key={k}>{keep}</div>;
                const preview = previews[k];
                if (!preview || typeof preview === 'string') return <div key={k}>{keep}
                    <button type="button" disabled={preview === null} onClick={async () => {
                        setPreviews(old => ({ ...old, [k]: null }));
                        try {
                            const current = await Assessments.previewRiskLink(assessment.id, t.variant_id!, t.package, link);
                            setPreviews(old => ({ ...old, [k]: { current, confirmed: false } }));
                        } catch (error) {
                            setPreviews(old => ({ ...old, [k]: String(error) }));
                        }
                    }}>Compare current {id}</button>
                    {preview && <span role="alert">{preview}</span>}
                </div>;
                const { risk_description, threat_description, threat_target_ids } = preview.current;
                return <div key={k}>{keep}<label className="block">
                    <input type="checkbox" checked={preview.confirmed} onChange={e => {
                        const confirmed = e.target.checked;
                        setPreviews(old => ({ ...old, [k]: { ...preview, confirmed } }));
                    }} />
                    Reconfirm {id} using the current description: {risk_description}
                    {threat_description && `; ${threat_description}`}
                    {threat_target_ids && `; current targets: ${describeThreatTargets(preview.current) || 'none'}`}
                </label></div>;
            })}
        </div>;
    });
    const linksChanged = edits.length > 0;
    useEffect(() => onFieldsChange?.(contentChanged || linksChanged), [onFieldsChange, contentChanged, linksChanged]);
    return (<>
        <fieldset disabled={saving || replaced} className="p-4 text-sm">
            <legend>Modeled risk links by target</legend>
            <p>Uncheck saved links to remove them. To add links, enter IDs from this variant’s model,
                separated by commas. Use R1 or R1/T2. A trailing \n denotes a newline in an ID.</p>
            {controls}
            {invalid && <p role="alert">Use a risk ID, optionally followed by / and a threat ID.</p>}
        </fieldset>
        <EditAssessment
            assessment={assessment}
            onSaveAssessment={data => onConfirm({
                ...toAiAssessmentEdits(data, assessment), ...(linksChanged && { target_risk_links: edits }),
            })}
            onCancel={onCancel}
            onFieldsChange={setContentChanged}
            triggerBanner={triggerBanner}
            contentOnly={true}
            requireMessage={true}
            allowImpactInsteadOfJustification
            title="Edit AI assessment"
            saveLabel={saving ? "Approving…" : "Confirm and approve"}
            cancelLabel="Cancel changes"
            saving={saving}
            saveDisabled={replaced || invalid}
            errorMessage={replaced ? "This suggestion is no longer pending here. Copy your draft or cancel changes." : errorMessage}
        />
    </>);
}

export default EditAiAssessment;
