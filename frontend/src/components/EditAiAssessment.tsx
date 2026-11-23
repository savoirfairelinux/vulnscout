import { useState, useEffect } from "react";
import EditAssessment from "./EditAssessment";
import ModeledRiskLinks from "./ModeledRiskLinks";
import Assessments, { describeThreatTargets, initialStatusNotes } from "../handlers/assessments";
import type { EditAssessmentData } from "./EditAssessment";
import type { AiAssessmentEdits, Assessment, RiskLinkPreview, TargetRiskEdit } from "../handlers/assessments";

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
    const [drafts, setDrafts] = useState<Record<string, string>>({});
    const [previews, setPreviews] = useState<Record<string, { current: RiskLinkPreview; confirmed: boolean } | string | null>>({});
    const [contentChanged, setContentChanged] = useState(false);
    const edits: TargetRiskEdit[] = [];
    let invalid = false;
    const controls = (assessment.targets ?? []).map(t => {
        if (!t.variant_id || t.risk_links_out_of_scope) return null;
        const key = JSON.stringify([t.variant_id, t.package]);
        const confirmationKey = (id: string) => JSON.stringify([key, id]);
        const confirmedRevision = (id: string) => {
            const state = previews[confirmationKey(id)];
            return state && typeof state === 'object' && state.confirmed ? state.current.revision : undefined;
        };
        const initial = (t.risk_links ?? []).map(l => [l.risk_id, l.threat_id].filter(Boolean).join('/')).join(', ');
        const text = drafts[key] ?? initial;
        const ids = text.trim() ? text.split(',').map(item => item.trim()) : [];
        if (text !== initial || ids.some(confirmedRevision)) {
            if (ids.some(id => !/^R[1-9]\d*(\/T[1-9]\d*)?$/.test(id))) invalid = true;
            edits.push({ package: t.package, variant_id: t.variant_id, risk_links: ids.map(id => {
                const [risk_id, threat_id] = id.split('/');
                const confirmed_revision = confirmedRevision(id);
                return { risk_id, ...(threat_id && { threat_id }), ...(confirmed_revision && { confirmed_revision }) };
            }) });
        }
        const label = `${variantNames?.[t.variant_id] ?? t.variant_id} · ${t.package}`;
        return <div key={key} className="my-2">
            <label className="block">{label}
                <input aria-label={`Modeled risk IDs for ${label}`} value={text}
                    placeholder="R1/T2, R3" className="mx-2 px-2 bg-gray-700"
                    onChange={event => setDrafts({ ...drafts, [key]: event.target.value })} />
            </label>
            <ModeledRiskLinks links={t.risk_links} />
            {t.risk_links?.map(link => {
                const id = [link.risk_id, link.threat_id].filter(Boolean).join('/');
                if (!link.stale || !ids.includes(id)) return null;
                const k = confirmationKey(id);
                const preview = previews[k];
                if (!preview || typeof preview === 'string') return <div key={id}>
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
                return <label key={id} className="block">
                    <input type="checkbox" checked={preview.confirmed} onChange={e => {
                        const confirmed = e.target.checked;
                        setPreviews(old => ({ ...old, [k]: { ...preview, confirmed } }));
                    }} />
                    Reconfirm {id} using the current description: {risk_description}
                    {threat_description && `; ${threat_description}`}
                    {threat_target_ids && `; current targets: ${describeThreatTargets(preview.current) || 'none'}`}
                </label>;
            })}
        </div>;
    });
    const linksChanged = edits.length > 0;
    useEffect(() => onFieldsChange?.(contentChanged || linksChanged), [onFieldsChange, contentChanged, linksChanged]);
    return (<>
        <fieldset disabled={saving || replaced} className="p-4 text-sm">
            <legend>Modeled risk links by target</legend>
            <p>Enter IDs from this variant’s model, separated by commas. Use R1 or R1/T2.
                Clear the field to remove its links. The original links are shown below each field.</p>
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
