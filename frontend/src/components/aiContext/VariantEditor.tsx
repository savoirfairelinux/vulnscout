import { useRef } from "react";
import type { KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import type { ContextFile, VariantDraft } from "../../handlers/context";
import ContextTab from "./ContextTab";
import SystemTab from "./SystemTab";
import ThreatModelTab from "./ThreatModelTab";
import RisksTab from "./RisksTab";
import { BADGE_VARIANT, BUTTON_PRIMARY, BUTTON_SECONDARY, PANEL } from "./styles";

export type VariantTab = 'context' | 'system' | 'threat_model' | 'risks';

type Props = {
    variantId: string;
    variantName: string;
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    files: ContextFile[];
    onSave: () => void;
    saving: boolean;
    dirty: boolean;
    /** Opens the copy dialog; the button is disabled without it. */
    onCopyFrom?: () => void;
    fieldErrors: Record<string, string>;
    notify: (message: string, type: 'success' | 'error') => void;
    /** Changes whenever the draft is loaded, reset or saved; per-draft UI state starts over. */
    draftGeneration: number;
    tab: VariantTab;
    onTabChange: (tab: VariantTab) => void;
};

const TABS: { key: VariantTab; label: string }[] = [
    { key: 'context', label: 'Context' },
    { key: 'system', label: 'System' },
    { key: 'threat_model', label: 'Threat model' },
    { key: 'risks', label: 'Risks' },
];

const tabId = (key: VariantTab) => `ai-variant-tab-${key}`;
const panelId = (key: VariantTab) => `ai-variant-panel-${key}`;
const TAB = "px-4 py-2 text-sm font-semibold border-b-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400";

/** Target tab for a tablist key press (arrows wrap, Home/End jump), or null for other keys. */
function keyTarget(key: string, index: number): number | null {
    const last = TABS.length - 1;
    if (key === 'ArrowRight') return index === last ? 0 : index + 1;
    if (key === 'ArrowLeft') return index === 0 ? last : index - 1;
    if (key === 'Home') return 0;
    if (key === 'End') return last;
    return null;
}

function VariantEditor({
    variantId, variantName, draft, onDraftChange, files, onSave, saving, dirty,
    onCopyFrom, fieldErrors, notify, draftGeneration, tab, onTabChange,
}: Readonly<Props>) {
    const tabRefs = useRef<Partial<Record<VariantTab, HTMLButtonElement | null>>>({});

    // Automatic activation: moving focus also selects the tab.
    const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
        const target = keyTarget(event.key, index);
        if (target === null) return;
        event.preventDefault();
        const next = TABS[target].key;
        onTabChange(next);
        tabRefs.current[next]?.focus();
    };

    return (
        <section aria-labelledby="ai-variant-heading" className={`${PANEL} space-y-3`}>
            <div className="flex flex-wrap items-center gap-3">
                <h2 id="ai-variant-heading" className="text-xl font-bold text-white">{variantName}</h2>
                <span className={BADGE_VARIANT}>Variant</span>
                <button type="button" onClick={onCopyFrom} disabled={!onCopyFrom || saving} className={BUTTON_SECONDARY}>
                    Copy from…
                </button>
                <button type="button" onClick={onSave} disabled={!dirty || saving} className={`${BUTTON_PRIMARY} ml-auto`}>
                    {saving && <FontAwesomeIcon icon={faSpinner} spin />}
                    Save changes
                </button>
            </div>
            <div role="tablist" aria-label="Variant context sections" className="flex border-b border-slate-700">
                {TABS.map(({ key, label }, index) => {
                    const selected = key === tab;
                    return (
                        <button
                            key={key}
                            ref={element => { tabRefs.current[key] = element; }}
                            type="button"
                            role="tab"
                            id={tabId(key)}
                            aria-selected={selected}
                            aria-controls={panelId(key)}
                            tabIndex={selected ? 0 : -1}
                            onClick={() => onTabChange(key)}
                            onKeyDown={event => handleKeyDown(event, index)}
                            className={`${TAB} ${selected ? 'border-cyan-400 text-white' : 'border-transparent text-zinc-400 hover:text-zinc-200'}`}
                        >
                            {label}
                        </button>
                    );
                })}
            </div>
            {TABS.map(({ key }) => (
                <div key={key} role="tabpanel" id={panelId(key)} aria-labelledby={tabId(key)} hidden={key !== tab}>
                    {key === 'context' && (
                        <ContextTab
                            draft={draft}
                            onDraftChange={onDraftChange}
                            variantId={variantId}
                            files={files}
                            notify={notify}
                            fieldErrors={fieldErrors}
                            disabled={saving}
                        />
                    )}
                    {key === 'system' && (
                        <SystemTab
                            key={`${variantId}:${draftGeneration}`}
                            draft={draft}
                            onDraftChange={onDraftChange}
                            fieldErrors={fieldErrors}
                            disabled={saving}
                        />
                    )}
                    {key === 'threat_model' && (
                        <ThreatModelTab
                            key={`${variantId}:${draftGeneration}`}
                            draft={draft}
                            onDraftChange={onDraftChange}
                            fieldErrors={fieldErrors}
                            disabled={saving}
                        />
                    )}
                    {key === 'risks' && (
                        <RisksTab
                            draft={draft}
                            onDraftChange={onDraftChange}
                            fieldErrors={fieldErrors}
                            disabled={saving}
                        />
                    )}
                </div>
            ))}
        </section>
    );
}

export default VariantEditor;
