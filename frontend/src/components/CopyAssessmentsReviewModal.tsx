import { useEffect, useReducer, useCallback } from "react";
import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy, faXmark, faChevronDown, faChevronRight } from "@fortawesome/free-solid-svg-icons";
import type {
    CopyAssessmentsPreviewGroup,
    CopyAssessmentsPreviewCandidate,
    CopyAssessmentsSelection,
    CopyAssessmentsAssessmentDetails,
} from "../handlers/variant";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RowState = {
    /** Whether the row checkbox is checked (will be included in copy). */
    selected: boolean;
    /** Index into `candidates` for the chosen target finding. */
    candidateIndex: number;
    /** Whether the assessment-details sub-row is visible. */
    expanded: boolean;
};

type ModalState = {
    /** Per-group row state, keyed by source_assessment_id. */
    rows: Record<string, RowState>;
};

type Action =
    | { type: "TOGGLE"; assessmentId: string }
    | { type: "TOGGLE_EXPAND"; assessmentId: string }
    | { type: "SET_CANDIDATE"; assessmentId: string; index: number }
    | { type: "SELECT_ALL" }
    | { type: "DESELECT_ALL" };

function buildInitialState(groups: CopyAssessmentsPreviewGroup[]): ModalState {
    const rows: Record<string, RowState> = {};
    for (const g of groups) {
        const defaultIndex = g.candidates.findIndex((c) => c.selected);
        rows[g.source_assessment_id] = {
            selected: defaultIndex >= 0,
            candidateIndex: Math.max(0, defaultIndex),
            expanded: true,
        };
    }
    return { rows };
}

function reducer(state: ModalState, action: Action): ModalState {
    switch (action.type) {
        case "TOGGLE": {
            const prev = state.rows[action.assessmentId];
            if (!prev) return state;
            return {
                ...state,
                rows: { ...state.rows, [action.assessmentId]: { ...prev, selected: !prev.selected } },
            };
        }
        case "TOGGLE_EXPAND": {
            const prev = state.rows[action.assessmentId];
            if (!prev) return state;
            return {
                ...state,
                rows: { ...state.rows, [action.assessmentId]: { ...prev, expanded: !prev.expanded } },
            };
        }
        case "SET_CANDIDATE": {
            const prev = state.rows[action.assessmentId];
            if (!prev) return state;
            return {
                ...state,
                rows: {
                    ...state.rows,
                    [action.assessmentId]: {
                        ...prev,
                        candidateIndex: action.index,
                        selected: true,
                    },
                },
            };
        }
        case "SELECT_ALL": {
            const next = { ...state.rows };
            for (const id of Object.keys(next)) {
                if (next[id]) next[id] = { ...next[id], selected: true };
            }
            return { ...state, rows: next };
        }
        case "DESELECT_ALL": {
            const next = { ...state.rows };
            for (const id of Object.keys(next)) {
                if (next[id]) next[id] = { ...next[id], selected: false };
            }
            return { ...state, rows: next };
        }
        default:
            return state;
    }
}

// ---------------------------------------------------------------------------
// Assessment-detail badge helpers
// ---------------------------------------------------------------------------

function statusBadgeClass(simplified: string): string {
    switch (simplified) {
        case "Not affected":       return "bg-emerald-700 text-emerald-100";
        case "Exploitable":        return "bg-red-800 text-red-100";
        case "Fixed":              return "bg-teal-700 text-teal-100";
        case "Pending Assessment": return "bg-amber-700 text-amber-100";
        case "False Positive":     return "bg-purple-700 text-purple-100";
        default:                   return "bg-slate-600 text-zinc-200";
    }
}

function AssessmentDetailRow({ details }: Readonly<{ details: CopyAssessmentsAssessmentDetails }>) {
    const fields: { label: string; value: string | null | undefined }[] = [
        { label: "Justification",    value: details.justification },
        { label: "Notes",            value: details.status_notes },
        { label: "Impact",           value: details.impact_statement },
        { label: "Workaround",       value: details.workaround },
        { label: "Responses",        value: details.responses?.length ? details.responses.join(", ") : null },
    ];
    const populated = fields.filter((f) => f.value);
    return (
        <div className="flex flex-wrap items-start gap-x-6 gap-y-1.5 text-xs">
            <span>
                <span className="text-zinc-400">Status: </span>
                <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                    statusBadgeClass(details.simplified_status)
                }`}>
                    {details.simplified_status || details.status || "—"}
                </span>
            </span>
            {populated.map(({ label, value }) => (
                <span key={label}>
                    <span className="text-zinc-400">{label}: </span>
                    <span className="text-zinc-200">{value}</span>
                </span>
            ))}
            {populated.length === 0 && !details.simplified_status && (
                <span className="text-zinc-500 italic">No additional details.</span>
            )}
        </div>
    );
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

type Props = {
    isOpen: boolean;
    groups: CopyAssessmentsPreviewGroup[];
    /** Summary message from the preview response (e.g. "3 assessments to copy"). */
    previewMessage?: string;
    /** Called with the final selections when the user confirms. */
    onConfirm: (selections: CopyAssessmentsSelection[]) => void;
    onCancel: () => void;
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function CopyAssessmentsReviewModal({ isOpen, groups, previewMessage, onConfirm, onCancel }: Readonly<Props>) {
    const [state, dispatch] = useReducer(reducer, groups, buildInitialState);

    // Escape key to close
    useEffect(() => {
        if (!isOpen) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") onCancel();
        };
        document.addEventListener("keydown", onKey);
        return () => document.removeEventListener("keydown", onKey);
    }, [isOpen, onCancel]);

    const handleConfirm = useCallback(() => {
        const selections: CopyAssessmentsSelection[] = [];
        for (const g of groups) {
            const rowState = state.rows[g.source_assessment_id];
            if (!rowState?.selected) continue;
            const candidate: CopyAssessmentsPreviewCandidate | undefined =
                g.candidates[rowState.candidateIndex];
            if (!candidate || candidate.already_has_custom) continue;
            selections.push({
                source_assessment_id: g.source_assessment_id,
                target_finding_id: candidate.target_finding_id,
            });
        }
        onConfirm(selections);
    }, [groups, state, onConfirm]);

    if (!isOpen) return null;

    const selectableCount = groups.filter((g) => {
        const rowState = state.rows[g.source_assessment_id];
        return rowState?.selected && !g.candidates[rowState.candidateIndex ?? 0]?.already_has_custom;
    }).length;

    const totalSelectable = groups.filter((g) => {
        const rowState = state.rows[g.source_assessment_id];
        // Has at least one non-already_has_custom candidate
        return g.candidates.some((c) => !c.already_has_custom) && rowState !== undefined;
    }).length;

    return (
        <div
            data-testid="copy-review-modal-backdrop"
            tabIndex={-1}
            onMouseDown={(e) => {
                if (e.target === e.currentTarget) onCancel();
            }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60"
        >
            <div className="relative w-full max-w-4xl max-h-[90vh] mx-4 flex flex-col rounded-lg shadow-2xl bg-slate-800 border border-slate-600">

                {/* Header */}
                <div className="flex items-center justify-between px-5 py-4 border-b border-slate-600">
                    <div className="flex items-center gap-2">
                        <FontAwesomeIcon icon={faCopy} className="text-cyan-400" aria-hidden="true" />
                        <div>
                            <h2 className="text-lg font-semibold text-white">Review Copy Alignments</h2>
                            {previewMessage && (
                                <p className="text-xs text-cyan-300 mt-0.5">{previewMessage}</p>
                            )}
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={onCancel}
                        className="text-zinc-400 hover:text-white hover:bg-slate-700 rounded-lg p-1.5 transition-colors"
                        aria-label="Close"
                    >
                        <FontAwesomeIcon icon={faXmark} className="w-4 h-4" aria-hidden="true" />
                    </button>
                </div>

                {/* Toolbar */}
                <div className="flex items-center gap-3 px-5 py-2 border-b border-slate-700/70 bg-slate-900/30">
                    <span className="text-xs text-zinc-400">
                        {selectableCount} of {totalSelectable} selected
                    </span>
                    <button
                        type="button"
                        onClick={() => dispatch({ type: "SELECT_ALL" })}
                        className="text-xs text-cyan-400 hover:text-cyan-300 underline"
                    >
                        Select all
                    </button>
                    <button
                        type="button"
                        onClick={() => dispatch({ type: "DESELECT_ALL" })}
                        className="text-xs text-zinc-400 hover:text-zinc-200 underline"
                    >
                        Deselect all
                    </button>
                </div>

                {/* Table */}
                <div className="flex-1 overflow-auto">
                    {groups.length === 0 ? (
                        <p className="px-5 py-6 text-sm text-zinc-400 text-center">
                            No alignments found for the selected options.
                        </p>
                    ) : (
                        <table className="min-w-full text-sm text-zinc-200">
                            <thead className="sticky top-0 bg-slate-800 text-zinc-300 text-xs uppercase tracking-wide z-10">
                                <tr>
                                    <th className="px-4 py-2 text-left w-10">Copy</th>
                                    <th className="px-4 py-2 text-left">Vulnerability</th>
                                    <th className="px-4 py-2 text-left">Source package</th>
                                    <th className="px-4 py-2 text-left">Target package</th>
                                    <th className="px-4 py-2 w-8" />
                                </tr>
                            </thead>
                            <tbody>
                                {groups.map((g) => {
                                    const rowState = state.rows[g.source_assessment_id];
                                    const candidateIndex = rowState?.candidateIndex ?? 0;
                                    const currentCandidate = g.candidates[candidateIndex];
                                    const isChecked = rowState?.selected ?? false;
                                    const isDisabled = g.candidates.every((c) => c.already_has_custom);
                                    const isExpanded = rowState?.expanded ?? false;

                                    return (
                                        <React.Fragment key={g.source_assessment_id}>
                                        <tr
                                            className={[
                                                "border-t border-slate-700/60 transition-colors",
                                                isDisabled ? "opacity-50" : "hover:bg-slate-700/30",
                                            ].join(" ")}
                                        >
                                            {/* Checkbox */}
                                            <td className="px-4 py-2">
                                                <input
                                                    type="checkbox"
                                                    checked={isChecked && !isDisabled}
                                                    disabled={isDisabled}
                                                    onChange={() => dispatch({ type: "TOGGLE", assessmentId: g.source_assessment_id })}
                                                    className="rounded border-slate-500 bg-slate-900 text-cyan-500 focus:ring-cyan-500 disabled:cursor-not-allowed"
                                                    aria-label={`Include ${g.vulnerability_id}`}
                                                />
                                            </td>

                                            {/* Vulnerability ID */}
                                            <td className="px-4 py-2 font-mono text-xs text-cyan-300 whitespace-nowrap">
                                                {g.vulnerability_id}
                                            </td>

                                            {/* Source package */}
                                            <td className="px-4 py-2 font-mono text-xs text-zinc-300 whitespace-nowrap">
                                                {g.source_package || "—"}
                                            </td>

                                            {/* Target package — dropdown if multiple candidates */}
                                            <td className="px-4 py-2">
                                                {g.candidates.length === 1 ? (
                                                    <span className={[
                                                        "font-mono text-xs",
                                                        currentCandidate?.already_has_custom
                                                            ? "text-amber-400"
                                                            : "text-zinc-300",
                                                    ].join(" ")}>
                                                        {currentCandidate?.target_package || "—"}
                                                        {currentCandidate?.already_has_custom && (
                                                            <span className="ml-1 text-amber-500 text-[10px]">(already assessed)</span>
                                                        )}
                                                    </span>
                                                ) : (
                                                    <select
                                                        value={candidateIndex}
                                                        onChange={(e) =>
                                                            dispatch({
                                                                type: "SET_CANDIDATE",
                                                                assessmentId: g.source_assessment_id,
                                                                index: Number(e.target.value),
                                                            })
                                                        }
                                                        disabled={isDisabled}
                                                        className="w-full rounded border border-slate-600 bg-slate-900 text-xs text-zinc-200 px-2 py-1 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-1 focus:ring-cyan-500"
                                                        aria-label={`Target for ${g.vulnerability_id}`}
                                                    >
                                                        {g.candidates.map((c, i) => (
                                                            <option key={c.target_finding_id} value={i}>
                                                                {c.target_package || "—"}
                                                                {c.already_has_custom ? " (already assessed)" : ""}
                                                            </option>
                                                        ))}
                                                    </select>
                                                )}
                                            </td>

                                            {/* Expand / collapse details */}
                                            <td className="px-2 py-2 text-center">
                                                <button
                                                    type="button"
                                                    onClick={() => dispatch({ type: "TOGGLE_EXPAND", assessmentId: g.source_assessment_id })}
                                                    className="text-zinc-500 hover:text-zinc-200 transition-colors"
                                                    aria-label={`${isExpanded ? "Collapse" : "Expand"} details for ${g.vulnerability_id}`}
                                                    aria-expanded={isExpanded}
                                                >
                                                    <FontAwesomeIcon
                                                        icon={isExpanded ? faChevronDown : faChevronRight}
                                                        className="w-3 h-3"
                                                        aria-hidden="true"
                                                    />
                                                </button>
                                            </td>
                                        </tr>

                                        {/* Assessment details sub-row */}
                                        {isExpanded && (
                                            <tr
                                                key={`${g.source_assessment_id}-details`}
                                                className="bg-slate-900/60 border-b border-slate-700/30"
                                            >
                                                <td colSpan={5} className="px-8 pb-3 pt-2">
                                                    {g.assessment_details
                                                        ? <AssessmentDetailRow details={g.assessment_details} />
                                                        : <span className="text-xs text-zinc-500 italic">No details available.</span>
                                                    }
                                                </td>
                                            </tr>
                                        )}
                                        </React.Fragment>
                                    );
                                })}
                            </tbody>
                        </table>
                    )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between gap-3 px-5 py-4 border-t border-slate-600 bg-slate-900/40">
                    <p className="text-xs text-zinc-400">
                        {selectableCount === 0
                            ? "Nothing selected — confirm to copy nothing."
                            : `${selectableCount} assessment${selectableCount !== 1 ? "s" : ""} will be copied.`}
                    </p>
                    <div className="flex gap-3">
                        <button
                            type="button"
                            onClick={onCancel}
                            className="px-4 py-2 text-sm font-medium text-zinc-300 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            onClick={handleConfirm}
                            className="px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors"
                        >
                            <FontAwesomeIcon icon={faCopy} className="mr-2" aria-hidden="true" />
                            Confirm Copy
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default CopyAssessmentsReviewModal;
