import { useState, useEffect, useRef } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faCopy,
    faRightLeft,
    faSpinner,
    faTriangleExclamation,
    faCheck,
} from "@fortawesome/free-solid-svg-icons";
import Variants from "../handlers/variant";
import type {
    Variant,
    CopyMatchMode,
    CopyCondition,
    CopyAssessmentsPreview,
    CopyAssessmentsPreviewGroup,
    CopyAssessmentsPreviewCandidate,
    CopyAssessmentsPreviewUnsupported,
    CopyAssessmentsSelection,
} from "../handlers/variant";
import CopyAssessmentsReviewModal from "../components/CopyAssessmentsReviewModal";

type Props = {
    /** Project currently selected in the global selector; drives the variant lists. */
    projectId?: string;
    onDataChanged?: (message?: string) => void;
};

function Transfer({ projectId, onDataChanged }: Readonly<Props>) {
    // ---- Unmount guard for async operations ----
    const unmountedRef = useRef(false);
    useEffect(() => {
        unmountedRef.current = false;
        return () => { unmountedRef.current = true; };
    }, []);

    // The active project comes from the global project/variant selector.
    const customProjectId = projectId ?? "";

    // ---- Copy Custom Assessments state ----
    const [customProjectVariants, setCustomProjectVariants] = useState<Variant[]>([]);
    const [copySourceId, setCopySourceId] = useState<string>("");
    const [copyTargetId, setCopyTargetId] = useState<string>("");
    const [copyMatchMode, setCopyMatchMode] = useState<CopyMatchMode>("exact");
    const [copyVersionPrecision, setCopyVersionPrecision] = useState<number>(1);
    const [copyCondition, setCopyCondition] = useState<CopyCondition>("no_custom");
    const [copyBusy, setCopyBusy] = useState(false);
    const [copyMsg, setCopyMsg] = useState<string | null>(null);
    const [copyPreviewBusy, setCopyPreviewBusy] = useState(false);
    const [copyPreviewError, setCopyPreviewError] = useState<string | null>(null);
    const [copyPreview, setCopyPreview] = useState<CopyAssessmentsPreview | null>(null);
    const [copyPreviewUnavailableMsg, setCopyPreviewUnavailableMsg] = useState<string | null>(null);
    const [copyReviewOpen, setCopyReviewOpen] = useState(false);
    const [copyReviewGroups, setCopyReviewGroups] = useState<CopyAssessmentsPreviewGroup[]>([]);
    const [reviewKey, setReviewKey] = useState(0);

    // ---- Handlers ----
    const handleCopyFromReview = async (selections: CopyAssessmentsSelection[]) => {
        setCopyReviewOpen(false);
        if (!copySourceId || !copyTargetId || copyBusy) return;
        setCopyBusy(true);
        setCopyMsg(null);
        try {
            const result = await Variants.copyAssessments(
                copySourceId,
                copyTargetId,
                copyMatchMode,
                copyVersionPrecision,
                selections,
                copyCondition,
            );
            setCopyMsg(result.message);
            onDataChanged?.("Copying assessments...");
        } catch (e: any) {
            setCopyMsg(e.message);
        } finally {
            setCopyBusy(false);
        }
    };

    const handleOpenReview = () => {
        if (!copyPreview) return;
        let groups: CopyAssessmentsPreviewGroup[];
        if (copyPreview.mode === "exact") {
            // Convert flat entries to groups — one candidate per group, all pre-selected
            groups = (copyPreview.entries ?? []).map(
                (entry): CopyAssessmentsPreviewGroup => ({
                    source_assessment_id: entry.source_assessment_id,
                    source_finding_id:    entry.source_finding_id,
                    vulnerability_id:     entry.vulnerability_id,
                    source_package:       entry.source_package,
                    assessment_details:   entry.assessment_details,
                    candidates: [{
                        target_finding_id:  entry.target_finding_id,
                        target_package:     entry.target_package,
                        already_has_custom: entry.already_has_custom ?? false,
                        selected:           entry.selected ?? !(entry.already_has_custom ?? false),
                    } satisfies CopyAssessmentsPreviewCandidate],
                })
            );
        } else {
            groups = copyPreview.groups ?? [];
        }
        setCopyReviewGroups(groups);
        setReviewKey((k) => k + 1);
        setCopyReviewOpen(true);
    };

    // ---- Effects ----
    useEffect(() => {
        // Reset any in-progress selection whenever the active project changes.
        setCopySourceId("");
        setCopyTargetId("");
        setCopyMsg(null);
        setCopyPreview(null);
        setCopyPreviewError(null);
        setCopyPreviewUnavailableMsg(null);
        setCopyPreviewBusy(false);
        if (!customProjectId) {
            setCustomProjectVariants([]);
            return;
        }
        Variants.list(customProjectId)
            .then(setCustomProjectVariants)
            .catch(() => setCustomProjectVariants([]));
    }, [customProjectId]);

    useEffect(() => {
        if (!customProjectId || !copySourceId || !copyTargetId || copySourceId === copyTargetId) {
            setCopyPreview(null);
            setCopyPreviewError(null);
            setCopyPreviewUnavailableMsg(null);
            setCopyPreviewBusy(false);
            return;
        }

        let cancelled = false;
        setCopyPreviewBusy(true);
        setCopyPreviewError(null);
        setCopyPreviewUnavailableMsg(null);

        Variants.previewCopyAssessments(copySourceId, copyTargetId, copyMatchMode, copyVersionPrecision, copyCondition)
            .then((data) => {
                if (cancelled || unmountedRef.current) return;
                if ((data as CopyAssessmentsPreviewUnsupported).unsupported) {
                    setCopyPreview(null);
                    setCopyPreviewUnavailableMsg(data.message);
                    return;
                }
                setCopyPreview(data as CopyAssessmentsPreview);
            })
            .catch((e: any) => {
                if (cancelled || unmountedRef.current) return;
                setCopyPreview(null);
                setCopyPreviewUnavailableMsg(null);
                setCopyPreviewError(e?.message || "Failed to generate preview.");
            })
            .finally(() => {
                if (cancelled || unmountedRef.current) return;
                setCopyPreviewBusy(false);
            });

        return () => { cancelled = true; };
    }, [customProjectId, copySourceId, copyTargetId, copyMatchMode, copyVersionPrecision, copyCondition]);

    // ---- Styles ----
    const inputClass =
        "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400";
    const selectClass = inputClass;
    const btnPrimary =
        "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
    const cardHeader =
        "bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60";
    const cardBody =
        "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 shadow-lg shadow-black/20";

    return (
        <div className="w-full">
            <div className="w-full space-y-6">
                <h1 className="text-3xl font-bold text-white mb-2">Transfer</h1>

                {/* ======== Copy Custom Assessments ======== */}
                <section
                    aria-labelledby="transfer-heading-copy"
                    aria-disabled={!customProjectId}
                    className={!customProjectId ? "opacity-50" : ""}
                >
                    <div className={cardHeader}>
                        <FontAwesomeIcon icon={faCopy} className="text-cyan-400" aria-hidden="true" />
                        <h2 id="transfer-heading-copy" className="text-xl font-bold text-white">Copy Custom Assessments</h2>
                    </div>
                    <div className={cardBody + " space-y-4"}>
                        <p className="text-sm text-zinc-400">
                            Copy custom assessments from a source variant to a target variant in the selected project.
                        </p>

                        {!customProjectId && (
                            <p className="text-amber-300 text-sm">
                                Select a project or variant from the selector above to copy assessments.
                            </p>
                        )}

                        {/* ---- Source / Target selectors ---- */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <label htmlFor="copy-source-select" className="block text-sm text-zinc-300 font-semibold">Source</label>
                                <select
                                    id="copy-source-select"
                                    value={copySourceId}
                                    onChange={(e) => {
                                        setCopySourceId(e.target.value);
                                        setCopyMsg(null);
                                        setCopyPreviewError(null);
                                        setCopyPreviewUnavailableMsg(null);
                                    }}
                                    className={selectClass + " disabled:opacity-50 disabled:cursor-not-allowed"}
                                    disabled={!customProjectId}
                                >
                                    <option value="">— select a variant —</option>
                                    {customProjectVariants.map((v) => (
                                        <option key={v.id} value={v.id}>{v.name}</option>
                                    ))}
                                </select>
                            </div>
                            <div className="flex items-end justify-center sm:justify-start">
                                <button
                                    type="button"
                                    onClick={() => {
                                        if (!customProjectId || copyBusy) return;
                                        setCopySourceId(copyTargetId);
                                        setCopyTargetId(copySourceId);
                                        setCopyMsg(null);
                                        setCopyPreviewError(null);
                                        setCopyPreviewUnavailableMsg(null);
                                    }}
                                    disabled={!customProjectId || copyBusy || !copySourceId || !copyTargetId}
                                    className="px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                                    title="Swap source and target variants"
                                    aria-label="Swap source and target variants"
                                >
                                    <FontAwesomeIcon icon={faRightLeft} className="mr-2" aria-hidden="true" />
                                    Swap
                                </button>
                            </div>
                            <div className="space-y-2">
                                <label htmlFor="copy-target-select" className="block text-sm text-zinc-300 font-semibold">Copy to</label>
                                <select
                                    id="copy-target-select"
                                    value={copyTargetId}
                                    onChange={(e) => {
                                        setCopyTargetId(e.target.value);
                                        setCopyMsg(null);
                                        setCopyPreviewError(null);
                                        setCopyPreviewUnavailableMsg(null);
                                    }}
                                    className={selectClass + " disabled:opacity-50 disabled:cursor-not-allowed"}
                                    disabled={!customProjectId}
                                >
                                    <option value="">— select a variant —</option>
                                    {customProjectVariants.map((v) => (
                                        <option key={v.id} value={v.id}>{v.name}</option>
                                    ))}
                                </select>
                            </div>
                        </div>

                        {/* ---- Copy condition ---- */}
                        <div className="space-y-2">
                            <p className="text-sm font-semibold text-zinc-300">Conditions to copy assessments</p>
                            <div className="grid grid-cols-1 gap-2">
                                {([
                                    { value: "no_custom",        label: "Target has no custom assessment",                    desc: "Only copy onto \u201cCopy to\u201d findings that have no custom assessment yet." },
                                    { value: "different_status", label: "Target has a different status",                      desc: "Also copy when the target already has a custom assessment with a different status." },
                                    { value: "different_value",  label: "Target differs in any value",                       desc: "Also copy when the target's custom assessment differs in status, justification, workaround or any other value." },
                                ] as { value: CopyCondition; label: string; desc: string }[]).map(({ value, label, desc }) => (
                                    <label
                                        key={value}
                                        className={[
                                            "flex items-start gap-2 rounded-lg border px-3 py-2 cursor-pointer transition-colors",
                                            copyCondition === value
                                                ? "border-cyan-500 bg-cyan-950/40 text-white"
                                                : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                            (!customProjectId || copyBusy) ? "opacity-50 cursor-not-allowed" : "",
                                        ].join(" ")}
                                    >
                                        <input
                                            type="radio"
                                            name="copy-condition"
                                            value={value}
                                            checked={copyCondition === value}
                                            disabled={!customProjectId || copyBusy}
                                            onChange={() => {
                                                setCopyCondition(value);
                                                setCopyMsg(null);
                                                setCopyPreviewError(null);
                                                setCopyPreviewUnavailableMsg(null);
                                            }}
                                            className="mt-0.5 accent-cyan-500"
                                        />
                                        <span className="flex flex-col">
                                            <span className="text-sm font-medium">{label}</span>
                                            <span className="text-xs text-zinc-400">{desc}</span>
                                        </span>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {/* ---- Matching mode ---- */}
                        <div className="space-y-2">
                            <p className="text-sm font-semibold text-zinc-300">How should packages be matched?</p>
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                                {([
                                    { value: "exact",                precision: 1, label: "Same Versions",                 desc: "Package name and full version must match (e.g. 6.5.1 \u2192 6.5.1)" },
                                    { value: "ignore_minor_version", precision: 2, label: "Same Major and Minor Versions", desc: "Major and minor must match; patch may differ (e.g. 6.5.1 \u2192 6.5.9)" },
                                    { value: "ignore_minor_version", precision: 1, label: "Same Major Versions",           desc: "Major must match; minor and patch may differ (e.g. 6.5.1 \u2192 6.9.0)" },
                                    { value: "ignore_version",       precision: 1, label: "Any Versions",                  desc: "Same name; version is ignored (e.g. 6.5.1 \u2192 7.0.0)" },
                                ] as { value: CopyMatchMode; precision: number; label: string; desc: string }[]).map(({ value, precision, label, desc }) => {
                                    const selected = copyMatchMode === value && (value === "ignore_minor_version" ? copyVersionPrecision === precision : true);
                                    return (
                                    <label
                                        key={label}
                                        className={[
                                            "flex items-start gap-2 rounded-lg border px-3 py-2 cursor-pointer transition-colors",
                                            selected
                                                ? "border-cyan-500 bg-cyan-950/40 text-white"
                                                : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                            (!customProjectId || copyBusy) ? "opacity-50 cursor-not-allowed" : "",
                                        ].join(" ")}
                                    >
                                        <input
                                            type="radio"
                                            name="copy-match-mode"
                                            value={label}
                                            checked={selected}
                                            disabled={!customProjectId || copyBusy}
                                            onChange={() => {
                                                setCopyMatchMode(value);
                                                setCopyVersionPrecision(precision);
                                                setCopyMsg(null);
                                                setCopyPreviewError(null);
                                                setCopyPreviewUnavailableMsg(null);
                                            }}
                                            className="mt-0.5 accent-cyan-500"
                                        />
                                        <span className="flex flex-col">
                                            <span className="text-sm font-medium">{label}</span>
                                            <span className="text-xs text-zinc-400">{desc}</span>
                                        </span>
                                    </label>
                                    );
                                })}
                            </div>
                        </div>

                        {/* ---- Preview summary ---- */}
                        {copyPreviewBusy && (
                            <p className="text-xs text-zinc-400">
                                <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                                Computing preview…
                            </p>
                        )}
                        {!copyPreviewBusy && copyPreview && (
                            <p className="text-xs text-cyan-300">{copyPreview.message}</p>
                        )}

                        {/* ---- Action button ---- */}
                        {copyPreviewError && (
                            <p className="text-xs text-red-300">
                                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                                {copyPreviewError}
                            </p>
                        )}
                        {copyPreviewUnavailableMsg && (
                            <p className="text-xs text-amber-300">
                                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                                {copyPreviewUnavailableMsg}
                            </p>
                        )}
                        <button
                                onClick={handleOpenReview}
                                disabled={
                                    !customProjectId || !copySourceId || !copyTargetId ||
                                    copySourceId === copyTargetId || copyBusy ||
                                    copyPreviewBusy || !!copyPreviewError || !!copyPreviewUnavailableMsg || !copyPreview
                                }
                                className={btnPrimary}
                            >
                                {(copyBusy || copyPreviewBusy) ? (
                                    <FontAwesomeIcon icon={faSpinner} spin className="mr-2" aria-hidden="true" />
                                ) : (
                                    <FontAwesomeIcon icon={faCopy} className="mr-2" aria-hidden="true" />
                                )}
                                {copyPreviewBusy ? "Loading preview…" : "Preview & Copy"}
                            </button>

                        {copyMsg && (
                            <span role="alert" className="block text-sm text-cyan-300">
                                <FontAwesomeIcon icon={faCheck} className="mr-1" aria-hidden="true" />
                                {copyMsg}
                            </span>
                        )}
                    </div>
                </section>
            </div>

            {/* ======== Review popup ======== */}
            <CopyAssessmentsReviewModal
                key={reviewKey}
                isOpen={copyReviewOpen}
                groups={copyReviewGroups}
                previewMessage={copyPreview?.message}
                onConfirm={handleCopyFromReview}
                onCancel={() => setCopyReviewOpen(false)}
            />
        </div>
    );
}

export default Transfer;
