// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

import { useEffect, useState } from "react";
import type { ImportMatchMode, Variant } from "../handlers/variant";

type Props = {
    isOpen: boolean;
    /** All selectable target variants. */
    variants: Variant[];
    /** Pre-selected variant ID (e.g. from the global selector). */
    initialVariantId?: string;
    onConfirm: (mode: ImportMatchMode, variantId: string) => void;
    onCancel: () => void;
};

const MATCH_MODE_OPTIONS: {
    value: ImportMatchMode;
    label: string;
    desc: string;
}[] = [
    {
        value: "exact",
        label: "Exact version",
        desc: "Package name and full version must match. Only imports assessments for packages present with the same version.",
    },
    {
        value: "ignore_minor_version",
        label: "Same major version",
        desc: "Package name and major version must match; minor and patch may differ (e.g. 1.16 \u2192 1.17 \u2713, 1.x \u2192 2.x \u2717).",
    },
    {
        value: "ignore_version",
        label: "Any version",
        desc: "Package name only; version is ignored. Imports assessments onto any observed finding for that package regardless of version.",
    },
];

/**
 * Dialog that lets the user choose a target variant and a package match mode
 * before the custom-data import preview is generated.
 */
function ImportMatchModeDialog({
    isOpen,
    variants,
    initialVariantId,
    onConfirm,
    onCancel,
}: Readonly<Props>) {
    const [selectedMode, setSelectedMode] = useState<ImportMatchMode>("exact");
    const [selectedVariantId, setSelectedVariantId] = useState<string>(initialVariantId ?? "");
    const [variantError, setVariantError] = useState<string | null>(null);

    // Reset to defaults whenever the dialog opens
    useEffect(() => {
        if (isOpen) {
            setSelectedMode("exact");
            setSelectedVariantId(initialVariantId ?? "");
            setVariantError(null);
        }
    }, [isOpen, initialVariantId]);

    useEffect(() => {
        if (!isOpen) return;
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === "Escape") onCancel();
        };
        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, [isOpen, onCancel]);

    const handleConfirm = () => {
        if (!selectedVariantId) {
            setVariantError("Please select a target variant.");
            return;
        }
        setVariantError(null);
        onConfirm(selectedMode, selectedVariantId);
    };

    if (!isOpen) return null;

    return (
        <div
            data-testid="import-match-mode-dialog-backdrop"
            tabIndex={-1}
            onMouseDown={(e) => {
                if (e.target === e.currentTarget) onCancel();
            }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60"
        >
            <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="import-match-mode-title"
                className="relative w-full max-w-md mx-4"
            >
                <div className="relative bg-slate-800 rounded-lg shadow-xl ring-1 ring-slate-600">
                    {/* Header */}
                    <div className="flex items-center justify-between px-5 py-4 border-b border-slate-600">
                        <h3 id="import-match-mode-title" className="text-base font-semibold text-white">
                            Import custom data
                        </h3>
                        <button
                            type="button"
                            aria-label="Close"
                            onClick={onCancel}
                            className="text-zinc-400 hover:text-white hover:bg-slate-700 rounded-lg p-1.5 transition-colors"
                        >
                            <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                        </button>
                    </div>

                    {/* Body */}
                    <div className="px-5 py-4 space-y-4">
                        <p className="text-sm text-zinc-400">
                            Assessments in the file will only be applied to findings <strong className="text-zinc-200">actually observed</strong> in the target variant's scans.
                        </p>
                        <p className="text-xs text-zinc-500">
                            CVSS scores and time estimates in the file are always imported, regardless of the selected assessments.
                        </p>

                        {/* Variant selector */}
                        <div className="space-y-1.5">
                            <label htmlFor="import-target-variant" className="block text-sm font-semibold text-zinc-300">
                                Target variant
                            </label>
                            <select
                                id="import-target-variant"
                                data-testid="import-target-variant-select"
                                value={selectedVariantId}
                                onChange={(e) => {
                                    setSelectedVariantId(e.target.value);
                                    if (e.target.value) setVariantError(null);
                                }}
                                className={[
                                    "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border text-white focus:outline-none focus:border-cyan-400",
                                    variantError ? "border-red-500" : "border-slate-600",
                                ].join(" ")}
                            >
                                <option value="">— select a variant —</option>
                                {variants.map((v) => (
                                    <option key={v.id} value={v.id}>{v.name}</option>
                                ))}
                            </select>
                            {variantError && (
                                <p className="text-xs text-red-400" role="alert" data-testid="import-variant-error">
                                    {variantError}
                                </p>
                            )}
                        </div>

                        {/* Match mode radios */}
                        <div className="space-y-1.5">
                            <p className="text-sm font-semibold text-zinc-300">Package matching mode</p>
                            <div className="grid grid-cols-1 gap-2">
                                {MATCH_MODE_OPTIONS.map(({ value, label, desc }) => (
                                    <label
                                        key={value}
                                        data-testid={`import-match-mode-option-${value}`}
                                        className={[
                                            "flex items-start gap-3 rounded-lg border px-4 py-3 cursor-pointer transition-colors",
                                            selectedMode === value
                                                ? "border-cyan-500 bg-cyan-950/40 text-white"
                                                : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                                        ].join(" ")}
                                    >
                                        <input
                                            type="radio"
                                            name="import-match-mode"
                                            value={value}
                                            checked={selectedMode === value}
                                            onChange={() => setSelectedMode(value)}
                                            className="mt-0.5 accent-cyan-500"
                                            data-testid={`import-match-mode-radio-${value}`}
                                        />
                                        <span className="flex flex-col">
                                            <span className="text-sm font-medium">{label}</span>
                                            <span className="text-xs text-zinc-400">{desc}</span>
                                        </span>
                                    </label>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Footer */}
                    <div className="flex justify-end gap-3 px-5 py-4 border-t border-slate-600">
                        <button
                            type="button"
                            onClick={onCancel}
                            className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            data-testid="import-match-mode-preview-btn"
                            onClick={handleConfirm}
                            className="px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 text-white text-sm font-semibold transition-colors"
                        >
                            Preview import
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default ImportMatchModeDialog;
export type { ImportMatchMode };
