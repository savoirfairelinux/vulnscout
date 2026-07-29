import { useEffect } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faXmark } from '@fortawesome/free-solid-svg-icons';
import type { Variant } from '../handlers/variant';

type Props = {
    mode: 'import' | 'export';
    variants: Variant[];
    selectedVariantIds: string[];
    transferFormat: 'custom' | 'openvex';
    timestampPolicy: 'original' | 'current';
    onSelectedVariantIdsChange: (ids: string[]) => void;
    onTransferFormatChange: (format: 'custom' | 'openvex') => void;
    onTimestampPolicyChange: (policy: 'original' | 'current') => void;
    onConfirm: () => void;
    onCancel: () => void;
};

function ReviewTransferModal({
    mode,
    variants,
    selectedVariantIds,
    transferFormat,
    timestampPolicy,
    onSelectedVariantIdsChange,
    onTransferFormatChange,
    onTimestampPolicyChange,
    onConfirm,
    onCancel,
}: Readonly<Props>) {
    const title = mode === 'export' ? 'Export review data' : 'Import review data';
    const isOpenVex = transferFormat === 'openvex';
    const needsVariantSelection = isOpenVex || mode === 'export';
    const supportsMultipleVariants = !isOpenVex;

    useEffect(() => {
        const onKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') onCancel();
        };
        document.addEventListener('keydown', onKeyDown);
        return () => document.removeEventListener('keydown', onKeyDown);
    }, [onCancel]);

    const toggleVariant = (variantId: string) => {
        onSelectedVariantIdsChange(
            selectedVariantIds.includes(variantId)
                ? selectedVariantIds.filter(id => id !== variantId)
                : [...selectedVariantIds, variantId],
        );
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-labelledby="review-transfer-title">
            <div className="w-full max-w-lg rounded-lg border border-gray-600 bg-gray-800 shadow-xl">
                <div className="flex items-center justify-between border-b border-gray-600 px-5 py-4">
                    <h2 id="review-transfer-title" className="text-lg font-semibold text-white">{title}</h2>
                    <button type="button" onClick={onCancel} aria-label="Close" className="h-8 w-8 text-gray-300 hover:text-white">
                        <FontAwesomeIcon icon={faXmark} />
                    </button>
                </div>

                <div className="space-y-5 p-5">
                    <fieldset>
                        <legend className="mb-2 text-sm font-semibold text-gray-200">Format</legend>
                        <div className="grid grid-cols-2 gap-3">
                            <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${transferFormat === 'custom' ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                <input type="radio" name="review-transfer-format" checked={transferFormat === 'custom'} onChange={() => onTransferFormatChange('custom')} className="mt-0.5 accent-cyan-500" />
                                <span className="flex flex-col"><span className="text-sm font-medium">VulnScout JSON</span><span className="text-xs text-zinc-400">{mode === 'export' ? 'Assessments, CVSS, and time estimates' : 'Uses the variants recorded in the file'}</span></span>
                            </label>
                            <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${isOpenVex ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                <input type="radio" name="review-transfer-format" checked={isOpenVex} onChange={() => onTransferFormatChange('openvex')} className="mt-0.5 accent-cyan-500" />
                                <span className="flex flex-col"><span className="text-sm font-medium">OpenVEX</span><span className="text-xs text-zinc-400">One variant in a JSON document</span></span>
                            </label>
                        </div>
                    </fieldset>

                    {mode === 'import' && (
                        <fieldset>
                            <legend className="mb-2 text-sm font-semibold text-gray-200">Assessment timestamps</legend>
                            <div className="space-y-2">
                                <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${timestampPolicy === 'original' ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                    <input type="radio" name="review-import-timestamp" checked={timestampPolicy === 'original'} onChange={() => onTimestampPolicyChange('original')} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="text-sm font-medium">Use original timestamps from file</span><span className="text-xs text-zinc-400">Preserve when each assessment was originally recorded</span></span>
                                </label>
                                <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${timestampPolicy === 'current' ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                    <input type="radio" name="review-import-timestamp" checked={timestampPolicy === 'current'} onChange={() => onTimestampPolicyChange('current')} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="text-sm font-medium">Use current system time</span><span className="text-xs text-zinc-400">Ignore timestamps stored in the file</span></span>
                                </label>
                            </div>
                        </fieldset>
                    )}

                    {needsVariantSelection && (
                        <fieldset>
                            <legend className="float-left text-sm font-semibold text-gray-200">{supportsMultipleVariants ? 'Variants' : 'Variant'}</legend>
                            {supportsMultipleVariants && (
                                <div className="mb-2 flex items-center justify-end">
                                    <button type="button" className="text-sm text-cyan-300 hover:text-cyan-200" onClick={() => onSelectedVariantIdsChange(selectedVariantIds.length === variants.length ? [] : variants.map(variant => variant.id))}>
                                        {selectedVariantIds.length === variants.length ? 'Clear all' : 'Select all'}
                                    </button>
                                </div>
                            )}
                            <div className="clear-both max-h-64 space-y-2 overflow-y-auto">
                                {variants.map(variant => {
                                    const selected = supportsMultipleVariants ? selectedVariantIds.includes(variant.id) : selectedVariantIds[0] === variant.id;
                                    return (
                                        <label key={variant.id} className={`flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm transition-colors ${selected ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                            <input type={supportsMultipleVariants ? 'checkbox' : 'radio'} name="review-openvex-variant" checked={selected} onChange={() => supportsMultipleVariants ? toggleVariant(variant.id) : onSelectedVariantIdsChange([variant.id])} className={supportsMultipleVariants ? 'rounded border-slate-500 bg-slate-900 text-cyan-500 focus:ring-cyan-500' : 'accent-cyan-500'} />
                                            {variant.name}
                                        </label>
                                    );
                                })}
                            </div>
                        </fieldset>
                    )}
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-600 px-5 py-4">
                    <button type="button" onClick={onCancel} className="rounded border border-gray-500 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700">Cancel</button>
                    <button type="button" onClick={onConfirm} disabled={needsVariantSelection && (isOpenVex ? selectedVariantIds.length !== 1 : selectedVariantIds.length === 0)} className="rounded bg-green-700 px-4 py-2 text-sm font-medium text-white hover:bg-green-600 disabled:cursor-not-allowed disabled:opacity-50">
                        {mode === 'export' ? 'Export' : 'Choose file'}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default ReviewTransferModal;
