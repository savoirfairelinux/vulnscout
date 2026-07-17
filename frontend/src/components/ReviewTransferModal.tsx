import { useEffect } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faXmark } from '@fortawesome/free-solid-svg-icons';
import type { Variant } from '../handlers/variant';

type Props = {
    mode: 'import' | 'export';
    variants: Variant[];
    selectedVariantIds: string[];
    exportFormat: 'custom' | 'openvex';
    onSelectedVariantIdsChange: (ids: string[]) => void;
    onExportFormatChange: (format: 'custom' | 'openvex') => void;
    onConfirm: () => void;
    onCancel: () => void;
};

function ReviewTransferModal({
    mode,
    variants,
    selectedVariantIds,
    exportFormat,
    onSelectedVariantIdsChange,
    onExportFormatChange,
    onConfirm,
    onCancel,
}: Readonly<Props>) {
    const title = mode === 'export' ? 'Export review data' : 'Import review data';

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
                    {mode === 'export' && (
                        <fieldset>
                            <legend className="mb-2 text-sm font-semibold text-gray-200">Format</legend>
                            <div className="grid grid-cols-2 gap-3">
                                <label className="flex cursor-pointer items-start gap-2 rounded border border-gray-600 p-3 text-gray-100">
                                    <input type="radio" name="review-export-format" checked={exportFormat === 'custom'} onChange={() => onExportFormatChange('custom')} />
                                    <span><span className="block font-medium">VulnScout JSON</span><span className="text-xs text-gray-400">Assessments, CVSS, and time estimates</span></span>
                                </label>
                                <label className="flex cursor-pointer items-start gap-2 rounded border border-gray-600 p-3 text-gray-100">
                                    <input type="radio" name="review-export-format" checked={exportFormat === 'openvex'} onChange={() => onExportFormatChange('openvex')} />
                                    <span><span className="block font-medium">OpenVEX</span><span className="text-xs text-gray-400">Assessment archive compatible with the CLI</span></span>
                                </label>
                            </div>
                        </fieldset>
                    )}

                    <fieldset>
                        <legend className="float-left text-sm font-semibold text-gray-200">Variants</legend>
                        <div className="mb-2 flex items-center justify-end">
                            <button type="button" className="text-sm text-cyan-300 hover:text-cyan-200" onClick={() => onSelectedVariantIdsChange(selectedVariantIds.length === variants.length ? [] : variants.map(v => v.id))}>
                                {selectedVariantIds.length === variants.length ? 'Clear all' : 'Select all'}
                            </button>
                        </div>
                        <div className="clear-both max-h-64 space-y-1 overflow-y-auto rounded border border-gray-600 p-2">
                            {variants.map(variant => (
                                <label key={variant.id} className="flex cursor-pointer items-center gap-3 rounded px-2 py-2 text-sm text-gray-100 hover:bg-gray-700">
                                    <input type="checkbox" checked={selectedVariantIds.includes(variant.id)} onChange={() => toggleVariant(variant.id)} />
                                    {variant.name}
                                </label>
                            ))}
                        </div>
                    </fieldset>
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-600 px-5 py-4">
                    <button type="button" onClick={onCancel} className="rounded border border-gray-500 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700">Cancel</button>
                    <button type="button" onClick={onConfirm} disabled={selectedVariantIds.length === 0} className="rounded bg-green-700 px-4 py-2 text-sm font-medium text-white hover:bg-green-600 disabled:cursor-not-allowed disabled:opacity-50">
                        {mode === 'export' ? 'Export' : 'Choose file'}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default ReviewTransferModal;
