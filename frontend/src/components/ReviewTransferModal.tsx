import type { Variant } from '../handlers/variant';
import ModalShell, { ModalActions, ModalButton } from './ModalShell';

type Props = {
    mode: 'import' | 'export';
    variants: Variant[];
    selectedVariantIds: string[];
    transferFormat: 'custom' | 'openvex';
    timestampPolicy: 'original' | 'current';
    exportMode: 'normal' | 'update';
    existingFileName?: string;
    existingFileError?: string;
    onSelectedVariantIdsChange: (ids: string[]) => void;
    onTransferFormatChange: (format: 'custom' | 'openvex') => void;
    onTimestampPolicyChange: (policy: 'original' | 'current') => void;
    onExportModeChange: (mode: 'normal' | 'update') => void;
    onExistingFileChange: (file?: File) => void;
    onConfirm: () => void;
    onCancel: () => void;
};

function ReviewTransferModal({
    mode,
    variants,
    selectedVariantIds,
    transferFormat,
    timestampPolicy,
    exportMode,
    existingFileName,
    existingFileError,
    onSelectedVariantIdsChange,
    onTransferFormatChange,
    onTimestampPolicyChange,
    onExportModeChange,
    onExistingFileChange,
    onConfirm,
    onCancel,
}: Readonly<Props>) {
    const title = mode === 'export' ? 'Export review data' : 'Import review data';
    const isOpenVex = transferFormat === 'openvex';
    const needsVariantSelection = isOpenVex || mode === 'export';
    const supportsMultipleVariants = !isOpenVex;
    const isUpdateExport = mode === 'export' && exportMode === 'update';

    const toggleVariant = (variantId: string) => {
        onSelectedVariantIdsChange(
            selectedVariantIds.includes(variantId)
                ? selectedVariantIds.filter(id => id !== variantId)
                : [...selectedVariantIds, variantId],
        );
    };

    const footer = (
        <ModalActions>
            <ModalButton onClick={onCancel}>Cancel</ModalButton>
            <ModalButton variant="primary" onClick={onConfirm} disabled={(needsVariantSelection && (isOpenVex ? selectedVariantIds.length !== 1 : selectedVariantIds.length === 0)) || (isUpdateExport && (!existingFileName || Boolean(existingFileError)))}>
                {mode === 'export' ? isUpdateExport ? 'Update export' : 'Export' : 'Choose file'}
            </ModalButton>
        </ModalActions>
    );

    return (
        <ModalShell
            isOpen={true}
            title={title}
            titleId="review-transfer-title"
            onClose={onCancel}
            closeLabel="Close"
            closeOnBackdrop={false}
            size="compact"
            contentClassName="space-y-5 p-5 md:p-5"
            footer={footer}
        >
                    {mode === 'export' && (
                        <fieldset>
                            <legend className="mb-2 text-sm font-semibold text-gray-200">Export method</legend>
                            <div className="grid grid-cols-2 gap-3">
                                <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${exportMode === 'normal' ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                    <input type="radio" name="review-export-mode" checked={exportMode === 'normal'} onChange={() => onExportModeChange('normal')} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="text-sm font-medium">Normal export</span><span className="text-xs text-zinc-400">Create a new export file</span></span>
                                </label>
                                <label className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition-colors ${isUpdateExport ? 'border-cyan-500 bg-cyan-950/40 text-white' : 'border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500'}`}>
                                    <input type="radio" name="review-export-mode" checked={isUpdateExport} onChange={() => onExportModeChange('update')} className="mt-0.5 accent-cyan-500" />
                                    <span className="flex flex-col"><span className="text-sm font-medium">Append/update existing file</span><span className="text-xs text-zinc-400">Preserve stable content for a minimal Git diff</span></span>
                                </label>
                            </div>
                        </fieldset>
                    )}

                    {isUpdateExport && (
                        <label className="block text-sm font-semibold text-gray-200">
                            Existing export file
                            <input
                                type="file"
                                aria-label="Existing export file"
                                accept=".json,application/json"
                                onChange={event => onExistingFileChange(event.target.files?.[0])}
                                className="mt-2 block w-full rounded border border-slate-600 bg-slate-900 p-2 text-sm font-normal text-zinc-300 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-1 file:text-white"
                            />
                            {existingFileName && !existingFileError && <span className="mt-1 block font-normal text-cyan-300">Detected {isOpenVex ? 'OpenVEX' : 'VulnScout JSON'}: {existingFileName}</span>}
                            {existingFileError && <span role="alert" className="mt-1 block font-normal text-red-300">{existingFileError}</span>}
                        </label>
                    )}

                    {!isUpdateExport && (
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
                    )}

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
        </ModalShell>
    );
}

export default ReviewTransferModal;
