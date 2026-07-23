import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ReviewTransferModal from '../../src/components/ReviewTransferModal';

const variants = [
    { id: 'variant-1', name: 'Variant One', project_id: 'project-1' },
    { id: 'variant-2', name: 'Variant Two', project_id: 'project-1' },
];

function renderModal(overrides = {}) {
    const props = {
        mode: 'import' as const,
        variants,
        selectedVariantIds: [] as string[],
        transferFormat: 'custom' as const,
        timestampPolicy: 'original' as const,
        onSelectedVariantIdsChange: jest.fn(),
        onTransferFormatChange: jest.fn(),
        onTimestampPolicyChange: jest.fn(),
        onConfirm: jest.fn(),
        onCancel: jest.fn(),
        ...overrides,
    };
    render(<ReviewTransferModal {...props} />);
    return props;
}

describe('ReviewTransferModal', () => {
    test('updates import format and timestamp preferences, then confirms', () => {
        const props = renderModal();

        fireEvent.click(screen.getByRole('radio', { name: /^OpenVEX/ }));
        fireEvent.click(screen.getByRole('radio', { name: /^Use current system time/ }));
        fireEvent.click(screen.getByRole('button', { name: 'Choose file' }));

        expect(props.onTransferFormatChange).toHaveBeenCalledWith('openvex');
        expect(props.onTimestampPolicyChange).toHaveBeenCalledWith('current');
        expect(props.onConfirm).toHaveBeenCalledTimes(1);
    });

    test('selects the OpenVEX destination variant and invokes cancellation controls', () => {
        const props = renderModal({
            transferFormat: 'openvex' as const,
            selectedVariantIds: ['variant-1'],
        });

        fireEvent.click(screen.getByRole('radio', { name: 'Variant Two' }));
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        fireEvent.keyDown(document, { key: 'Escape' });

        expect(props.onSelectedVariantIdsChange).toHaveBeenCalledWith(['variant-2']);
        expect(props.onCancel).toHaveBeenCalledTimes(2);
    });

    test('selects and clears all export variants', () => {
        const props = renderModal({
            mode: 'export' as const,
            selectedVariantIds: [],
        });

        fireEvent.click(screen.getByRole('button', { name: 'Select all' }));

        expect(props.onSelectedVariantIdsChange).toHaveBeenCalledWith(['variant-1', 'variant-2']);

        const selectedProps = renderModal({
            mode: 'export' as const,
            selectedVariantIds: ['variant-1', 'variant-2'],
        });
        fireEvent.click(screen.getAllByRole('button', { name: 'Clear all' })[0]);

        expect(selectedProps.onSelectedVariantIdsChange).toHaveBeenCalledWith([]);
    });

    test('toggles individual export variants and resets custom import settings', () => {
        const exportProps = renderModal({
            mode: 'export' as const,
            selectedVariantIds: ['variant-1'],
        });

        fireEvent.click(screen.getByRole('checkbox', { name: 'Variant One' }));
        fireEvent.click(screen.getByRole('checkbox', { name: 'Variant Two' }));

        expect(exportProps.onSelectedVariantIdsChange).toHaveBeenNthCalledWith(1, []);
        expect(exportProps.onSelectedVariantIdsChange).toHaveBeenNthCalledWith(2, ['variant-1', 'variant-2']);

        cleanup();
        const importProps = renderModal({
            transferFormat: 'openvex' as const,
            timestampPolicy: 'current' as const,
        });
        fireEvent.click(screen.getByRole('radio', { name: /^VulnScout JSON/ }));
        fireEvent.click(screen.getByRole('radio', { name: /^Use original timestamps/ }));

        expect(importProps.onTransferFormatChange).toHaveBeenCalledWith('custom');
        expect(importProps.onTimestampPolicyChange).toHaveBeenCalledWith('original');
    });
});