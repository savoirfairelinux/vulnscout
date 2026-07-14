import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import ImportMatchModeDialog from '../../src/components/ImportMatchModeDialog';

const VARIANTS = [
    { id: 'v1', name: 'Variant Alpha', project_id: 'proj1' },
    { id: 'v2', name: 'Variant Beta', project_id: 'proj1' },
];

describe('ImportMatchModeDialog', () => {
    const baseProps = {
        isOpen: true,
        variants: VARIANTS,
        onConfirm: jest.fn(),
        onCancel: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('does not render when isOpen is false', () => {
        render(<ImportMatchModeDialog {...baseProps} isOpen={false} />);
        expect(screen.queryByText('Import custom data')).not.toBeInTheDocument();
    });

    test('renders the dialog header, variant selector and three mode options when open', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        expect(screen.getByText('Import custom data')).toBeInTheDocument();
        expect(screen.getByTestId('import-target-variant-select')).toBeInTheDocument();
        expect(screen.getByTestId('import-match-mode-option-exact')).toBeInTheDocument();
        expect(screen.getByTestId('import-match-mode-option-ignore_minor_version')).toBeInTheDocument();
        expect(screen.getByTestId('import-match-mode-option-ignore_version')).toBeInTheDocument();
    });

    test('exposes accessible dialog semantics and the CVSS/time-estimate note', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        const dialog = screen.getByRole('dialog');
        expect(dialog).toHaveAttribute('aria-modal', 'true');
        expect(dialog).toHaveAttribute('aria-labelledby', 'import-match-mode-title');
        expect(
            screen.getByText(/CVSS scores and time estimates .* are always imported/i)
        ).toBeInTheDocument();
    });

    test('variant selector shows all provided variants', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        expect(screen.getByRole('option', { name: 'Variant Alpha' })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: 'Variant Beta' })).toBeInTheDocument();
    });

    test('exact mode is selected by default', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        const radio = screen.getByTestId('import-match-mode-radio-exact') as HTMLInputElement;
        expect(radio.checked).toBe(true);
        const radioMinor = screen.getByTestId('import-match-mode-radio-ignore_minor_version') as HTMLInputElement;
        expect(radioMinor.checked).toBe(false);
    });

    test('initialVariantId pre-selects the variant', () => {
        render(<ImportMatchModeDialog {...baseProps} initialVariantId="v2" />);
        const select = screen.getByTestId('import-target-variant-select') as HTMLSelectElement;
        expect(select.value).toBe('v2');
    });

    test('without initialVariantId the selector is empty', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        const select = screen.getByTestId('import-target-variant-select') as HTMLSelectElement;
        expect(select.value).toBe('');
    });

    test('clicking Preview import without selecting a variant shows inline error', () => {
        const onConfirm = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByTestId('import-match-mode-preview-btn'));
        expect(screen.getByTestId('import-variant-error')).toBeInTheDocument();
        expect(screen.getByText('Please select a target variant.')).toBeInTheDocument();
        expect(onConfirm).not.toHaveBeenCalled();
    });

    test('inline error clears when a variant is selected', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        fireEvent.click(screen.getByTestId('import-match-mode-preview-btn'));
        expect(screen.getByTestId('import-variant-error')).toBeInTheDocument();
        fireEvent.change(screen.getByTestId('import-target-variant-select'), { target: { value: 'v1' } });
        expect(screen.queryByTestId('import-variant-error')).not.toBeInTheDocument();
    });

    test('confirms with exact mode and selected variant', () => {
        const onConfirm = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} initialVariantId="v1" onConfirm={onConfirm} />);
        fireEvent.click(screen.getByTestId('import-match-mode-preview-btn'));
        expect(onConfirm).toHaveBeenCalledWith('exact', 'v1');
    });

    test('confirms with selected mode and variant', () => {
        const onConfirm = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} onConfirm={onConfirm} />);
        fireEvent.change(screen.getByTestId('import-target-variant-select'), { target: { value: 'v2' } });
        fireEvent.click(screen.getByTestId('import-match-mode-radio-ignore_minor_version'));
        fireEvent.click(screen.getByTestId('import-match-mode-preview-btn'));
        expect(onConfirm).toHaveBeenCalledWith('ignore_minor_version', 'v2');
    });

    test('confirms with ignore_version mode', () => {
        const onConfirm = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} initialVariantId="v1" onConfirm={onConfirm} />);
        fireEvent.click(screen.getByTestId('import-match-mode-radio-ignore_version'));
        fireEvent.click(screen.getByTestId('import-match-mode-preview-btn'));
        expect(onConfirm).toHaveBeenCalledWith('ignore_version', 'v1');
    });

    test('clicking a different mode option selects it', () => {
        render(<ImportMatchModeDialog {...baseProps} />);
        const radioVersion = screen.getByTestId('import-match-mode-radio-ignore_version') as HTMLInputElement;
        fireEvent.click(radioVersion);
        expect(radioVersion.checked).toBe(true);
        const radioExact = screen.getByTestId('import-match-mode-radio-exact') as HTMLInputElement;
        expect(radioExact.checked).toBe(false);
    });

    test('Cancel button calls onCancel', () => {
        const onCancel = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} onCancel={onCancel} />);
        fireEvent.click(screen.getByText('Cancel'));
        expect(onCancel).toHaveBeenCalled();
    });

    test('Escape key calls onCancel', () => {
        const onCancel = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} onCancel={onCancel} />);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onCancel).toHaveBeenCalled();
    });

    test('clicking backdrop calls onCancel', () => {
        const onCancel = jest.fn();
        render(<ImportMatchModeDialog {...baseProps} onCancel={onCancel} />);
        const backdrop = screen.getByTestId('import-match-mode-dialog-backdrop');
        fireEvent.mouseDown(backdrop, { target: backdrop });
        expect(onCancel).toHaveBeenCalled();
    });

    test('resets to exact mode and clears variant when reopened without initialVariantId', () => {
        const { rerender } = render(<ImportMatchModeDialog {...baseProps} />);
        fireEvent.change(screen.getByTestId('import-target-variant-select'), { target: { value: 'v2' } });
        fireEvent.click(screen.getByTestId('import-match-mode-radio-ignore_version'));
        // Close then reopen
        rerender(<ImportMatchModeDialog {...baseProps} isOpen={false} />);
        rerender(<ImportMatchModeDialog {...baseProps} isOpen={true} />);
        const exactRadio = screen.getByTestId('import-match-mode-radio-exact') as HTMLInputElement;
        expect(exactRadio.checked).toBe(true);
        const select = screen.getByTestId('import-target-variant-select') as HTMLSelectElement;
        expect(select.value).toBe('');
    });

    test('resets to initialVariantId when reopened with initialVariantId', () => {
        const { rerender } = render(<ImportMatchModeDialog {...baseProps} initialVariantId="v1" />);
        fireEvent.change(screen.getByTestId('import-target-variant-select'), { target: { value: 'v2' } });
        rerender(<ImportMatchModeDialog {...baseProps} initialVariantId="v1" isOpen={false} />);
        rerender(<ImportMatchModeDialog {...baseProps} initialVariantId="v1" isOpen={true} />);
        const select = screen.getByTestId('import-target-variant-select') as HTMLSelectElement;
        expect(select.value).toBe('v1');
    });
});
