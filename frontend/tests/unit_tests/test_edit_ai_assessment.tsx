import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import EditAiAssessment from '../../src/components/EditAiAssessment';
import type { Assessment } from '../../src/handlers/assessments';

describe('EditAiAssessment', () => {
    const aiAssessment: Assessment = {
        id: 'ai-1',
        approval_fingerprint: 'original',
        vuln_id: 'CVE-2023-1234',
        packages: ['package@1.0.0'],
        status: 'affected',
        simplified_status: 'Exploitable',
        justification: '',
        impact_statement: 'Original impact',
        status_notes: 'AI rationale',
        workaround: 'AI workaround',
        timestamp: '2023-01-01T00:00:00Z',
        origin: 'ai',
        responses: [],
    };

    const notes = () => screen.getByPlaceholderText(/Free text notes/);

    test('offers confirm/cancel actions and hides the timestamp option', () => {
        render(<EditAiAssessment assessment={aiAssessment} onConfirm={jest.fn()} onCancel={jest.fn()} />);

        expect(screen.getByText('Edit AI assessment')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Confirm and approve' })).toBeEnabled();
        expect(screen.getByRole('button', { name: 'Cancel changes' })).toBeEnabled();
        expect(screen.queryByText('Keep the current timestamp')).not.toBeInTheDocument();
        expect(notes()).toHaveValue('AI rationale');
    });

    test('confirms only the edited content fields', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment assessment={aiAssessment} onConfirm={onConfirm} onCancel={jest.fn()} />);
        const user = userEvent.setup();

        await user.clear(notes());
        await user.type(notes(), 'Edited message');
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));

        expect(onConfirm).toHaveBeenCalledTimes(1);
        expect(onConfirm.mock.calls[0][0]).toEqual({
            expected_fingerprint: 'original',
            status_notes: 'Edited message',
        });
    });

    test('shows the original CycloneDX verdict without rewriting it on a notes edit', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment assessment={{ ...aiAssessment, status: 'exploitable' }} onConfirm={onConfirm}
            onCancel={jest.fn()} />);
        expect(screen.getByText('exploitable')).toBeVisible();
        expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
        const user = userEvent.setup();
        await user.clear(notes());
        await user.type(notes(), 'Reviewed');
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));
        expect(onConfirm).toHaveBeenCalledWith({ expected_fingerprint: 'original', status_notes: 'Reviewed' });
    });

    test('displays the stored OpenVEX justification without rewriting it on approval', async () => {
        const onConfirm = jest.fn();
        const justification = 'vulnerable_code_not_in_execute_path';
        render(<EditAiAssessment assessment={{ ...aiAssessment, status: 'not_affected', justification }}
            onConfirm={onConfirm} onCancel={jest.fn()} />);
        expect(screen.getByRole('combobox')).toHaveDisplayValue(justification);
        await userEvent.setup().click(screen.getByRole('button', { name: 'Confirm and approve' }));
        expect(onConfirm).toHaveBeenCalledWith({ expected_fingerprint: 'original' });
    });

    test('updates imported impact displayed as notes only when the message changes', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment assessment={{ ...aiAssessment, status_notes: '' }}
            onConfirm={onConfirm} onCancel={jest.fn()} />);
        const user = userEvent.setup();
        expect(notes()).toHaveValue('Original impact');
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));
        expect(onConfirm).toHaveBeenLastCalledWith({ expected_fingerprint: 'original' });

        await user.clear(notes());
        await user.type(notes(), 'Corrected message');
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));
        expect(onConfirm).toHaveBeenLastCalledWith({
            expected_fingerprint: 'original',
            status_notes: 'Corrected message',
            impact_statement: '',
        });
    });

    test('cancel changes calls onCancel without confirming', async () => {
        const onConfirm = jest.fn();
        const onCancel = jest.fn();
        render(<EditAiAssessment assessment={aiAssessment} onConfirm={onConfirm} onCancel={onCancel} />);
        const user = userEvent.setup();

        await user.type(notes(), ' more');
        await user.click(screen.getByRole('button', { name: 'Cancel changes' }));

        expect(onCancel).toHaveBeenCalledTimes(1);
        expect(onConfirm).not.toHaveBeenCalled();
    });

    test('allows changing the justification, impact and workaround without changing the verdict', async () => {
        const onConfirm = jest.fn();
        const user = userEvent.setup();
        render(<EditAiAssessment assessment={{ ...aiAssessment, status: 'not_affected' }}
            onConfirm={onConfirm} onCancel={jest.fn()} />);
        expect(screen.getByRole('option', { name: 'Component not present' })).toBeDisabled();
        await user.selectOptions(screen.getByRole('combobox'), 'code_not_reachable');
        const impact = screen.getByPlaceholderText(/Why this vulnerability is not exploitable/i);
        await user.clear(impact);
        await user.type(impact, 'Reviewed impact');
        await user.clear(screen.getByPlaceholderText(/Describe workaround/i));
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));
        expect(onConfirm).toHaveBeenCalledWith({
            expected_fingerprint: 'original', justification: 'code_not_reachable',
            impact_statement: 'Reviewed impact', workaround: '',
        });
    });

    test('rejects an empty message', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment assessment={aiAssessment} onConfirm={onConfirm} onCancel={jest.fn()} />);
        const user = userEvent.setup();

        await user.clear(notes());
        await user.type(notes(), '   ');
        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));

        expect(onConfirm).not.toHaveBeenCalled();
        expect(screen.getByRole('alert')).toHaveTextContent('The assessment message cannot be empty.');

        await user.type(notes(), 'x');
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('accepts a notes-only edit with impact but no justification', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment
            assessment={{ ...aiAssessment, status: 'not_affected', justification: '', impact_statement: 'AI impact' }}
            onConfirm={onConfirm} onCancel={jest.fn()}
        />);
        const user = userEvent.setup();
        await user.clear(notes());
        await user.type(notes(), 'Reviewed');
        const confirm = screen.getByRole('button', { name: 'Confirm and approve' });
        await user.click(confirm);
        expect(onConfirm).toHaveBeenCalledWith({ expected_fingerprint: 'original', status_notes: 'Reviewed' });
    });

    test('accepts an impact statement as the message of a not affected assessment', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment
            assessment={{ ...aiAssessment, status: 'not_affected', justification: 'component_not_present', impact_statement: 'AI impact', status_notes: '' }}
            onConfirm={onConfirm}
            onCancel={jest.fn()}
        />);
        const user = userEvent.setup();
        expect(screen.getByRole('combobox')).toBeDisabled();

        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));

        expect(onConfirm).toHaveBeenCalledWith({ expected_fingerprint: 'original' });
    });

    test('disables the actions while saving and shows the save error', async () => {
        const onConfirm = jest.fn();
        const onCancel = jest.fn();
        render(<EditAiAssessment
            assessment={aiAssessment}
            onConfirm={onConfirm}
            onCancel={onCancel}
            saving={true}
            errorMessage="Failed to approve AI assessment: Invalid justification"
        />);
        const user = userEvent.setup();

        const confirm = screen.getByRole('button', { name: 'Approving…' });
        const cancel = screen.getByRole('button', { name: 'Cancel changes' });
        expect(confirm).toBeDisabled();
        expect(cancel).toBeDisabled();
        await user.click(confirm);
        await user.click(cancel);
        expect(onConfirm).not.toHaveBeenCalled();
        expect(onCancel).not.toHaveBeenCalled();
        expect(screen.getByRole('alert')).toHaveTextContent('Failed to approve AI assessment: Invalid justification');
    });
});
