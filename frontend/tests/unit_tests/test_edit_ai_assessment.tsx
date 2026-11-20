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
        vuln_id: 'CVE-2023-1234',
        packages: ['package@1.0.0'],
        status: 'affected',
        simplified_status: 'Exploitable',
        justification: '',
        impact_statement: '',
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
            status: 'affected',
            justification: undefined,
            impact_statement: '',
            status_notes: 'Edited message',
            workaround: 'AI workaround',
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

    test('accepts an impact statement as the message of a not affected assessment', async () => {
        const onConfirm = jest.fn();
        render(<EditAiAssessment
            assessment={{ ...aiAssessment, status: 'not_affected', justification: 'component_not_present', impact_statement: 'AI impact', status_notes: '' }}
            onConfirm={onConfirm}
            onCancel={jest.fn()}
        />);
        const user = userEvent.setup();

        await user.click(screen.getByRole('button', { name: 'Confirm and approve' }));

        expect(onConfirm).toHaveBeenCalledWith(expect.objectContaining({
            status: 'not_affected',
            justification: 'component_not_present',
            impact_statement: 'AI impact',
            status_notes: '',
        }));
    });

    test('disables the actions while saving and shows the save error', async () => {
        const onConfirm = jest.fn();
        const onCancel = jest.fn();
        render(<EditAiAssessment
            assessment={aiAssessment}
            onConfirm={onConfirm}
            onCancel={onCancel}
            saving={true}
            errorMessage="Failed to approve AI assessment: Invalid status"
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
        expect(screen.getByRole('alert')).toHaveTextContent('Failed to approve AI assessment: Invalid status');
    });
});
