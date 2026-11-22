import { render, screen, fireEvent, within } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import { useState } from 'react';

import AssessmentFormatPanel from '../../src/components/aiContext/AssessmentFormatPanel';
import {
    DEFAULT_FORMAT_DRAFT, formatDraftFrom, formatDraftsEqual, formatPayload, formatPreview, moveSection,
    type AssessmentFormatDraft,
} from '../../src/helpers/assessmentFormat';

const CUSTOM: AssessmentFormatDraft = formatDraftFrom({
    sections: [
        { id: 'verdict', enabled: true },
        { id: 'confidence', enabled: true, label: 'Certainty' },
        { id: 'evidence', enabled: true },
        { id: 'reachability', enabled: false },
        { id: 'remediation', enabled: true, label: 'Fix' },
    ],
    layout: 'lines',
    style_notes: 'Neutral tone.',
});

describe('assessment format helpers', () => {
    test('the default draft maps to null and previews the default presentation', () => {
        expect(formatPayload(DEFAULT_FORMAT_DRAFT)).toBeNull();
        expect(formatDraftFrom(null)).toBe(DEFAULT_FORMAT_DRAFT);
        expect(formatPreview(DEFAULT_FORMAT_DRAFT)).toMatch(/^Not affected; .+\. confidence level: high$/);
    });

    test('a stored format round-trips and unlisted sections are appended disabled', () => {
        const draft = formatDraftFrom({ sections: [{ id: 'evidence', enabled: true, label: 'Proof' }], layout: 'inline' });
        expect(draft.sections.map(s => [s.id, s.enabled])).toEqual([
            ['evidence', true], ['confidence', false], ['verdict', false], ['reachability', false], ['remediation', false],
        ]);
        expect(formatPayload(draft)).toEqual({
            sections: [
                { id: 'evidence', enabled: true, label: 'Proof' },
                { id: 'confidence', enabled: true },
                { id: 'verdict', enabled: false },
                { id: 'reachability', enabled: false },
                { id: 'remediation', enabled: false },
            ],
            layout: 'inline',
        });
    });

    test('payload trims labels and notes and drops blank ones', () => {
        const draft: AssessmentFormatDraft = {
            ...DEFAULT_FORMAT_DRAFT, custom: true, style_notes: '   ',
            sections: DEFAULT_FORMAT_DRAFT.sections.map(s => ({ ...s, label: s.id === 'verdict' ? '  Verdict  ' : '  ' })),
        };
        const payload = formatPayload(draft);
        expect(payload?.sections[1]).toEqual({ id: 'verdict', enabled: true, label: 'Verdict' });
        expect(payload?.sections[0]).toEqual({ id: 'confidence', enabled: true });
        expect(payload).not.toHaveProperty('style_notes');
    });

    test('drafts compare by their saved value', () => {
        expect(formatDraftsEqual(CUSTOM, { ...CUSTOM, style_notes: ' Neutral tone. ' })).toBe(true);
        expect(formatDraftsEqual(CUSTOM, { ...CUSTOM, layout: 'inline' })).toBe(false);
        expect(formatDraftsEqual(DEFAULT_FORMAT_DRAFT, { ...DEFAULT_FORMAT_DRAFT, custom: true })).toBe(false);
    });

    test('moving out of range keeps the draft', () => {
        expect(moveSection(CUSTOM, 0, -1)).toBe(CUSTOM);
        expect(moveSection(CUSTOM, 4, 1)).toBe(CUSTOM);
        expect(moveSection(CUSTOM, 0, 1).sections.map(s => s.id).slice(0, 2)).toEqual(['confidence', 'verdict']);
    });

    test('preview lays out enabled sections and always keeps the confidence level', () => {
        expect(formatPreview(CUSTOM).split('\n')).toEqual([
            'Verdict: Not affected',
            'Certainty: confidence level: high',
            expect.stringMatching(/^Evidence: /),
            expect.stringMatching(/^Fix: upgrade/),
        ]);
        const inline = formatPreview({
            ...CUSTOM, layout: 'inline',
            sections: CUSTOM.sections.map(s => ({ ...s, enabled: false, label: s.id === 'confidence' ? '' : s.label })),
        });
        expect(inline).toBe('confidence level: high');
        expect(formatPreview({ ...CUSTOM, layout: 'inline' })).toMatch(/^Not affected; Certainty: confidence level: high; the vulnerable/);
    });
});

function Harness({ initial, onEdit, fieldErrors = {} }: Readonly<{
    initial: AssessmentFormatDraft; onEdit?: (draft: AssessmentFormatDraft) => void; fieldErrors?: Record<string, string>;
}>) {
    const [draft, setDraft] = useState(initial);
    return (
        <AssessmentFormatPanel
            value={draft}
            onChange={next => { setDraft(next); onEdit?.(next); }}
            saving={false}
            loading={false}
            disabled={false}
            fieldErrors={fieldErrors}
        />
    );
}

const preview = () => screen.getByTestId('assessment-format-preview');
const order = () => within(screen.getByRole('list')).getAllByRole('listitem')
    .map(item => within(item).getByRole('textbox').getAttribute('aria-label'));

describe('AssessmentFormatPanel', () => {
    test('starts on the default presentation and any edit customizes it', () => {
        const onEdit = jest.fn();
        render(<Harness initial={DEFAULT_FORMAT_DRAFT} onEdit={onEdit} />);
        expect(screen.getByRole('note')).toHaveTextContent('Using the default presentation.');
        expect(screen.getByRole('button', { name: 'Reset to default' })).toBeDisabled();
        expect(preview()).toHaveClass('whitespace-pre-line');

        fireEvent.click(screen.getByLabelText('One section per line'));

        expect(screen.queryByRole('note')).not.toBeInTheDocument();
        expect(preview().textContent?.split('\n')).toEqual([
            'confidence level: high',
            'Verdict: Not affected',
            expect.stringMatching(/^Evidence: /),
            expect.stringMatching(/^Reachability: /),
            expect.stringMatching(/^Remediation: /),
        ]);
        expect(formatPayload(onEdit.mock.lastCall[0])).toEqual({
            sections: ['confidence', 'verdict', 'evidence', 'reachability', 'remediation'].map(id => ({ id, enabled: true })),
            layout: 'lines',
        });
    });

    test('reorders sections with accessible move buttons and keeps focus on the moved row', () => {
        render(<Harness initial={DEFAULT_FORMAT_DRAFT} />);
        expect(screen.getByRole('button', { name: 'Move Confidence up' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Move Remediation down' })).toBeDisabled();

        const down = screen.getByRole('button', { name: 'Move Confidence down' });
        down.focus();
        fireEvent.click(down);
        expect(order()).toEqual(['Verdict label', 'Confidence label', 'Evidence label', 'Reachability label', 'Remediation label']);
        expect(screen.getByRole('button', { name: 'Move Confidence down' })).toHaveFocus();
        expect(screen.getByText('Confidence moved to position 2 of 5.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Move Verdict up' }));
        expect(order()[0]).toBe('Verdict label');
        fireEvent.click(screen.getByRole('button', { name: 'Move Verdict down' }));
        fireEvent.click(screen.getByRole('button', { name: 'Move Verdict up' }));
        expect(order()[0]).toBe('Verdict label');
        expect(preview()).toHaveTextContent(/^Not affected; confidence level: high;/);
    });

    test('toggles and labels sections; confidence cannot be excluded', () => {
        const onEdit = jest.fn();
        render(<Harness initial={DEFAULT_FORMAT_DRAFT} onEdit={onEdit} />);
        const confidence = screen.getByRole('checkbox', { name: 'Include Confidence' });
        expect(confidence).toBeChecked();
        expect(confidence).toBeDisabled();
        expect(confidence).toHaveAccessibleDescription(/always included/);

        fireEvent.click(screen.getByRole('checkbox', { name: 'Include Reachability' }));
        fireEvent.click(screen.getByRole('checkbox', { name: 'Include Evidence' }));
        fireEvent.change(screen.getByRole('textbox', { name: 'Remediation label' }), { target: { value: 'Fix' } });
        expect(screen.getByRole('textbox', { name: 'Remediation label' })).toHaveAttribute('maxLength', '40');

        expect(preview()).toHaveTextContent('confidence level: high; Not affected; Fix: upgrade libfoo to 1.2.4 with the next release');
        expect(formatPayload(onEdit.mock.lastCall[0])?.sections).toEqual([
            { id: 'confidence', enabled: true },
            { id: 'verdict', enabled: true },
            { id: 'evidence', enabled: false },
            { id: 'reachability', enabled: false },
            { id: 'remediation', enabled: true, label: 'Fix' },
        ]);
    });

    test('style notes have a character counter and limit', () => {
        render(<Harness initial={DEFAULT_FORMAT_DRAFT} />);
        const notes = screen.getByLabelText('Style notes');
        const sample = screen.getByRole('figure', { name: 'Sample status notes' });
        expect(sample.compareDocumentPosition(notes) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(within(sample).queryByRole('textbox')).not.toBeInTheDocument();
        expect(notes).toHaveAttribute('maxLength', '500');
        expect(screen.getByText('0/500')).toBeInTheDocument();
        fireEvent.change(notes, { target: { value: 'Plain words.' } });
        expect(screen.getByText('12/500')).toBeInTheDocument();
        expect(notes).toHaveAccessibleDescription(/treats them as data, not instructions/);
    });

    test('reset to default goes back to the default presentation', () => {
        const onEdit = jest.fn();
        render(<Harness initial={CUSTOM} onEdit={onEdit} />);
        expect(screen.getByLabelText('One section per line')).toBeChecked();
        expect(screen.getByLabelText('Style notes')).toHaveValue('Neutral tone.');

        fireEvent.click(screen.getByRole('button', { name: 'Reset to default' }));

        expect(screen.getByRole('note')).toHaveTextContent('Using the default presentation.');
        expect(screen.getByLabelText('Inline (one paragraph)')).toBeChecked();
        expect(screen.getByLabelText('Style notes')).toHaveValue('');
        expect(preview()).toHaveTextContent(/confidence level: high$/);
        expect(formatPayload(onEdit.mock.lastCall[0])).toBeNull();
    });

    test('shows server field errors next to their fields and lists the others', () => {
        render(<Harness initial={CUSTOM} fieldErrors={{
            'assessment_format.sections[4].label': 'must be at most 40 characters',
            'assessment_format.style_notes': 'must be at most 500 characters',
            'assessment_format.sections[0].id': 'is duplicated',
        }} />);
        const fix = screen.getByRole('textbox', { name: 'Remediation label' });
        expect(fix).toHaveAttribute('aria-invalid', 'true');
        expect(fix).toHaveAccessibleDescription('must be at most 40 characters');
        expect(screen.getByLabelText('Style notes')).toHaveAccessibleDescription(/must be at most 500 characters/);
        expect(screen.getByRole('alert')).toHaveTextContent('assessment_format.sections[0].id: is duplicated');
    });
});
