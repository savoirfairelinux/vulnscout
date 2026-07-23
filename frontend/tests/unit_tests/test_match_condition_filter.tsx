import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import MatchConditionFilter from '../../src/components/MatchConditionFilter';

describe('MatchConditionFilter', () => {
    test('updates and applies the condition with Enter', () => {
        const onConditionChange = jest.fn();
        const onApply = jest.fn();

        render(
            <MatchConditionFilter
                id="test-match-condition"
                condition="cvss >= 7"
                error=""
                subject="vulnerabilities"
                onConditionChange={onConditionChange}
                onApply={onApply}
            />
        );

        const input = screen.getByLabelText('Match condition');
        fireEvent.change(input, { target: { value: 'pending' } });
        fireEvent.keyDown(input, { key: 'Enter' });

        expect(onConditionChange).toHaveBeenCalledWith('pending');
        expect(onApply).toHaveBeenCalledTimes(1);
    });

    test('describes the supported vulnerability facts', () => {
        render(
            <MatchConditionFilter
                id="test-match-condition"
                condition=""
                error="Invalid condition"
                subject="review rows"
                onConditionChange={jest.fn()}
                onApply={jest.fn()}
            />
        );

        expect(screen.getByLabelText('Match condition')).toHaveAttribute('aria-invalid', 'true');
        fireEvent.click(screen.getByRole('button', { name: 'match condition help' }));
        expect(screen.getByText('Filter review rows by vulnerability facts. Press Enter to apply the condition.')).toBeInTheDocument();
        expect(screen.getByText('field operator value')).toBeInTheDocument();
        expect(screen.getByText('cvss >= 7 and pending')).toBeInTheDocument();
    });
});