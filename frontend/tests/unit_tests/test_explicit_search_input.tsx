import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { describe, expect, jest, test } from '@jest/globals';

import ExplicitSearchInput from '../../src/components/ExplicitSearchInput';


describe('ExplicitSearchInput', () => {
    test('applies the search from the button and Enter key', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn<(value: string) => void>();
        const onSearch = jest.fn<() => void>();
        render(
            <ExplicitSearchInput
                id="test-search"
                label="Search"
                value="openssl"
                onChange={onChange}
                onSearch={onSearch}
                placeholder="Search packages"
                ariaLabel="Search packages"
            />
        );

        const input = screen.getByRole('searchbox');
        await user.type(input, '{enter}');
        await user.click(screen.getByRole('button', {name: 'Search packages'}));

        expect(onSearch).toHaveBeenCalledTimes(2);
    });

    test('reports changes and disables search while loading', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn<(value: string) => void>();
        const onSearch = jest.fn<() => void>();
        render(
            <ExplicitSearchInput
                id="test-search"
                label="Search"
                value=""
                onChange={onChange}
                onSearch={onSearch}
                placeholder="Search packages"
                ariaLabel="Search packages"
                loading={true}
            />
        );

        await user.type(screen.getByRole('searchbox'), 'a');

        expect(onChange).toHaveBeenCalledWith('a');
        expect((screen.getByRole('button', {name: 'Search packages'}) as HTMLButtonElement).disabled).toBe(true);
    });
});
