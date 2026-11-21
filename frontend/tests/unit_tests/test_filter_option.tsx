import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { useState } from 'react';

import FilterOption from '../../src/components/FilterOption';


type HarnessProps = {
    options: string[];
    initial?: string[];
    showSelectAll?: boolean;
    searchable?: boolean;
    onChange?: (values: string[]) => void;
    setShowCustomFilterComponent?: (show: boolean) => void;
};

function Harness({ options, initial = [], showSelectAll, searchable, onChange, setShowCustomFilterComponent }: Readonly<HarnessProps>) {
    const [selected, setSelected] = useState<string[]>(initial);
    return (
        <FilterOption
            label="Packages"
            options={options}
            selected={selected}
            setSelected={(values) => {
                setSelected(values);
                onChange?.(values);
            }}
            showSelectAll={showSelectAll}
            searchable={searchable}
            setShowCustomFilterComponent={setShowCustomFilterComponent}
        />
    );
}

const OPTIONS = ['openssl@3.0.0', 'busybox@1.36.1', 'zlib@1.3'];

describe('FilterOption select all', () => {
    test('does not render bulk actions unless opted in', async () => {
        const user = userEvent.setup();
        render(<Harness options={OPTIONS} />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));

        expect(screen.queryByRole('button', { name: /select all/i })).not.toBeInTheDocument();
    });

    test('renders both buttons above the options', async () => {
        const user = userEvent.setup();
        render(<Harness options={OPTIONS} showSelectAll />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));

        const firstCheckbox = screen.getAllByRole('checkbox')[0];
        for (const name of ['Select all', 'Deselect all']) {
            const button = screen.getByRole('button', { name });
            expect(button).toHaveAttribute('type', 'button');
            expect(button.compareDocumentPosition(firstCheckbox) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        }
    });

    test('selects every option, then deselects them all', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn<void, [string[]]>();
        render(<Harness options={OPTIONS} initial={['busybox@1.36.1']} showSelectAll onChange={onChange} />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        await user.click(screen.getByRole('button', { name: 'Select all' }));

        expect(onChange).toHaveBeenLastCalledWith(['busybox@1.36.1', 'openssl@3.0.0', 'zlib@1.3']);
        for (const option of OPTIONS) {
            expect(screen.getByRole('checkbox', { name: option })).toBeChecked();
        }

        await user.click(screen.getByRole('button', { name: 'Deselect all' }));

        expect(onChange).toHaveBeenLastCalledWith([]);
        for (const option of OPTIONS) {
            expect(screen.getByRole('checkbox', { name: option })).not.toBeChecked();
        }
        expect(screen.getByRole('button', { name: 'Select all' })).toBeInTheDocument();
    });

    test('deselects directly from a partial selection', async () => {
        const user = userEvent.setup();
        render(<Harness options={OPTIONS} showSelectAll />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        await user.click(screen.getByRole('checkbox', { name: 'zlib@1.3' }));
        expect(screen.getByRole('checkbox', { name: 'zlib@1.3' })).toBeChecked();
        await user.click(screen.getByRole('button', { name: 'Deselect all' }));
        expect(screen.queryByRole('checkbox', { checked: true })).not.toBeInTheDocument();
    });

    test('is keyboard operable', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn<void, [string[]]>();
        render(<Harness options={OPTIONS} showSelectAll onChange={onChange} />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        screen.getByRole('button', { name: 'Select all' }).focus();
        await user.keyboard('{Enter}');
        expect(onChange).toHaveBeenLastCalledWith(OPTIONS);

        await user.tab();
        expect(screen.getByRole('button', { name: 'Deselect all' })).toHaveFocus();
        await user.keyboard(' ');
        expect(onChange).toHaveBeenLastCalledWith([]);
    });

    test('only affects options matching the search and keeps other selections', async () => {
        const user = userEvent.setup();
        const onChange = jest.fn<void, [string[]]>();
        render(<Harness options={OPTIONS} initial={['openssl@3.0.0', 'zlib@1.3']} showSelectAll searchable onChange={onChange} />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        await user.type(screen.getByRole('searchbox', { name: 'Search packages' }), 'o');

        // "openssl" and "busybox" match, "zlib" is hidden but stays selected
        await user.click(screen.getByRole('button', { name: 'Deselect all matching' }));
        expect(onChange).toHaveBeenLastCalledWith(['zlib@1.3']);

        await user.click(screen.getByRole('button', { name: 'Select all matching' }));
        expect(onChange).toHaveBeenLastCalledWith(['zlib@1.3', 'openssl@3.0.0', 'busybox@1.36.1']);

        await user.click(screen.getByRole('button', { name: 'Deselect all matching' }));
        expect(onChange).toHaveBeenLastCalledWith(['zlib@1.3']);
    });

    test('is hidden when no option matches the search', async () => {
        const user = userEvent.setup();
        render(<Harness options={OPTIONS} showSelectAll searchable />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        await user.type(screen.getByRole('searchbox', { name: 'Search packages' }), 'nothing-matches');

        expect(screen.queryByRole('button', { name: /select all/i })).not.toBeInTheDocument();
        expect(screen.getByText('No match found')).toBeInTheDocument();
    });

    test('turns off the custom filter like a manual option toggle', async () => {
        const user = userEvent.setup();
        const setShowCustom = jest.fn<void, [boolean]>();
        render(<Harness options={OPTIONS} showSelectAll setShowCustomFilterComponent={setShowCustom} />);

        await user.click(screen.getByRole('button', { name: 'Packages' }));
        await user.click(screen.getByRole('button', { name: 'Select all' }));

        expect(setShowCustom).toHaveBeenCalledWith(false);
    });
});
