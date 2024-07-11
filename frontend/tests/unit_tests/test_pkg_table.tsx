import { render, screen, waitFor, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Package } from "../../src/handlers/packages";
import TablePackages from '../../src/pages/TablePackages';


const getDOMRect = (width: number, height: number) => ({
    width,
    height,
    top: 0,
    left: 0,
    bottom: 0,
    right: 0,
    x: 0,
    y: 0,
    toJSON: () => {},
})


describe('Packages Table', () => {

    const packages: Package[] = [
        {
            id: 'aaabbbccc@1.0.0',
            name: 'aaabbbccc',
            version: '1.0.0',
            cpe: ['cpe:2.3:a:vendor:aaabbbccc:1.0.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/aaabbbccc@1.0.0'],
            vulnerabilities: {
                "active": 2,
                "fixed": 6
            },
            maxSeverity: {
                "active": {label: 'low', index: 2},
                "fixed": {label: 'medium', index: 3}
            },
            source: ['hardcoded']
        },
        {
            id: 'xxxyyyzzz@2.0.0',
            name: 'xxxyyyzzz',
            version: '2.0.0',
            cpe: ['cpe:2.3:a:vendor:xxxyyyzzz:2.0.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/xxxyyyzzz@2.0.0'],
            vulnerabilities: {"active": 4},
            maxSeverity: {"active": {label: 'high', index: 4}},
            source: ['cve-finder']
        }
    ];

    Element.prototype.getBoundingClientRect = jest.fn(function () {
        return getDOMRect(500, 500)
    })

    test('render headers with empty array', async () => {
        // ARRANGE
        render(<TablePackages packages={[]} />);

        // ACT
        const name_header = await screen.getByRole('columnheader', {name: /name/i});
        const version_header = await screen.getByRole('columnheader', {name: /version/i});
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});

        // ASSERT
        expect(name_header).toBeInTheDocument();
        expect(version_header).toBeInTheDocument();
        expect(vuln_count_header).toBeInTheDocument();
    })

    test('render with packages', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const name_col = await screen.getByRole('cell', {name: /aaabbbccc/});
        const version_col = await screen.getByRole('cell', {name: /1.0.0/});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT
        expect(name_col).toBeInTheDocument();
        expect(version_col).toBeInTheDocument();
        expect(source_col).toBeInTheDocument();
    })

    test('render severity when toggle activated', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const user = userEvent.setup();
        const severity_toggle = await screen.getByRole('button', {name: /severity disabled/i});

        const pending_deletion = waitForElementToBeRemoved(() => screen.getByRole('button', {name: /severity disabled/i}), { timeout: 500 });

        await user.click(severity_toggle); // switch to enabled mode

        await pending_deletion;

        const btn_enabled = await screen.getByRole('button', {name: /severity enabled/i});
        const severity_high = await screen.getByText(/high/i);
        const severity_medium = await screen.getByText(/medium/i);

        // ASSERT
        expect(btn_enabled).toBeInTheDocument();
        expect(severity_high).toBeInTheDocument();
        expect(severity_medium).toBeInTheDocument();
    })

    test('sorting by name', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const name_header = await screen.getByRole('columnheader', {name: /name/i});

        await user.click(name_header); // un-ordoned -> alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(name_header); // alphabetical order -> reverse alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('sorting by version', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const version_header = await screen.getByRole('columnheader', {name: /version/i});

        await user.click(version_header); // un-ordoned -> alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('1.0.0')).toBeLessThan(html.indexOf('2.0.0'));
        });

        await user.click(version_header); // alphabetical order -> reverse alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('2.0.0')).toBeLessThan(html.indexOf('1.0.0'));
        });
    })

    test('sorting by vulnerabilities count', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});

        await user.click(vuln_count_header); // numerical order -> reverse numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(vuln_count_header); // un-ordoned -> numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('searching for package name', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, 'yyy');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /aaabbbccc/}), { timeout: 1000 });

        const pkg_xyz = await screen.getByRole('cell', {name: /xxxyyyzzz/});
        expect(pkg_xyz).toBeInTheDocument();
    })

    test('filter by source', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const selects = await screen.getAllByRole('combobox');
        const filter_select = selects.find((el) => el.getAttribute('name')?.includes('source')) as HTMLElement;
        expect(filter_select).toBeDefined();
        expect(filter_select).toBeInTheDocument();

        const deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /aaabbbccc/}), { timeout: 250 });

        await user.selectOptions(filter_select, 'cve-finder');

        await deletion;

        const pkg_xyz = await screen.getByRole('cell', {name: /xxxyyyzzz/});
        expect(pkg_xyz).toBeInTheDocument();
    })

    test('filter by status', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const hide_fixed = await screen.getByRole('checkbox', {name: /hide fixed/i});
        const severity_toggle = await screen.getByRole('button', {name: /severity disabled/i});
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});

        await user.click(severity_toggle); // switch to enabled mode
        const pending_deletion = waitForElementToBeRemoved(() => screen.getByText(/medium/i), { timeout: 500 });

        // ACT
        await user.click(hide_fixed);
        await user.click(vuln_count_header); // numerical order -> reverse numerical order

        // ASSERT
        await pending_deletion;
        const severity_high = await screen.getByText(/high/i);
        const severity_low = await screen.getByText(/low/i);
        expect(severity_high).toBeInTheDocument();
        expect(severity_low).toBeInTheDocument();

        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })
});
