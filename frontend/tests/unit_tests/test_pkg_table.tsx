import { render, screen, waitFor, waitForElementToBeRemoved, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
import { describe, test, expect } from '@jest/globals';
import matchers from '@testing-library/jest-dom/matchers';
expect.extend(matchers);

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
            source: ['hardcoded'],
            licences: 'NOASSERTION'
        },
        {
            id: 'xxxyyyzzz@2.0.0',
            name: 'xxxyyyzzz',
            version: '2.0.0',
            cpe: ['cpe:2.3:a:vendor:xxxyyyzzz:2.0.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/xxxyyyzzz@2.0.0'],
            vulnerabilities: {"active": 4},
            maxSeverity: {"active": {label: 'high', index: 4}},
            source: ['cve-finder'],
            licences: 'NOASSERTION'
        }
    ];

    Element.prototype.getBoundingClientRect = function () { return getDOMRect(500, 500); } as any;

    test('render headers with empty array', async () => {
        // ARRANGE
        render(<TablePackages packages={[]} />);

        // ACT
        const name_header = await screen.getByRole('columnheader', {name: /name/i});
        const version_header = await screen.getByRole('columnheader', {name: /version/i});
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});

        // ASSERT
        expect(name_header).toBeTruthy();
        expect(version_header).toBeTruthy();
        expect(vuln_count_header).toBeTruthy();
    })

    test('render with packages', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const name_col = await screen.getByRole('cell', {name: /aaabbbccc/});
        const version_col = await screen.getByRole('cell', {name: /1.0.0/});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT
        expect(name_col).toBeTruthy();
        expect(version_col).toBeTruthy();
        expect(source_col).toBeTruthy();
    })

    test('render severity when toggle activated', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const user = userEvent.setup();
        const severity_toggle = await screen.getByRole('button', {name: /show severity/i});

        await user.click(severity_toggle); // switch to enabled mode

        const btn_enabled = await screen.getByRole('button', {name: /hide severity/i});
        const severity_high = await screen.getByText(/high/i);
        const severity_medium = await screen.getByText(/medium/i);

        // ASSERT
        expect(btn_enabled).toBeTruthy();
        expect(severity_high).toBeTruthy();
        expect(severity_medium).toBeTruthy();
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

        await waitForElementToBeRemoved(() => screen.queryByRole('cell', { name: /aaabbbccc/ }), { timeout: 2000 });

        const pkg_xyz = await screen.getByRole('cell', {name: /xxxyyyzzz/});
        expect(pkg_xyz).toBeTruthy();
    })

    test('filter by source', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Open the "Source" filter dropdown
        const source_btn = await screen.getByRole('button', { name: /source/i });
        await user.click(source_btn);

        // ACT: select "cve-finder"
        const cveFinderCheckbox = await screen.getByRole('checkbox', { name: /cve-finder/i });
        const deletion = waitForElementToBeRemoved(() => screen.queryByRole('cell', { name: /aaabbbccc/ }), { timeout: 2000 });
        await user.click(cveFinderCheckbox);
        await deletion;

        const pkg_xyz = await screen.getByRole('cell', { name: /xxxyyyzzz/ });
        expect(pkg_xyz).toBeTruthy();

        // REVERT CHANGE: uncheck "cve-finder"
        await user.click(cveFinderCheckbox);

        const pkg_abc = await screen.getByRole('cell', { name: /aaabbbccc/ });
        const pkg_xyz2 = await screen.getByRole('cell', { name: /xxxyyyzzz/ });

        expect(pkg_abc).toBeTruthy();
        expect(pkg_xyz2).toBeTruthy();
    })

    test('filter by status', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const status_btn = await screen.getByRole('button', { name: /status/i });
        await user.click(status_btn);
        const fixed_checkbox = await screen.getByRole('checkbox', { name: /fixed/i });
        // Schedule wait before applying the filter to ensure the target exists
        const removal = waitForElementToBeRemoved(() => screen.queryByRole('cell', { name: /xxxyyyzzz/ }), { timeout: 4000 });
        // Apply status filter first (clicking outside would close the dropdown)
        await user.click(fixed_checkbox);
        await removal;
        const severity_toggle = await screen.getByRole('button', { name: /show severity/i });
        const vuln_count_header = await screen.getByRole('columnheader', { name: /vulnerabilities/i });
        await user.click(severity_toggle); // switch to enabled mode
        // ACT

        // Then assert remaining row shows count 2 (excluding 'fixed')
        await waitFor(() => {
            const pkgNameCell = screen.getByRole('cell', { name: /aaabbbccc/ });
            const pkgRow = pkgNameCell.closest('tr') as HTMLElement;
            expect(within(pkgRow).getByText(/^2$/)).toBeTruthy();
        }, { timeout: 4000 });

        // Assert the remaining row "aaabbbccc" shows count 2 (excluding 'fixed')
        const pkgNameCell = await screen.getByRole('cell', { name: /aaabbbccc/ });
        const pkgRow = pkgNameCell.closest('tr') as HTMLElement;
        expect(pkgRow).toBeTruthy();
        expect(within(pkgRow).getByText(/^2$/)).toBeTruthy();

        await user.click(vuln_count_header); // numerical order -> reverse numerical order

        // ASSERT
        const severity_low = await screen.getByText(/low/i);
        expect(severity_low).toBeTruthy();
        expect(screen.queryByText(/high/i)).toBeNull();
    })
});
