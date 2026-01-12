import { render, screen, waitFor, waitForElementToBeRemoved } from '@testing-library/react';
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
        },
        {
            id: 'dddeeefff@1.5.0',
            name: 'dddeeefff',
            version: '1.5.0',
            cpe: ['cpe:2.3:a:vendor:dddeeefff:1.5.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/dddeeefff@1.5.0'],
            vulnerabilities: {"active": 1, "fixed": 2},
            maxSeverity: {
                "active": {label: 'medium', index: 3},
                "fixed": {label: 'low', index: 2}
            },
            source: ['cve-finder', 'hardcoded']
        }
    ];

    Element.prototype.getBoundingClientRect = function () {
        return getDOMRect(500, 500)
    }

    test('render headers with empty array', async () => {
        // ARRANGE
        render(<TablePackages packages={[]} />);

        // ACT
        const name_header = await screen.getByRole('columnheader', {name: /name/i});
        const version_header = await screen.getByRole('columnheader', {name: /version/i});
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});
        const sources_header = await screen.getByRole('columnheader', {name: /sources/i});

        // ASSERT
        expect(name_header).toBeTruthy();
        expect(version_header).toBeTruthy();
        expect(vuln_count_header).toBeTruthy();
        expect(sources_header).toBeTruthy();
    })

    test('render with packages', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const name_col = await screen.getByRole('cell', {name: /aaabbbccc/});
        const version_col = await screen.getByRole('cell', {name: /1.0.0/});
        const vuln_count_col = await screen.getByRole('cell', {name: /^8$/});
        const source_col = await screen.getByRole('cell', {name: /^hardcoded$/});

        // ASSERT
        expect(name_col).toBeTruthy();
        expect(version_col).toBeTruthy();
        expect(vuln_count_col).toBeTruthy();
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
        const severity_high = await screen.getByText('high');
        const severity_mediums = await screen.getAllByText('medium');

        // ASSERT
        expect(btn_enabled).toBeTruthy();
        expect(severity_high).toBeTruthy();
        expect(severity_mediums.length).toBeGreaterThan(0);
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

    test('reset filters button clears all filters', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Set some filters
        const search_bar = await screen.getByRole('searchbox');
        await user.type(search_bar, 'xyz');

        const severity_toggle = await screen.getByRole('button', {name: /show severity/i});
        await user.click(severity_toggle);

        const source_btn = await screen.getByRole('button', { name: /source/i });
        await user.click(source_btn);
        const cveFinderCheckbox = await screen.getByRole('checkbox', { name: /cve-finder/i });
        await user.click(cveFinderCheckbox);

        // ACT: Click reset filters
        const resetBtn = await screen.getByRole('button', { name: /reset filters/i });
        await user.click(resetBtn);

        // ASSERT: All packages should be visible again
        await waitFor(async () => {
            const pkg_abc = await screen.findByRole('cell', { name: /aaabbbccc/ });
            expect(pkg_abc).toBeTruthy();
        });
    })

    test('CPE button shows popup with CPE IDs', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // ACT: Click CPE button
        const cpeButtons = await screen.getAllByText('CPE');
        await user.click(cpeButtons[0]);

        // ASSERT: CPE ID should be visible in popup
        const cpeId = await screen.getByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
        expect(cpeId).toBeTruthy();
    })

    test('CPE popup close button works', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Open CPE popup
        const cpeButtons = await screen.getAllByText('CPE');
        await user.click(cpeButtons[0]);

        // ACT: Click close button in popup
        const closeBtn = await screen.getByText('✕');
        await user.click(closeBtn);

        // ASSERT: CPE ID should no longer be visible
        await waitFor(() => {
            const cpeId = screen.queryByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
            expect(cpeId).toBe(null);
        });
    })

    test('CPE popup closes when clicking CPE button again', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Open CPE popup
        const cpeButtons = await screen.getAllByText('CPE');
        await user.click(cpeButtons[0]);

        // Verify popup is open
        const cpeId = await screen.getByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
        expect(cpeId).toBeTruthy();

        // ACT: Click CPE button again
        await user.click(cpeButtons[0]);

        // ASSERT: CPE ID should no longer be visible
        await waitFor(() => {
            const cpeId = screen.queryByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
            expect(cpeId).toBe(null);
        });
    })

    test('show vulnerabilities button calls onShowVulns', async () => {
        // ARRANGE
        const mockOnShowVulns = jest.fn();
        render(<TablePackages packages={packages} onShowVulns={mockOnShowVulns} />);

        const user = userEvent.setup();

        // ACT: Click show vulnerabilities button
        const showVulnsButtons = await screen.getAllByRole('button', { name: /show vulnerabilities/i });
        await user.click(showVulnsButtons[0]);

        // ASSERT
        expect(mockOnShowVulns).toHaveBeenCalledWith('aaabbbccc@1.0.0');
    })

    test('package without CPE does not show CPE button', async () => {
        // ARRANGE
        const packagesNoCpe: Package[] = [
            {
                id: 'pkg-no-cpe@1.0.0',
                name: 'pkg-no-cpe',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {"active": 1},
                maxSeverity: {"active": {label: 'low', index: 2}},
                source: ['test']
            }
        ];

        render(<TablePackages packages={packagesNoCpe} />);

        // ACT & ASSERT
        const cpeButtons = screen.queryAllByText('CPE');
        expect(cpeButtons).toHaveLength(0);
    })

    test('multiple CPE IDs are displayed in popup', async () => {
        // ARRANGE
        const packagesMultiCpe: Package[] = [
            {
                id: 'multi-cpe@1.0.0',
                name: 'multi-cpe',
                version: '1.0.0',
                cpe: [
                    'cpe:2.3:a:vendor:multi-cpe:1.0.0:*:*:*:*:*:*:*:*',
                    'cpe:2.3:a:another:multi-cpe:1.0.0:*:*:*:*:*:*:*:*'
                ],
                purl: [],
                vulnerabilities: {"active": 1},
                maxSeverity: {"active": {label: 'low', index: 2}},
                source: ['test']
            }
        ];

        render(<TablePackages packages={packagesMultiCpe} />);

        const user = userEvent.setup();

        // ACT: Click CPE button
        const cpeButton = await screen.getByText('CPE');
        await user.click(cpeButton);

        // ASSERT: Both CPE IDs should be visible
        const cpeId1 = await screen.getByText(/cpe:2.3:a:vendor:multi-cpe:1.0.0/);
        const cpeId2 = await screen.getByText(/cpe:2.3:a:another:multi-cpe:1.0.0/);
        expect(cpeId1).toBeTruthy();
        expect(cpeId2).toBeTruthy();
    });
});
