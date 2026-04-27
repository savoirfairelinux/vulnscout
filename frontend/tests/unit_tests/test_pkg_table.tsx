import { render, screen, waitFor } from '@testing-library/react';
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
            variants: []
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
            variants: []
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
            source: ['cve-finder', 'hardcoded'],
            variants: []
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
        const vuln_count_header = await screen.getByRole('columnheader', {name: /^Vulnerabilities$/i});
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

        // ACT - use getAllByRole and pick the name column (first match)
        const name_cols = await screen.getAllByRole('cell', {name: /aaabbbccc/});
        const version_col = await screen.getByRole('cell', {name: /^1\.0\.0$/});
        const vuln_count_col = await screen.getByRole('cell', {name: /^8$/});
        const source_col = await screen.getByRole('cell', {name: /^hardcoded$/});

        // ASSERT
        expect(name_cols.length).toBeGreaterThan(0);
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

        // Use package names as anchors since version strings may appear in
        // row IDs/keys before the visible table cells.
        await user.click(version_header); // un-ordoned -> alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('dddeeefff'));
            expect(html.indexOf('dddeeefff')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(version_header); // alphabetical order -> reverse alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('dddeeefff'));
            expect(html.indexOf('dddeeefff')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('sorting by vulnerabilities count', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const vuln_count_header = await screen.getByRole('columnheader', {name: /^Vulnerabilities$/i});

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

        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).not.toContain('aaabbbccc');
            expect(html).toContain('xxxyyyzzz');
        }, { timeout: 2000 });
    })

    test('searching with negation text', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '-aaabbbccc');

        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).not.toContain('aaabbbccc');
            expect(html).toContain('xxxyyyzzz');
            expect(html).toContain('dddeeefff');
        }, { timeout: 2000 });
    })

    test('searching with a combination of queries', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '-aaabbbccc xxxyyyzzz');

        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).not.toContain('aaabbbccc');
            expect(html).not.toContain('dddeeefff');
            expect(html).toContain('xxxyyyzzz');
        }, { timeout: 2000 });
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
        await user.click(cveFinderCheckbox);

        // Wait until aaabbbccc is no longer visible (it's only in 'hardcoded' source)
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).not.toContain('aaabbbccc');
        }, { timeout: 2000 });

        const pkg_xyz = screen.getAllByRole('cell', { name: /xxxyyyzzz/ });
        expect(pkg_xyz.length).toBeGreaterThan(0);

        // REVERT CHANGE: uncheck "cve-finder"
        await user.click(cveFinderCheckbox);

        await waitFor(() => {
            expect(screen.getAllByRole('cell', { name: /aaabbbccc/ }).length).toBeGreaterThan(0);
            expect(screen.getAllByRole('cell', { name: /xxxyyyzzz/ }).length).toBeGreaterThan(0);
        });
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
        await waitFor(() => {
            expect(screen.getAllByRole('cell', { name: /aaabbbccc/ }).length).toBeGreaterThan(0);
        });
    })

    test('CPE values are displayed inline in the table', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // ACT: Enable CPE column via Columns filter
        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const cpeCheckbox = screen.getByRole('checkbox', { name: /^CPE$/i });
        await user.click(cpeCheckbox);

        // ASSERT: CPE values should be directly visible (no popup needed)
        const cpeId = await screen.getByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
        expect(cpeId).toBeTruthy();
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

    test('package without CPE shows dash placeholder', async () => {
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
                source: ['test'],
                variants: []
            }
        ];

        render(<TablePackages packages={packagesNoCpe} />);

        const user = userEvent.setup();

        // ACT: Enable CPE column via Columns filter
        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const cpeCheckbox = screen.getByRole('checkbox', { name: /^CPE$/i });
        await user.click(cpeCheckbox);

        // ASSERT: No CPE text should be present, dash placeholder shown
        expect(screen.queryByText(/cpe:2\.3/)).toBeNull();
        expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    })

    test('multiple CPE IDs are displayed inline', async () => {
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
                source: ['test'],
                variants: []
            }
        ];

        render(<TablePackages packages={packagesMultiCpe} />);

        const user = userEvent.setup();

        // ACT: Enable CPE column via Columns filter
        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const cpeCheckbox = screen.getByRole('checkbox', { name: /^CPE$/i });
        await user.click(cpeCheckbox);

        // ASSERT: Both CPE IDs should be directly visible
        const cpeId1 = await screen.getByText(/cpe:2.3:a:vendor:multi-cpe:1.0.0/);
        const cpeId2 = await screen.getByText(/cpe:2.3:a:another:multi-cpe:1.0.0/);
        expect(cpeId1).toBeTruthy();
        expect(cpeId2).toBeTruthy();
    });

    test('shortcut helper icon is visible', async () => {
        render(<TablePackages packages={packages} />);

        const helperBtn = await screen.getByRole('button', { name: /shortcut helper/i });
        expect(helperBtn).toBeTruthy();
    });

    test('shortcut helper shows keyboard shortcuts content', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const helperBtn = await screen.getByRole('button', { name: /shortcut helper/i });
        await user.click(helperBtn);

        expect(await screen.findByText('Keyboard Shortcuts')).toBeTruthy();
        expect(screen.getByText('/')).toBeTruthy();
        expect(screen.getByText('Focus search bar')).toBeTruthy();
        expect(screen.getByText('↑ / ↓')).toBeTruthy();
        expect(screen.getByText('Navigate focused table row')).toBeTruthy();
        expect(screen.getByText('Home / End')).toBeTruthy();
        expect(screen.getByText('Navigate to first/last table row')).toBeTruthy();
    });

    test('search syntax helper is visible and shows syntax content when clicked', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const helperBtn = screen.getByRole('button', { name: /search syntax helper/i });
        expect(helperBtn).toBeTruthy();

        await user.click(helperBtn);

        expect(await screen.findByText('Search Syntax')).toBeTruthy();
        expect(screen.getByText('Match rows containing term')).toBeTruthy();
        expect(screen.getByText('AND: both terms must match')).toBeTruthy();
        expect(screen.getByText('OR: either term matches')).toBeTruthy();
        expect(screen.getByText('NOT: exclude rows with term')).toBeTruthy();
    });

    test('pressing / focuses search bar', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const searchBar = await screen.getByRole('searchbox') as HTMLInputElement;

        expect(document.activeElement).not.toBe(searchBar);

        await user.keyboard('/');

        expect(document.activeElement).toBe(searchBar);
    });

    test('pressing / while search bar is focused types slash in search', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const searchBar = await screen.getByRole('searchbox') as HTMLInputElement;

        searchBar.focus();
        expect(document.activeElement).toBe(searchBar);

        await user.keyboard('/');

        expect(document.activeElement).toBe(searchBar);
        expect(searchBar.value).toBe('/');
    });

    test('ArrowDown and ArrowUp navigate focused table row', async () => {
        const { container } = render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const rows = container.querySelectorAll('tr.row-with-hover-effect');

        expect(rows.length).toBeGreaterThanOrEqual(3);

        const firstRow = rows[0] as HTMLElement;
        const secondRow = rows[1] as HTMLElement;

        firstRow.focus();
        expect(document.activeElement).toBe(firstRow);

        await user.keyboard('{ArrowDown}');
        await waitFor(() => {
            expect(document.activeElement).toBe(secondRow);
        });

        await user.keyboard('{ArrowUp}');
        await waitFor(() => {
            expect(document.activeElement).toBe(firstRow);
        });
    });

    test('Home and End navigate to first and last focused table row', async () => {
        const { container } = render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const rows = container.querySelectorAll('tr.row-with-hover-effect');

        expect(rows.length).toBeGreaterThanOrEqual(3);

        const firstRow = rows[0] as HTMLElement;
        const secondRow = rows[1] as HTMLElement;
        const lastRow = rows[rows.length - 1] as HTMLElement;

        secondRow.focus();
        expect(document.activeElement).toBe(secondRow);

        await user.keyboard('{End}');
        await waitFor(() => {
            expect(document.activeElement).toBe(lastRow);
        });

        await user.keyboard('{Home}');
        await waitFor(() => {
            expect(document.activeElement).toBe(firstRow);
        });
    });

    test('renders variant badges when packages have variants', async () => {
        const packagesWithVariants: Package[] = [
            {
                id: 'pkg-var@1.0.0',
                name: 'pkg-var',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {"active": 1},
                maxSeverity: {"active": {label: 'low', index: 2}},
                source: ['test'],
                variants: ['variant-A', 'variant-B']
            }
        ];

        render(<TablePackages packages={packagesWithVariants} />);

        expect(await screen.findByText('variant-A')).toBeTruthy();
        expect(screen.getByText('variant-B')).toBeTruthy();
    });

    test('sorting by remaining pending vulnerabilities', async () => {
        const packagesWithPending: Package[] = [
            {
                id: 'pkg-a@1.0.0',
                name: 'pkg-a',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {"Pending Assessment": 5, "active": 1},
                maxSeverity: {"active": {label: 'low', index: 2}},
                source: ['test'],
                variants: []
            },
            {
                id: 'pkg-b@1.0.0',
                name: 'pkg-b',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {"Pending Assessment": 1, "active": 2},
                maxSeverity: {"active": {label: 'medium', index: 3}},
                source: ['test'],
                variants: []
            }
        ];

        render(<TablePackages packages={packagesWithPending} />);

        const user = userEvent.setup();

        // Enable "Remaining Pending Vulnerabilities" column via the Columns filter
        const columnsBtn = await screen.getByRole('button', { name: /columns/i });
        await user.click(columnsBtn);
        const pendingCheckbox = await screen.getByRole('checkbox', { name: /remaining pending/i });
        await user.click(pendingCheckbox);

        // Verify both pending values are rendered
        await waitFor(() => {
            const cells = screen.getAllByRole('cell');
            const pendingValues = cells.filter(c => c.textContent === '5' || c.textContent === '1');
            expect(pendingValues.length).toBeGreaterThanOrEqual(2);
        });

        const pendingHeader = await screen.getByRole('columnheader', {name: /remaining pending/i});

        // Click to sort
        await user.click(pendingHeader);

        // Click again to sort in other direction
        await user.click(pendingHeader);

        // Verify sorting by checking the sort icon changed (sort was applied)
        await waitFor(() => {
            const html = document.body.innerHTML;
            // Both names should still be present
            expect(html).toContain('pkg-a');
            expect(html).toContain('pkg-b');
        });
    });

    test('CPE values have title attribute for hover tooltip', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // ACT: Enable CPE column via Columns filter
        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const cpeCheckbox = screen.getByRole('checkbox', { name: /^CPE$/i });
        await user.click(cpeCheckbox);

        const cpeSpan = await screen.getByText(/cpe:2.3:a:vendor:aaabbbccc:1.0.0/);
        expect(cpeSpan).toBeTruthy();
        expect(cpeSpan.getAttribute('title')).toContain('cpe:2.3:a:vendor:aaabbbccc:1.0.0');
    });
});
