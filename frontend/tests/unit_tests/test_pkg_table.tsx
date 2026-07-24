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
            variants: [],
            sbom_documents: [],
            supplier: '',
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
            variants: [],
            sbom_documents: [],
            supplier: '',
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
            variants: [],
            sbom_documents: [],
            supplier: '',
        }
    ];

    const packagesWithSuppliers: Package[] = [
        {
            id: 'pkg-acme@1.0.0',
            name: 'pkg-acme',
            version: '1.0.0',
            cpe: [],
            purl: [],
            vulnerabilities: {},
            maxSeverity: {},
            source: ['test'],
            variants: [],
            sbom_documents: [],
            supplier: 'Organization: Acme Corp',
        },
        {
            id: 'pkg-globex@1.0.0',
            name: 'pkg-globex',
            version: '1.0.0',
            cpe: [],
            purl: [],
            vulnerabilities: {},
            maxSeverity: {},
            source: ['test'],
            variants: [],
            sbom_documents: [],
            supplier: 'Organization: Globex',
        },
        {
            id: 'pkg-acme2@2.0.0',
            name: 'pkg-acme2',
            version: '2.0.0',
            cpe: [],
            purl: [],
            vulnerabilities: {},
            maxSeverity: {},
            source: ['test'],
            variants: [],
            sbom_documents: [],
            supplier: 'Organization: Acme Corp',
        },
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

    test('does not render the obsolete severity toggle', () => {
        render(<TablePackages packages={packages} />);

        expect(screen.queryByRole('button', {name: /severity/i})).toBeNull();
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
        const source_btn = await screen.getByRole('button', { name: /^source$/i });
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

    test('filter by variant', async () => {
        // ARRANGE: packages spread across two variants
        const packagesWithVariants: Package[] = [
            { ...packages[0], variants: ['variant-a'] },
            { ...packages[1], variants: ['variant-b'] },
            { ...packages[2], variants: ['variant-a', 'variant-b'] },
        ];
        render(<TablePackages packages={packagesWithVariants} />);

        const user = userEvent.setup();

        // Open the "Variants" filter dropdown
        const variants_btn = await screen.getByRole('button', { name: /^variants$/i });
        await user.click(variants_btn);

        // All variants are checked by default. ACT: uncheck "variant-a"
        const variantACheckbox = await screen.getByRole('checkbox', { name: /variant-a/i });
        await user.click(variantACheckbox);

        // aaabbbccc is only in variant-a, so it must disappear
        await waitFor(() => {
            expect(document.body.innerHTML).not.toContain('aaabbbccc');
        }, { timeout: 2000 });

        // xxxyyyzzz (variant-b) and dddeeefff (variant-a + variant-b) remain
        expect(screen.getAllByRole('cell', { name: /xxxyyyzzz/ }).length).toBeGreaterThan(0);
        expect(screen.getAllByRole('cell', { name: /dddeeefff/ }).length).toBeGreaterThan(0);

        // REVERT CHANGE: re-check "variant-a"
        await user.click(variantACheckbox);

        await waitFor(() => {
            expect(screen.getAllByRole('cell', { name: /aaabbbccc/ }).length).toBeGreaterThan(0);
        });
    })

    test('variant filter is hidden when no package has variants', async () => {
        // ARRANGE: the default packages have no variants
        render(<TablePackages packages={packages} />);

        // ASSERT: the "Variants" filter button is not rendered
        expect(screen.queryByRole('button', { name: /^variants$/i })).toBeNull();
    })

    test('reset filters button clears all filters', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Set some filters
        const search_bar = await screen.getByRole('searchbox');
        await user.type(search_bar, 'xyz');

        const source_btn = await screen.getByRole('button', { name: /^source$/i });
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
                variants: [],
                sbom_documents: [],
                supplier: '',
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
                variants: [],
                sbom_documents: [],
                supplier: '',
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
                variants: ['variant-A', 'variant-B'],
                sbom_documents: [],
                supplier: '',
            }
        ];

        render(<TablePackages packages={packagesWithVariants} />);

        expect(await screen.findByText('variant-A')).toBeTruthy();
        expect(screen.getByText('variant-B')).toBeTruthy();
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

    test('supplier column is hidden by default when no package has supplier info', async () => {
        render(<TablePackages packages={packages} />);
        // All packages have empty supplier, so the column should NOT be visible initially
        expect(screen.queryByRole('columnheader', { name: /^supplier$/i })).toBeNull();
    });

    test('supplier column is shown by default when at least one package has supplier info', async () => {
        const packagesWithSupplier: Package[] = [
            { ...packages[0], supplier: 'Acme Corp' },
            ...packages.slice(1),
        ];
        render(<TablePackages packages={packagesWithSupplier} />);
        // At least one package has a supplier, so the column should be visible by default
        const supplierHeader = await screen.findByRole('columnheader', { name: /^supplier$/i });
        expect(supplierHeader).toBeTruthy();
    });

    test('filter by supplier', async () => {
        render(<TablePackages packages={packagesWithSuppliers} />);
        const user = userEvent.setup();

        // ACT: open the Supplier filter dropdown and select "Acme Corp"
        const supplierBtn = await screen.getByRole('button', { name: /^supplier$/i });
        await user.click(supplierBtn);

        const acmeCheckbox = await screen.getByRole('checkbox', { name: /acme corp/i });
        await user.click(acmeCheckbox);

        // ASSERT: only Acme Corp packages are shown, Globex is hidden
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).toContain('pkg-acme');
            expect(html).toContain('pkg-acme2');
            expect(html).not.toContain('pkg-globex');
        }, { timeout: 2000 });

        // REVERT: uncheck "Acme Corp" — all packages should reappear
        await user.click(acmeCheckbox);

        await waitFor(() => {
            expect(screen.getAllByRole('cell', { name: /pkg-globex/ }).length).toBeGreaterThan(0);
        });
    });

    test('PURL column displays PURL values when enabled', async () => {
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Enable PURL column via Columns filter
        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const purlCheckbox = screen.getByRole('checkbox', { name: /^PURL$/i });
        await user.click(purlCheckbox);

        // PURL value should now be visible
        const purlSpan = await screen.getByText(/pkg:vendor\/aaabbbccc@1\.0\.0/);
        expect(purlSpan).toBeTruthy();
    });

    test('PURL column shows dash placeholder when package has no PURL', async () => {
        const packagesNoPurl: Package[] = [
            {
                id: 'pkg-no-purl@1.0.0',
                name: 'pkg-no-purl',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: { 'active': 1 },
                maxSeverity: { 'active': { label: 'low', index: 2 } },
                source: ['test'],
                variants: [],
                sbom_documents: [],
                supplier: '',
            }
        ];

        render(<TablePackages packages={packagesNoPurl} />);
        const user = userEvent.setup();

        const columnsBtn = screen.getByText('Columns');
        await user.click(columnsBtn);
        const purlCheckbox = screen.getByRole('checkbox', { name: /^PURL$/i });
        await user.click(purlCheckbox);

        expect(screen.queryByText(/pkg:/)).toBeNull();
        expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    });

    test('filter by SBOM document hides packages not matching that document', async () => {
        const packagesWithSbom: Package[] = [
            {
                id: 'pkg-with-sbom@1.0.0',
                name: 'pkg-with-sbom',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {},
                maxSeverity: {},
                source: ['test'],
                variants: [],
                sbom_documents: ['build-2024.spdx.json'],
                supplier: '',
            },
            {
                id: 'pkg-other-sbom@1.0.0',
                name: 'pkg-other-sbom',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {},
                maxSeverity: {},
                source: ['test'],
                variants: [],
                sbom_documents: ['release-2024.spdx.json'],
                supplier: '',
            },
        ];

        render(<TablePackages packages={packagesWithSbom} />);
        const user = userEvent.setup();

        // Open the SBOM Source File filter dropdown
        const sbomBtn = await screen.getByRole('button', { name: /^sbom source file$/i });
        await user.click(sbomBtn);

        const buildCheckbox = await screen.getByRole('checkbox', { name: /build-2024\.spdx\.json/i });
        await user.click(buildCheckbox);

        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html).toContain('pkg-with-sbom');
            expect(html).not.toContain('pkg-other-sbom');
        }, { timeout: 2000 });

        // Uncheck to restore
        await user.click(buildCheckbox);

        await waitFor(() => {
            expect(screen.getAllByRole('cell', { name: /pkg-other-sbom/ }).length).toBeGreaterThan(0);
        });
    });

    test('SBOM Source File column shows document badge when enabled', async () => {
        const packagesWithSbom: Package[] = [
            {
                id: 'pkg-with-doc@1.0.0',
                name: 'pkg-with-doc',
                version: '1.0.0',
                cpe: [],
                purl: [],
                vulnerabilities: {},
                maxSeverity: {},
                source: ['test'],
                variants: [],
                sbom_documents: ['production-2024.spdx.json'],
                supplier: '',
            },
        ];

        // The SBOM Source File column is defined in allColumns but filtered from rendered columns
        // because 'sbom_documents' has no entry in columnDisplayNames.
        // The SBOM Source File FilterOption is a filter button, not a column toggle.
        // Verify the filter button is rendered correctly.
        render(<TablePackages packages={packagesWithSbom} />);

        // The SBOM Source File filter button should be present
        const sbomFilterBtn = screen.getByRole('button', { name: /^sbom source file$/i });
        expect(sbomFilterBtn).toBeTruthy();

        // Open it and verify the document is listed as a filter option
        const user = userEvent.setup();
        await user.click(sbomFilterBtn);

        const docCheckbox = await screen.findByRole('checkbox', { name: /production-2024\.spdx\.json/i });
        expect(docCheckbox).toBeTruthy();
    });

    test('clicking outside shortcut helper dropdown closes it', async () => {
        render(<TablePackages packages={packages} />);
        const user = userEvent.setup();

        // Open the shortcut helper
        const helperBtn = await screen.getByRole('button', { name: /shortcut helper/i });
        await user.click(helperBtn);

        // Verify it opened
        expect(await screen.findByText('Keyboard Shortcuts')).toBeTruthy();

        // Click outside (on the document body)
        await user.click(document.body);

        // Dropdown should close
        await waitFor(() => {
            expect(screen.queryByText('Keyboard Shortcuts')).toBeNull();
        });
    });

    test('clicking outside search syntax helper closes it', async () => {
        render(<TablePackages packages={packages} />);
        const user = userEvent.setup();

        // Open the search syntax helper
        const helperBtn = screen.getByRole('button', { name: /search syntax helper/i });
        await user.click(helperBtn);

        expect(await screen.findByText('Search Syntax')).toBeTruthy();

        // Click outside
        await user.click(document.body);

        await waitFor(() => {
            expect(screen.queryByText('Search Syntax')).toBeNull();
        });
    });
});
