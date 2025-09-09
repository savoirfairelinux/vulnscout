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
            source: ['hardcoded'],
            licences: 'MIT AND Apache-2.0'
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
            licences: 'GPL-3.0'
        },
        {
            id: 'customlicense@1.5.0',
            name: 'customlicense',
            version: '1.5.0',
            cpe: ['cpe:2.3:a:vendor:customlicense:1.5.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/customlicense@1.5.0'],
            vulnerabilities: {"active": 1, "fixed": 2},
            maxSeverity: {
                "active": {label: 'medium', index: 3},
                "fixed": {label: 'low', index: 2}
            },
            source: ['cve-finder', 'hardcoded'],
            licences: 'DocumentRef-custom-license LicenseRef-proprietary'
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
        const licences_header = await screen.getByRole('columnheader', {name: /licences/i});
        const vuln_count_header = await screen.getByRole('columnheader', {name: /vulnerabilities/i});
        const sources_header = await screen.getByRole('columnheader', {name: /sources/i});

        // ASSERT
        expect(name_header).toBeTruthy();
        expect(version_header).toBeTruthy();
        expect(licences_header).toBeTruthy();
        expect(vuln_count_header).toBeTruthy();
        expect(sources_header).toBeTruthy();
    })

    test('render with packages', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const name_col = await screen.getByRole('cell', {name: /aaabbbccc/});
        const version_col = await screen.getByRole('cell', {name: /1.0.0/});
        const licences_col = await screen.getByRole('cell', {name: /MIT AND Apache-2.0/});
        const vuln_count_col = await screen.getByRole('cell', {name: /^8$/});
        const source_col = await screen.getByRole('cell', {name: /^hardcoded$/});

        // ASSERT
        expect(name_col).toBeTruthy();
        expect(version_col).toBeTruthy();
        expect(licences_col).toBeTruthy();
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

    test('filter by licences', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Open the "Licences" filter dropdown
        const licences_btn = await screen.getByRole('button', { name: /licences/i });
        await user.click(licences_btn);

        // ACT: select "MIT"
        const mitCheckbox = await screen.getByRole('checkbox', { name: /^MIT$/i });
        const deletion = waitForElementToBeRemoved(() => screen.queryByRole('cell', { name: /xxxyyyzzz/ }), { timeout: 2000 });
        await user.click(mitCheckbox);
        await deletion;

        const pkg_abc = await screen.getByRole('cell', { name: /aaabbbccc/ });
        expect(pkg_abc).toBeTruthy();

        // REVERT CHANGE: uncheck "MIT"
        await user.click(mitCheckbox);

        const pkg_abc2 = await screen.getByRole('cell', { name: /aaabbbccc/ });
        const pkg_xyz = await screen.getByRole('cell', { name: /xxxyyyzzz/ });

        expect(pkg_abc2).toBeTruthy();
        expect(pkg_xyz).toBeTruthy();
    })

    test('filter by custom licence', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();

        // Open the "Licences" filter dropdown
        const licences_btn = await screen.getByRole('button', { name: /licences/i });
        await user.click(licences_btn);

        // ACT: select "Custom Licence"
        const customCheckbox = await screen.getByRole('checkbox', { name: /Custom Licence/i });
        const deletion = waitForElementToBeRemoved(() => screen.queryByRole('cell', { name: /aaabbbccc/ }), { timeout: 2000 });
        await user.click(customCheckbox);
        await deletion;

        const pkg_custom = await screen.getByRole('cell', { name: /customlicense/ });
        expect(pkg_custom).toBeTruthy();
        expect(screen.queryByRole('cell', { name: /xxxyyyzzz/ })).toBeNull();
    })
});
