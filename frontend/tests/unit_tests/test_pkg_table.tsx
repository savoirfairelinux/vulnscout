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
            vulnerabilities: 2,
            maxSeverity: 'low',
            source: ['hardcoded']
        },
        {
            id: 'xxxyyyzzz@2.0.0',
            name: 'xxxyyyzzz',
            version: '2.0.0',
            cpe: ['cpe:2.3:a:vendor:xxxyyyzzz:2.0.0:*:*:*:*:*:*:*:*'],
            purl: ['pkg:vendor/xxxyyyzzz@2.0.0'],
            vulnerabilities: 4,
            maxSeverity: 'high',
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
        const name_header = await screen.getByText(/name/i);
        const version_header = await screen.getByText(/version/i);
        const vuln_count_header = await screen.getByText(/vulnerabilities/i);

        // ASSERT
        expect(name_header).toBeInTheDocument();
        expect(version_header).toBeInTheDocument();
        expect(vuln_count_header).toBeInTheDocument();
    })

    test('render with packages', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        // ACT
        const name_col = await screen.getByText(/aaabbbccc/);
        const version_col = await screen.getByText(/1.0.0/);
        const source_col = await screen.getByText(/hardcoded/);

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
        const severity_toggle = await screen.getByText(/severity disabled/i);

        const pending_deletion = waitForElementToBeRemoved(() => screen.queryByText(/severity disabled/i), { timeout: 500 });

        await user.click(severity_toggle); // switch to enabled mode

        await pending_deletion;

        const btn_enabled = await screen.getByText(/severity enabled/i);
        const severity_high = await screen.getByText(/high/i);
        const severity_low = await screen.getByText(/low/i);

        // ASSERT
        expect(btn_enabled).toBeInTheDocument();
        expect(severity_high).toBeInTheDocument();
        expect(severity_low).toBeInTheDocument();
    })

    test('sorting by name', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const name_header = await screen.getByText(/name/i);

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
        const version_header = await screen.getByText(/version/i);

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
        const vuln_count_header = await screen.getByText(/vulnerabilities/i);

        await user.click(vuln_count_header); // numerical order -> reverse numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });

        await user.click(vuln_count_header); // un-ordoned -> numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });
    })

    test('searching for package name', async () => {
        // ARRANGE
        render(<TablePackages packages={packages} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByPlaceholderText(/search/i);

        await user.type(search_bar, 'yyy');

        await waitForElementToBeRemoved(() => screen.queryByText(/aaabbbccc/), { timeout: 1000 });

        const pkg_xyz = await screen.getByText(/xxxyyyzzz/);
        expect(pkg_xyz).toBeInTheDocument();
    })
});
