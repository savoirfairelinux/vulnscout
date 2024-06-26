import { render, screen, waitFor, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import TableVulnerabilities from '../../src/pages/TableVulnerabilities';


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

    const vulnerabilities: Vulnerability[] = [
        {
            id: 'CVE-2010-1234',
            aliases: ['CVE-2008-3456'],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: 'hardcoded',
            datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2010-1234',
            packages: ['aaabbbccc@1.0.0'],
            urls: ['https://security-tracker.debian.org/tracker/CVE-2010-1234'],
            texts: [
                {
                    title: 'description',
                    content: 'This vulnerability impact the authentification process of 4 first numbers (1, 2, 3 and 4)'
                }
            ],
            severity: {
                severity: 'low',
                min_score: 3,
                max_score: 3,
                cvss: []
            },
            fix: {
                state: 'unknown'
            },
            status: 'affected',
            simplified_status: 'active',
            assessments: []
        },
        {
            id: 'CVE-2018-5678',
            aliases: ['CVE-2017-7890'],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: 'cve-finder',
            datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2018-5678',
            packages: ['xxxyyyzzz@2.0.0'],
            urls: ['https://security-tracker.debian.org/tracker/CVE-2018-5678'],
            texts: [
                {
                    title: 'description',
                    content: 'This vulnerability allow remote execution of code (RCE) on ssh daemon, thus allowing root access'
                }
            ],
            severity: {
                severity: 'high',
                min_score: 8,
                max_score: 8,
                cvss: []
            },
            fix: {
                state: 'unknown'
            },
            status: 'under_investigation',
            simplified_status: 'pending analysis',
            assessments: []
        }
    ];

    Element.prototype.getBoundingClientRect = jest.fn(function () {
        return getDOMRect(500, 500)
    })

    test('render headers with empty array', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={[]} appendAssessment={() => {}} />);

        // ACT
        const id_header = await screen.getByRole('columnheader', {name: /id/i});
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});
        const packages_header = await screen.getByRole('columnheader', {name: /packages/i});
        const status_header = await screen.getByRole('columnheader', {name: /status/i});
        const source_header = await screen.getByRole('columnheader', {name: /source/i});

        // ASSERT
        expect(id_header).toBeInTheDocument();
        expect(severity_header).toBeInTheDocument();
        expect(packages_header).toBeInTheDocument();
        expect(status_header).toBeInTheDocument();
        expect(source_header).toBeInTheDocument();
    })

    test('render with vulnerabilities', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        // ACT
        const id_col = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const severity_col = await screen.getByRole('cell', {name: /low/});
        const packages_col = await screen.getByRole('cell', {name: /aaabbbccc@1\.0\.0/i});
        const status_col = await screen.getByRole('cell', {name: /pending analysis/i});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT
        expect(id_col).toBeInTheDocument();
        expect(severity_col).toBeInTheDocument();
        expect(packages_col).toBeInTheDocument();
        expect(status_col).toBeInTheDocument();
        expect(source_col).toBeInTheDocument();
    })

    test('sorting by name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const id_header = await screen.getByRole('columnheader', {name: /id/i});

        await user.click(id_header); // un-ordoned -> reverse alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('CVE-2018-5678')).toBeLessThan(html.indexOf('CVE-2010-1234'));
        });

        await user.click(id_header); // reverse alphabetical order -> alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('CVE-2010-1234')).toBeLessThan(html.indexOf('CVE-2018-5678'));
        });
    })

    test('sorting by severity', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});

        await user.click(severity_header); // un-ordoned -> alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(severity_header); // alphabetical order -> reverse alphabetical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('sorting by status', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const status_header = await screen.getByRole('columnheader', {name: /status/i});

        await user.click(status_header); // un-ordoned -> numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('pending analysis')).toBeLessThan(html.indexOf('active'));
        });

        await user.click(status_header); // numerical order -> reverse numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('active')).toBeLessThan(html.indexOf('pending analysis'));
        });
    })

    test('searching for vulnerability ID', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '\'2018-5678');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 1000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching for package name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, 'yyy');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 1000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching for description', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '\'authentification process');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2018-5678/}), { timeout: 1000 });

        const vuln_abc = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_abc).toBeInTheDocument();
    })

    test('filter by source', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const selects = await screen.getAllByRole('combobox');
        const filter_select = selects.find((el) => el.getAttribute('name')?.includes('source')) as HTMLElement;
        expect(filter_select).toBeDefined();
        expect(filter_select).toBeInTheDocument();

        const deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 250 });

        await user.selectOptions(filter_select, 'cve-finder');

        await deletion;

        const pkg_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(pkg_xyz).toBeInTheDocument();
    })
});
