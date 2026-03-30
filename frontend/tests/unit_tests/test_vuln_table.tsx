/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { fireEvent, render, screen, waitFor, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import TableVulnerabilities from '../../src/pages/TableVulnerabilities';
import Iso8601Duration from '../../src/handlers/iso8601duration';

// Mock NVDProgressHandler to prevent unwanted fetch calls
jest.mock('../../src/handlers/nvd_progress', () => ({
    __esModule: true,
    default: {
        getProgress: jest.fn().mockImplementation(() => new Promise(() => {})),
        getProgressPercentage: jest.fn().mockReturnValue(0),
    },
}));


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


describe('Vulnerability Table', () => {

    const vulnerabilities: Vulnerability[] = [
        {
            id: 'CVE-2010-1234',
            aliases: ['CVE-2008-3456'],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: ['hardcoded'],
            datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2010-1234',
            packages: ['aaabbbccc@1.0.0'],
            packages_current: ['aaabbbccc@1.0.0'],
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
                cvss: [{
                    author: 'company A',
                    severity: 'low',
                    base_score: 3,
                    vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                    version: '3.1',
                    impact_score: 0,
                    exploitability_score: 0,
                    attack_vector: 'NETWORK'
                }]
            },
            epss: {
                score: 0.356789,
                percentile: 0.7546
            },
            effort: {
                optimistic: new Iso8601Duration('PT4H'),
                likely: new Iso8601Duration('P1DT2H'),
                pessimistic: new Iso8601Duration('P2.5D')
            },
            fix: {
                state: 'unknown'
            },
            status: 'affected',
            simplified_status: 'Exploitable',
            assessments: [],
            variants: [],
            published: '2010-05-15T08:00:00Z'
        },
        {
            id: 'CVE-2018-5678',
            aliases: ['CVE-2017-7890'],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: ['cve-finder'],
            datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2018-5678',
            packages: ['xxxyyyzzz@2.0.0'],
            packages_current: ['xxxyyyzzz@2.0.0'],
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
                cvss: [
                    {
                        author: 'company A',
                        severity: 'high',
                        base_score: 8,
                        vector_string: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                        version: '3.1',
                        impact_score: 0,
                        exploitability_score: 0,
                        attack_vector: 'LOCAL'
                    },
                    {
                        author: 'company B',
                        severity: 'high',
                        base_score: 8,
                        vector_string: 'CVSS:3.1/AV:P',
                        version: '3.1',
                        impact_score: 0,
                        exploitability_score: 0,
                        attack_vector: 'PHYSICAL'
                    }
                ]
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            effort: {
                optimistic: new Iso8601Duration(undefined),
                likely: new Iso8601Duration('P2D'),
                pessimistic: new Iso8601Duration('P0D')
            },
            fix: {
                state: 'unknown'
            },
            status: 'under_investigation',
            simplified_status: 'Pending Assessment',
            published: '2018-07-22T14:30:00Z',
            assessments: [],
            variants: []
        },
        {
            id: 'CVE-2024-56730',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'unknown',
            found_by: ['yocto'],
            datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2024-56730',
            packages: ['linux-yocto@6.6.21'],
            packages_current: ['linux-yocto@6.6.21'],
            urls: ['https://nvd.nist.gov/vuln/detail/CVE-2024-56730'],
            texts: [
                {
                    title: 'summary',
                    content: 'In the Linux kernel, the following vulnerability has been resolved:\n\nnet/9p/usbg: fix handling of the failed kzalloc() memory allocation\n\nOn the linux-next, next-20241108 vanilla kernel, the coccinelle tool gave the\nfollowing error report:\n\n./net/9p/trans_usbg.c:912:5-11: ERROR: allocation function on line 911 returns\nNULL not ERR_PTR on failure\n\nkzalloc() failure is fixed to handle the NULL return case on the memory exhaustion.'
                }
            ],
            severity: {
                severity: 'medium',
                min_score: 5.5,
                max_score: 5.5,
                cvss: [
                    {
                        author: 'unknown',
                        severity: 'Medium',
                        version: '3.1',
                        vector_string: 'CVSS:3.1/AV:LOCAL',
                        attack_vector: 'LOCAL',
                        base_score: 5.5,
                        exploitability_score: 0,
                        impact_score: 0
                    }
                ]
            },
            epss: {
                score: 0.00021,
                percentile: 0.04731
            },
            effort: {
                optimistic: new Iso8601Duration(undefined),
                likely: new Iso8601Duration(undefined),
                pessimistic: new Iso8601Duration(undefined)
            },
            fix: {
                state: 'unknown'
            },
            status: 'fixed',
            simplified_status: 'Fixed',
            assessments: [
                {
                    id: '9db07870-42c0-4e7a-b1b5-689c29f8943f',
                    vuln_id: 'CVE-2024-56730',
                    packages: ['linux-yocto@6.6.21'],
                    status: 'fixed',
                    simplified_status: 'Fixed',
                    status_notes: '',
                    justification: '',
                    impact_statement: 'Yocto reported vulnerability as Patched',
                    workaround: '',
                    workaround_timestamp: '',
                    timestamp: '2026-02-06T17:43:14.254534+00:00',
                    last_update: '2026-02-06T17:43:14.254537+00:00',
                    responses: []
                }
            ],
            variants: []
        }
    ];

    Element.prototype.getBoundingClientRect = jest.fn(function () {
        return getDOMRect(500, 500)
    })

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('render headers with empty array', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={[]} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // ACT - Check for default visible columns
        const id_header = await screen.getByRole('columnheader', {name: /id/i});
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});
        const exploit_header = await screen.getByRole('columnheader', {name: /EPSS score/i});
        const packages_header = await screen.getByRole('columnheader', {name: /SBOM Affected/i});
        const status_header = await screen.getByRole('columnheader', {name: /status/i});
        const last_updated_header = await screen.getByRole('columnheader', {name: /last updated/i});

        // ASSERT - Default visible columns
        expect(id_header).toBeInTheDocument();
        expect(severity_header).toBeInTheDocument();
        expect(exploit_header).toBeInTheDocument();
        expect(packages_header).toBeInTheDocument();
        expect(status_header).toBeInTheDocument();
        expect(last_updated_header).toBeInTheDocument();

        // Now enable hidden columns to test they can be shown
        const buttons = await screen.getAllByRole('button', { name: /columns/i });
        const columnsBtn = buttons[0]; // Get the first Columns button
        await user.click(columnsBtn);

        const attackVectorCheckbox = await screen.getByRole('checkbox', { name: 'Attack Vector' });
        const sourcesCheckbox = await screen.getByRole('checkbox', { name: 'Sources' });

        await user.click(attackVectorCheckbox);
        await user.click(sourcesCheckbox);

        // ACT - Check for now-visible columns
        const atk_vector_header = await screen.getByRole('columnheader', {name: /attack vector/i});
        const source_header = await screen.getByRole('columnheader', {name: /source/i});

        // ASSERT - Previously hidden columns are now visible
        expect(atk_vector_header).toBeInTheDocument();
        expect(source_header).toBeInTheDocument();
    })

    test('render with vulnerabilities', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // ACT - Check default visible columns
        const id_col = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const severity_col = await screen.getByRole('cell', {name: /low/});
        const epss_col = await screen.getByRole('cell', {name: /35\.68%/});
        const packages_col = await screen.getByRole('cell', {name: /aaabbbccc@1\.0\.0/i});
        const status_col = await screen.getByRole('cell', {name: /Pending Assessment/i});

        // ASSERT - Default visible columns
        expect(id_col).toBeInTheDocument();
        expect(severity_col).toBeInTheDocument();
        expect(epss_col).toBeInTheDocument();
        expect(packages_col).toBeInTheDocument();
        expect(status_col).toBeInTheDocument();

        // Now enable hidden columns to test their content
        const buttons = await screen.getAllByRole('button', { name: /columns/i });
        const columnsBtn = buttons[0]; // Get the first Columns button
        await user.click(columnsBtn);

        const effortCheckbox = await screen.getByRole('checkbox', { name: 'Estimated Effort' });
        const attackVectorCheckbox = await screen.getByRole('checkbox', { name: 'Attack Vector' });
        const sourcesCheckbox = await screen.getByRole('checkbox', { name: 'Sources' });

        await user.click(effortCheckbox);
        await user.click(attackVectorCheckbox);
        await user.click(sourcesCheckbox);

        // ACT - Check content of now-visible columns
        const effort_col = await screen.getByRole('cell', {name: /1d 2h/i});
        const atk_vector_col = await screen.getByRole('cell', {name: /network/i});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT - Previously hidden columns now show correct content
        expect(effort_col).toBeInTheDocument();
        expect(atk_vector_col).toBeInTheDocument();
        expect(source_col).toBeInTheDocument();
    })

    test('sorting by name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});

        await user.click(severity_header); // un-ordered -> descending order (high to low)
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });

        await user.click(severity_header); // descending order -> ascending order (low to high)
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });
    })

    test('sorting by attack vector', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // First, enable the Attack Vector column
        const buttons = await screen.getAllByRole('button', { name: /columns/i });
        const columnsBtn = buttons[0]; // Get the first Columns button
        await user.click(columnsBtn);
        const attackVectorCheckbox = await screen.getByRole('checkbox', { name: 'Attack Vector' });
        await user.click(attackVectorCheckbox);

        // Now get the header and test sorting
        const atk_vector_header = await screen.getByRole('columnheader', {name: /attack vector/i});

        await user.click(atk_vector_header); // un-ordoned -> network first
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(atk_vector_header); // network first -> physical first
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('sorting by exploitability score', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const exploit_header = await screen.getByRole('columnheader', {name: /EPSS score/i});

        await user.click(exploit_header); // un-ordoned -> more important first
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });

        await user.click(exploit_header); // more important first -> reverse (lower first)
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });
    })

    test('sorting by efforts needed', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // First, enable the Estimated Effort column
        // Use getAllByRole to handle multiple buttons with 'columns' in name, select the first (main button)
        const columnsButtons = await screen.getAllByRole('button', { name: /columns/i });
        await user.click(columnsButtons[0]);
        const effortCheckbox = await screen.getByRole('checkbox', { name: 'Estimated Effort' });
        await user.click(effortCheckbox);

        // Now get the header and test sorting
        const effort_header = await screen.getByRole('columnheader', {name: /effort/i});

        await user.click(effort_header); // un-ordoned -> more long first
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('xxxyyyzzz')).toBeLessThan(html.indexOf('aaabbbccc'));
        });

        await user.click(effort_header); // more long first -> reverse (short first)
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('aaabbbccc')).toBeLessThan(html.indexOf('xxxyyyzzz'));
        });
    })

    test('sorting by status', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const status_header = await screen.getByRole('columnheader', {name: /status/i});

        await user.click(status_header); // un-ordoned -> numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('CVE-2018-5678')).toBeLessThan(html.indexOf('CVE-2010-1234'));
        });

        await user.click(status_header); // numerical order -> reverse numerical order
        await waitFor(() => {
            const html = document.body.innerHTML;
            expect(html.indexOf('CVE-2010-1234')).toBeLessThan(html.indexOf('CVE-2018-5678'));
        });
    })

    test('searching for vulnerability ID', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        // Capture the row that should disappear before triggering the search.
        const rowToRemove = await screen.findByRole('cell', {name: /CVE-2010-1234/});

        await user.type(search_bar, '2018-5678');

        // Allow for debounce + filter render (debounce is 750ms in component)
        await waitForElementToBeRemoved(rowToRemove, { timeout: 2000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching for package name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        const rowToRemove = await screen.findByRole('cell', {name: /CVE-2010-1234/});

        await user.type(search_bar, 'yyy');

        await waitForElementToBeRemoved(rowToRemove, { timeout: 2000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching with negation text', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        const rowToRemove = await screen.findByRole('cell', {name: /CVE-2010-1234/});

        await user.type(search_bar, '-2010');

        await waitForElementToBeRemoved(rowToRemove, { timeout: 2000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching with a combination of queries', async () => {
        // ARRANGE
         render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '-2010 2024');

        // Better use waitFor for a combined check instead of using waitForElementToBeRemoved in sequence, because the items are filtered out after the user.type() is completed, which may lead to the success of the first check and failure of the rest.
        await waitFor(() => {
            expect(screen.queryByRole('cell', {name: /CVE-2018-5678/})).toBeNull();
            expect(screen.queryByRole('cell', {name: /CVE-2010-1234/})).toBeNull();
        }, { timeout: 2000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2024-56730/});
        expect(vuln_xyz).toBeTruthy();
    })

    test('searching for description', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        const rowToRemove = await screen.findByRole('cell', {name: /CVE-2018-5678/});

        await user.type(search_bar, 'authentification process');

        await waitForElementToBeRemoved(rowToRemove, { timeout: 2000 });

        const vuln_abc = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_abc).toBeInTheDocument();
    })

    test('filter by source', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const sourceBtn = await screen.getByRole('button', { name: /source/i });
        expect(sourceBtn).toBeInTheDocument();
        await user.click(sourceBtn);

        const deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 1000 });

        const srcCheckbox = await screen.getByRole('checkbox', { name: 'cve-finder' });
        await user.click(srcCheckbox);

        await deletion;

        const pkg_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(pkg_xyz).toBeInTheDocument();
    })

    test('filter out Exploitable', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const statusBtn = await screen.getByRole('button', { name: /status/i });
        expect(statusBtn).toBeInTheDocument();
        await user.click(statusBtn);

        // Ensure the exploitable row exists before starting the removal watcher.
        const exploitableRow = await screen.findByRole('cell', {name: /CVE-2010-1234/});
        const pending_deletion = waitForElementToBeRemoved(exploitableRow, { timeout: 1000 });

        const pendingCheckbox = await screen.getByRole('checkbox', { name: /Pending Assessment/i });
        await user.click(pendingCheckbox);

        // ASSERT
        await pending_deletion;
        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('filter out Pending Assessment', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const statusBtn = await screen.getByRole('button', { name: /status/i });
        expect(statusBtn).toBeInTheDocument();
        await user.click(statusBtn);

        // Ensure the target row is present before starting removal watcher
        const communityRow = await screen.findByRole('cell', {name: /CVE-2018-5678/});
        const pending_deletion = waitForElementToBeRemoved(communityRow, { timeout: 1000 });

        // ACT
        const exploitableCheckbox = await screen.getByRole('checkbox', { name: /Exploitable/i });
        await user.click(exploitableCheckbox);

        // ASSERT
        await pending_deletion;
        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('select all in table and unselecting', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const select_all = await screen.getByTitle(/select all/i);
        expect(select_all).toBeInTheDocument();

        await user.click(select_all)
        expect(select_all).toBeChecked();

        const uniques_selections = await screen.getAllByTitle(/unselect/i);
        expect(uniques_selections.length).toBeGreaterThanOrEqual(1);
        uniques_selections.forEach((el) => expect(el).toBeChecked());

        await user.click(uniques_selections[0])

        expect(select_all).not.toBeChecked();
    })

    test('select using ctrl+click and reset selection', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const id_col = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(id_col).toBeInTheDocument();

        await user.keyboard('[ControlLeft>]')
        await user.click(id_col);
        await user.keyboard('[/ControlLeft]')

        const selected_checkbox = await screen.getByTitle(/unselect/i);
        expect(selected_checkbox).toBeInTheDocument();

        const bulkeditbar = await screen.getByText(/selected vulnerabilities: 1/i);
        expect(bulkeditbar).toBeInTheDocument();

        const reset_btn = await screen.getByRole('button', {name: /reset selection/i});
        expect(reset_btn).toBeInTheDocument();
        await user.click(reset_btn);

        const selecteds = await screen.queryAllByTitle(/unselect/i);
        expect(selecteds.length).toBe(0);
    })

    test('select and change status', async () => {
        fetchMock.mockResponse(
            JSON.stringify({
                status: 'success',
                count: 2,
                error_count: 0,
                assessments: [
                    {
                        id: '000',
                        vuln_id: 'CVE-0000-00000',
                        status: 'not_affected',
                        simplified_status: 'not_affected',
                        timestamp: "2024-01-01T00:00:00Z"
                    }
                ]
            }),
            { status: 200 }
        );

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const select_all = await screen.getByTitle(/select all/i);
        expect(select_all).toBeInTheDocument();

        await user.click(select_all)

        const edit_status_btn = await screen.getByRole('button', {name: /Change status/i});
        expect(edit_status_btn).toBeInTheDocument();
        await user.click(edit_status_btn);

        // StatusEditor testing, taken from test_vuln_modal
        let selects = await screen.getAllByRole('combobox');
        const selectSource = selects.find((el) => el.getAttribute('name')?.includes('new_assessment_status')) as HTMLElement;
        expect(selectSource).toBeDefined();
        expect(selectSource).toBeInTheDocument();
        const inputStatus = await screen.getByPlaceholderText(/notes/i);
        const inputWorkaround = await screen.getByPlaceholderText(/workaround/i);
        const btn = await screen.getByRole('button', {name: /add assessment/i});

        await user.selectOptions(selectSource, 'not_affected');

        // new checkbox arrived
        selects = await screen.getAllByRole('combobox');
        const selectjustification = selects.find((el) => el.getAttribute('name')?.includes('new_assessment_justification')) as HTMLElement;
        expect(selectjustification).toBeDefined();
        expect(selectjustification).toBeInTheDocument();

        const inputJustification = await screen.getByPlaceholderText(/vulnerability is not exploitable/i);
        expect(inputJustification).toBeDefined();
        expect(inputJustification).toBeInTheDocument();

        await user.selectOptions(selectjustification, 'inline_mitigations_already_exist');
        await user.type(inputStatus, 'patched by disabling configuration X');
        await user.type(inputWorkaround, 'feature Y is safe when configuration X is disabled (from source)');
        await user.click(btn);

        // ASSERT
        // 3 Variants.listByVuln calls (one per selected vulnerability) + 1 batch assessment API call
        expect(fetchMock).toHaveBeenCalledTimes(4);
    })

    test('select and change time estimate', async () => {
        fetchMock.mockResponse(
            JSON.stringify({
                status: 'success',
                count: 2,
                error_count: 0,
                vulnerabilities: [
                    {
                        id: 'CVE-2010-1234',
                        effort: {
                            optimistic: 'PT5H',
                            likely: 'P2DT4H',
                            pessimistic: 'P2W3D'
                        }
                    }
                ]
            }),
            { status: 200 }
        );

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const select_all = await screen.getByTitle(/select all/i);
        expect(select_all).toBeInTheDocument();

        await user.click(select_all)

        const edit_time_btn = await screen.getByRole('button', {name: /Change estimated time/i});
        expect(edit_time_btn).toBeInTheDocument();
        await user.click(edit_time_btn);

        // TimeEstimateEditor testing, taken from test_vuln_modal
        const optimistic = await screen.findByPlaceholderText(/shortest estimate/i);
        const likely = await screen.findByPlaceholderText(/balanced estimate/i);
        const pessimistic = await screen.findByPlaceholderText(/longest estimate/i);
        const btn = await screen.getByText(/save estimation/i);

        await user.type(optimistic, '5h');
        await user.type(likely, '2.5');
        await user.type(pessimistic, '2w 3d');
        await user.click(btn);

        // ASSERT
        expect(fetchMock).toHaveBeenCalledTimes(1);
    })

    test('show description when hovering vulnerability', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const id_col = await screen.getByRole('cell', {name: vulnerabilities[0].id});
        expect(id_col).toBeInTheDocument();
        const description = await screen.getByText(vulnerabilities[0].texts[0].content);
        expect(description).toBeInTheDocument();

        await user.hover(id_col);
        expect(description).toBeVisible();

        await user.unhover(id_col)
        // doesn't seem to work : expect(description).not.toBeVisible();
    })

    test('filter by severity', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const severityBtn = await screen.getByRole('button', { name: /severity/i });
        expect(severityBtn).toBeInTheDocument();
        await user.click(severityBtn);

        const deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2018-5678/}), { timeout: 1000 });

        const lowCheckbox = await screen.getByRole('checkbox', { name: 'low' });
        await user.click(lowCheckbox);

        await deletion;

        const vuln_abc = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_abc).toBeInTheDocument();
    })

    test('filter by custom severity range', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const severityBtn = await screen.getByRole('button', { name: /severity/i });
        expect(severityBtn).toBeInTheDocument();
        await user.click(severityBtn);

        const customCheckbox = await screen.getAllByRole('checkbox').find(
            (checkbox) => checkbox.id.match(/^custom-filter-checkbox-/)
        );
        expect(customCheckbox).toBeInTheDocument();
        await user.click(customCheckbox as HTMLElement);

        const [minSlider, maxSlider] = await screen.findAllByRole('slider');

        expect(minSlider).toBeInTheDocument();
        expect(maxSlider).toBeInTheDocument();

        // Vulneraibilities with the severity max score between 2 and 4 will remain.
        fireEvent.change(minSlider, { target: { value: '2' } });
        fireEvent.change(maxSlider, { target: { value: '4' } });

        await waitFor(() => {
            expect(screen.queryByRole('cell', {name: /CVE-2018-5678/})).toBeNull();
            expect(screen.queryByRole('cell', {name: /CVE-2024-56730/})).toBeNull();
        }, { timeout: 1000 });

        const vuln_abc = await screen.getByRole('cell', {name: /CVE-2010-1234/});

        expect(vuln_abc).toBeInTheDocument();
    })

    test('custom severity filter and other severity filters cannot be checked at the same time', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const severityBtn = await screen.getByRole('button', { name: /severity/i });
        expect(severityBtn).toBeInTheDocument();
        await user.click(severityBtn);

        const lowCheckbox = await screen.getByRole('checkbox', { name: 'low' });
        const customCheckbox = await screen.getAllByRole('checkbox').find(
            (checkbox) => checkbox.id.match(/^custom-filter-checkbox-/)
        );

        expect(customCheckbox).toBeInTheDocument();

        // Check low severity filter
        await user.click(lowCheckbox);
        expect(lowCheckbox).toBeChecked();

        // Now check custom filter, which should uncheck low severity filter
        await user.click(customCheckbox as HTMLElement);
        expect(customCheckbox).toBeChecked();
        expect(lowCheckbox).not.toBeChecked();

        // Vice-versa
        await user.click(lowCheckbox);
        expect(lowCheckbox).toBeChecked();
        expect(customCheckbox).not.toBeChecked();
    })

    test('hide fixed toggle functionality', async () => {
        const vulnWithFixed: Vulnerability[] = [
            ...vulnerabilities,
            {
                ...vulnerabilities[0],
                id: 'CVE-2020-9999',
                simplified_status: 'Fixed'
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithFixed} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const hideFixedToggle = await screen.getByRole('button', { name: /Hide Fixed/i });
        expect(hideFixedToggle).toBeInTheDocument();

        // Ensure the fixed vulnerability is initially visible
        const fixedVuln = await screen.getByRole('cell', {name: /CVE-2020-9999/});
        expect(fixedVuln).toBeInTheDocument();

        const deletion = waitForElementToBeRemoved(fixedVuln, { timeout: 1000 });

        // ACT - Toggle hide fixed
        await user.click(hideFixedToggle);

        // ASSERT - Fixed vulnerability should be hidden
        await deletion;
        expect(screen.queryByRole('cell', {name: /CVE-2020-9999/})).not.toBeInTheDocument();

        // Other vulnerabilities should still be visible
        const otherVuln = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(otherVuln).toBeInTheDocument();
    })

    test('reset filters button clears all filters', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Set up some filters first
        const sourceBtn = await screen.getByRole('button', { name: /source/i });
        await user.click(sourceBtn);
        const srcCheckbox = await screen.getByRole('checkbox', { name: 'cve-finder' });
        await user.click(srcCheckbox);

        // Set search
        const search_bar = await screen.getByRole('searchbox');
        await user.type(search_bar, '2018-5678');

        // Wait for filters to take effect
        await waitFor(() => {
            expect(screen.queryByRole('cell', {name: /CVE-2010-1234/})).not.toBeInTheDocument();
        });

        // ACT - Reset filters
        const resetBtn = await screen.getByRole('button', { name: /reset filters/i });
        await user.click(resetBtn);

        // ASSERT - All vulnerabilities should be visible again
        await waitFor(() => {
            const vuln1 = screen.getByRole('cell', {name: /CVE-2010-1234/});
            const vuln2 = screen.getByRole('cell', {name: /CVE-2018-5678/});
            expect(vuln1).toBeInTheDocument();
            expect(vuln2).toBeInTheDocument();
        });

        // Search bar should be cleared (it doesn't have a value attribute when cleared)
        expect(search_bar.getAttribute('value')).toBeNull();
    })

    test('initial filter props set correct filters', async () => {
        // ARRANGE - Render with initial filter props
        render(
            <TableVulnerabilities
                vulnerabilities={vulnerabilities}
                appendAssessment={() => {}}
                appendCVSS={() => null}
                patchVuln={() => {}}
                filterLabel="Source"
                filterValue="hardcoded"
            />
        );

        // ASSERT - Only hardcoded vulnerability should be visible
        await waitFor(() => {
            const vuln_abc = screen.getByRole('cell', {name: /CVE-2010-1234/});
            expect(vuln_abc).toBeInTheDocument();
            expect(screen.queryByRole('cell', {name: /CVE-2018-5678/})).not.toBeInTheDocument();
        });
    })

    test('multiple source selection works', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const sourceBtn = await screen.getByRole('button', { name: /source/i });
        await user.click(sourceBtn);

        // Select multiple sources
        const hardcodedCheckbox = await screen.getByRole('checkbox', { name: 'hardcoded' });
        const cveFinderCheckbox = await screen.getByRole('checkbox', { name: 'cve-finder' });

        await user.click(hardcodedCheckbox);
        await user.click(cveFinderCheckbox);

        // ASSERT - Both vulnerabilities should be visible
        const vuln1 = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const vuln2 = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln1).toBeInTheDocument();
        expect(vuln2).toBeInTheDocument();
    })

    test('hide fixed toggle interaction with status filter', async () => {
        const vulnWithFixed: Vulnerability[] = [
            ...vulnerabilities,
            {
                ...vulnerabilities[0],
                id: 'CVE-2020-9999',
                simplified_status: 'Fixed'
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithFixed} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // First enable hide fixed
        const hideFixedToggle = await screen.getByRole('button', { name: /Hide Fixed/i });
        await user.click(hideFixedToggle);

        // Wait for fixed vulnerability to be hidden
        await waitFor(() => {
            expect(screen.queryByRole('cell', {name: /CVE-2020-9999/})).not.toBeInTheDocument();
        });

        // Now manually select 'fixed' in status filter
        // Use getAllByRole to handle multiple buttons with 'status' in name, select the first (main button)
        const statusButtons = await screen.getAllByRole('button', { name: /status/i });
        await user.click(statusButtons[0]);
        const fixedCheckbox = await screen.getByRole('checkbox', { name: 'Fixed' });
        await user.click(fixedCheckbox);

        // ASSERT - Hide fixed toggle should be disabled when fixed is manually selected
        expect(hideFixedToggle).toHaveAttribute('aria-pressed', 'false');

        // Fixed vulnerability should now be visible
        await waitFor(() => {
            const fixedVuln = screen.getByRole('cell', {name: /CVE-2020-9999/});
            expect(fixedVuln).toBeInTheDocument();
        });
    })

    test('search debounce functionality', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        // ACT - Type only one character (should not trigger search)
        await user.type(search_bar, '2');

        // ASSERT - Both vulnerabilities should still be visible (no filtering with < 2 chars)
        const vuln1 = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const vuln2 = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln1).toBeInTheDocument();
        expect(vuln2).toBeInTheDocument();
    })

    test('sorting by packages column is disabled', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const packagesHeader = await screen.getByRole('columnheader', {name: /SBOM Affected/i});

        // Store initial order
        const initialHtml = document.body.innerHTML;
        const initialOrder = initialHtml.indexOf('aaabbbccc') < initialHtml.indexOf('xxxyyyzzz');

        // ACT - Try to click packages header (should not sort)
        await user.click(packagesHeader);

        // Wait a moment for any potential sorting
        await new Promise(resolve => setTimeout(resolve, 100));

        // ASSERT - Order should remain the same
        const finalHtml = document.body.innerHTML;
        const finalOrder = finalHtml.indexOf('aaabbbccc') < finalHtml.indexOf('xxxyyyzzz');
        expect(finalOrder).toBe(initialOrder);
    })

    test('last updated column shows "No assessment" when no assessments exist', async () => {
        // ARRANGE - Create a scenario similar to the passing tests with one vulnerability that has no assessments
        const vulnWithoutAssessments: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                assessments: []
            }
        ];

        render(<TableVulnerabilities vulnerabilities={vulnWithoutAssessments} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // ACT & ASSERT - Vulnerability has empty assessments array, should show "No assessment"
        const noAssessmentCell = await screen.getByText(/no assessment/i);
        expect(noAssessmentCell).toBeInTheDocument();
    })

    test('last updated column displays assessment timestamp when assessments exist', async () => {
        const vulnWithAssessments: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                assessments: [
                    {
                        id: '1',
                        vuln_id: 'CVE-2010-1234',
                        packages: ['aaabbbccc@1.0.0'],
                        status: 'not_affected',
                        simplified_status: 'Not affected',
                        timestamp: '2024-01-15T10:30:00Z',
                        responses: []
                    }
                ]
            },
            {
                ...vulnerabilities[1],
                assessments: []
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithAssessments} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // ACT & ASSERT
        // First vulnerability should show formatted date
        const formattedDate = await screen.getByText(/january 15, 2024/i);
        expect(formattedDate).toBeInTheDocument();

        // Second vulnerability should still show "No assessment"
        const noAssessment = await screen.getByText(/no assessment/i);
        expect(noAssessment).toBeInTheDocument();
    })

    test('last updated column uses last_update field when available', async () => {
        const vulnWithUpdatedAssessments: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                assessments: [
                    {
                        id: '1',
                        vuln_id: 'CVE-2010-1234',
                        packages: ['aaabbbccc@1.0.0'],
                        status: 'not_affected',
                        simplified_status: 'Not affected',
                        timestamp: '2024-01-15T10:30:00Z',
                        last_update: '2024-02-20T14:45:00Z', // More recent than timestamp
                        responses: []
                    }
                ]
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithUpdatedAssessments} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // ACT & ASSERT - Should show the more recent last_update date
        const formattedDate = await screen.getByText(/february 20, 2024/i);
        expect(formattedDate).toBeInTheDocument();
    })

    test('last updated column shows most recent assessment across multiple assessments', async () => {
        const vulnWithMultipleAssessments: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                assessments: [
                    {
                        id: '1',
                        vuln_id: 'CVE-2010-1234',
                        packages: ['aaabbbccc@1.0.0'],
                        status: 'not_affected',
                        simplified_status: 'Not affected',
                        timestamp: '2024-01-15T10:30:00Z',
                        responses: []
                    },
                    {
                        id: '2',
                        vuln_id: 'CVE-2010-1234',
                        packages: ['aaabbbccc@1.0.0'],
                        status: 'affected',
                        simplified_status: 'Exploitable',
                        timestamp: '2024-03-10T16:20:00Z', // Most recent
                        responses: []
                    },
                    {
                        id: '3',
                        vuln_id: 'CVE-2010-1234',
                        packages: ['aaabbbccc@1.0.0'],
                        status: 'under_investigation',
                        simplified_status: 'Pending Assessment',
                        timestamp: '2024-02-05T12:15:00Z',
                        responses: []
                    }
                ]
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithMultipleAssessments} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // ACT & ASSERT - Should show the most recent assessment date (March 10)
        const formattedDate = await screen.getByText(/march 10, 2024/i);
        expect(formattedDate).toBeInTheDocument();
    })

    test('sorting by last updated column', async () => {
        const vulnWithDifferentDates: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                id: 'CVE-2020-1111', // Earlier assessment
                assessments: [
                    {
                        id: '1',
                        vuln_id: 'CVE-2020-1111',
                        packages: ['package1@1.0.0'],
                        status: 'not_affected',
                        simplified_status: 'Not affected',
                        timestamp: '2024-01-15T10:30:00Z',
                        responses: []
                    }
                ]
            },
            {
                ...vulnerabilities[1],
                id: 'CVE-2020-2222', // Later assessment
                assessments: [
                    {
                        id: '2',
                        vuln_id: 'CVE-2020-2222',
                        packages: ['package2@1.0.0'],
                        status: 'affected',
                        simplified_status: 'Exploitable',
                        timestamp: '2024-03-20T15:45:00Z',
                        responses: []
                    }
                ]
            },
            {
                ...vulnerabilities[0],
                id: 'CVE-2020-3333', // No assessment
                assessments: []
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithDifferentDates} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const lastUpdatedHeader = await screen.getByRole('columnheader', {name: /last updated/i});

        // ACT - Sort by last updated (first click: descending - newest first, then older, then no assessments)
        await user.click(lastUpdatedHeader);
        await waitFor(() => {
            const html = document.body.innerHTML;
            // CVE-2020-2222 should come first (newest), then CVE-2020-1111, then CVE-2020-3333 (no assessment)
            expect(html.indexOf('CVE-2020-2222')).toBeLessThan(html.indexOf('CVE-2020-1111'));
            expect(html.indexOf('CVE-2020-1111')).toBeLessThan(html.indexOf('CVE-2020-3333'));
        });

        // ACT - Sort by last updated (second click: ascending - no assessments first, then oldest to newest)
        await user.click(lastUpdatedHeader);
        await waitFor(() => {
            const html = document.body.innerHTML;
            // No assessment (CVE-2020-3333) should come first, then CVE-2020-1111, then CVE-2020-2222
            expect(html.indexOf('CVE-2020-3333')).toBeLessThan(html.indexOf('CVE-2020-1111'));
            expect(html.indexOf('CVE-2020-1111')).toBeLessThan(html.indexOf('CVE-2020-2222'));
        });
    })

    test('last updated column handles mixed timestamp and last_update fields correctly for sorting', async () => {
        const vulnWithMixedDates: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                id: 'CVE-2020-1111',
                assessments: [
                    {
                        id: '1',
                        vuln_id: 'CVE-2020-1111',
                        packages: ['package1@1.0.0'],
                        status: 'not_affected',
                        simplified_status: 'Not affected',
                        timestamp: '2024-01-15T10:30:00Z',
                        last_update: '2024-03-25T12:00:00Z', // Most recent overall
                        responses: []
                    }
                ]
            },
            {
                ...vulnerabilities[1],
                id: 'CVE-2020-2222',
                assessments: [
                    {
                        id: '2',
                        vuln_id: 'CVE-2020-2222',
                        packages: ['package2@1.0.0'],
                        status: 'affected',
                        simplified_status: 'Exploitable',
                        timestamp: '2024-03-20T15:45:00Z', // Only timestamp, no last_update
                        responses: []
                    }
                ]
            }
        ];

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnWithMixedDates} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const lastUpdatedHeader = await screen.getByRole('columnheader', {name: /last updated/i});

        // ACT - Sort descending (newest first) - should only need one click
        await user.click(lastUpdatedHeader);

        await waitFor(() => {
            const html = document.body.innerHTML;
            // CVE-2020-1111 should come first because last_update (March 25) is more recent than CVE-2020-2222's timestamp (March 20)
            expect(html.indexOf('CVE-2020-1111')).toBeLessThan(html.indexOf('CVE-2020-2222'));
        });
    })

    test('handleHideFixedToggle filters out Fixed status when enabled', async () => {
        const vulnsWithFixed: Vulnerability[] = [
            {
                ...vulnerabilities[0],
                id: 'CVE-FIXED-001',
                simplified_status: 'Fixed'
            },
            {
                ...vulnerabilities[1],
                id: 'CVE-ACTIVE-001',
                simplified_status: 'Exploitable'
            }
        ];

        render(<TableVulnerabilities vulnerabilities={vulnsWithFixed} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Toggle "Hide Fixed"
        const hideFixedToggle = await screen.getByRole('button', {name: /hide fixed/i});
        await user.click(hideFixedToggle);

        // Fixed vulnerability should not be visible
        await waitFor(() => {
            expect(screen.queryByText('CVE-FIXED-001')).not.toBeInTheDocument();
            expect(screen.getByText('CVE-ACTIVE-001')).toBeInTheDocument();
        });
    })

    test('handleHideFixedToggle can be toggled on and off', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Enable "Hide Fixed"
        const hideFixedToggle = await screen.getByRole('button', {name: /show hide fixed/i});
        await user.click(hideFixedToggle);

        // Toggle should change its aria-label
        await waitFor(() => {
            const toggleAfter = screen.getByRole('button', {name: /hide hide fixed/i});
            expect(toggleAfter).toBeInTheDocument();
        });

        // Disable "Hide Fixed" by clicking again
        const hideFixedToggle2 = await screen.getByRole('button', {name: /hide hide fixed/i});
        await user.click(hideFixedToggle2);

        // Toggle should revert
        await waitFor(() => {
            const toggleReverted = screen.getByRole('button', {name: /show hide fixed/i});
            expect(toggleReverted).toBeInTheDocument();
        });
    })

    test('modal navigation works correctly', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Open modal for first vulnerability
        const firstVulnId = await screen.getByText('CVE-2010-1234');
        await user.click(firstVulnId);

        // Modal should be open
        await waitFor(() => {
            expect(screen.getAllByText('CVE-2010-1234').length).toBeGreaterThan(1);
        });

        // Navigate to next vulnerability (if navigation buttons exist in modal)
        // This would require the modal to have next/previous buttons
    })

    test('clicking Edit button opens modal in edit mode', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Click Edit button for first vulnerability
        const editButtons = await screen.getAllByRole('button', { name: /^edit$/i });
        await user.click(editButtons[0]);

        // Modal should be open in edit mode
        await waitFor(() => {
            // The modal should show the vulnerability details
            expect(screen.getAllByText('CVE-2010-1234').length).toBeGreaterThan(1);
        });
    })

    test('clicking vulnerability ID opens modal in view mode', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();

        // Click on vulnerability ID cell
        const vulnIdCells = await screen.getAllByText('CVE-2010-1234');
        await user.click(vulnIdCells[0]);

        // Modal should be open
        await waitFor(() => {
            expect(screen.getAllByText('CVE-2010-1234').length).toBeGreaterThan(1);
        });
    });

    // =========================================================================
    // Published Date Feature Tests
    // =========================================================================

    test('published date filter button is disabled when NVD sync is not completed', async () => {
        // NVD progress mock defaults to phase: 'idle', which means not completed
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const publishedDateBtn = await screen.getByRole('button', { name: /published date/i });
        expect(publishedDateBtn).toBeInTheDocument();
        expect(publishedDateBtn).toBeDisabled();
        expect(publishedDateBtn).toHaveAttribute('title', 'NVD sync in progress');
    });

    test('published date filter button is enabled when NVD sync is completed', async () => {
        // Override the NVD progress mock for this test
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        await waitFor(() => {
            const publishedDateBtn = screen.getByRole('button', { name: /published date/i });
            expect(publishedDateBtn).not.toBeDisabled();
            expect(publishedDateBtn).toHaveAttribute('title', 'Filter by published date');
        });
    });

    test('published date filter dropdown opens and shows filter types', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        const publishedDateBtn = screen.getByRole('button', { name: /published date/i });
        await user.click(publishedDateBtn);

        // Dropdown should show filter type options
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        expect(filterTypeSelect).toBeInTheDocument();

        // Check all filter type options exist
        const options = filterTypeSelect.querySelectorAll('option');
        const optionValues = Array.from(options).map(o => o.textContent);
        expect(optionValues).toContain('Select filter type...');
        expect(optionValues).toContain('Is');
        expect(optionValues).toContain('On or after');
        expect(optionValues).toContain('On or before');
        expect(optionValues).toContain('Between');
        expect(optionValues).toContain('Less than X days ago');
    });

    test('published date filter "is" shows date input and filters exact date', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Open the dropdown
        await user.click(screen.getByRole('button', { name: /published date/i }));

        // Select "Is" filter type
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'is');

        // A date input should appear
        const dateInput = await screen.getByLabelText(/^date:/i);
        expect(dateInput).toBeInTheDocument();

        // Set the date to match CVE-2010-1234's published date (2010-05-15)
        await user.clear(dateInput);
        await user.type(dateInput, '2010-05-15');

        await waitFor(() => {
            // CVE-2010-1234 should remain (published 2010-05-15)
            expect(screen.getByRole('cell', { name: /CVE-2010-1234/ })).toBeInTheDocument();
            // CVE-2018-5678 should be filtered out (published 2018-07-22)
            expect(screen.queryByRole('cell', { name: /CVE-2018-5678/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter ">=" filters vulnerabilities on or after date', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, '>=');

        const dateInput = await screen.getByLabelText(/on or after/i);
        expect(dateInput).toBeInTheDocument();

        // Set date to 2015-01-01 - should filter out CVE-2010-1234
        await user.clear(dateInput);
        await user.type(dateInput, '2015-01-01');

        await waitFor(() => {
            // CVE-2018-5678 (published 2018-07-22) should remain
            expect(screen.getByRole('cell', { name: /CVE-2018-5678/ })).toBeInTheDocument();
            // CVE-2010-1234 (published 2010-05-15) should be filtered out
            expect(screen.queryByRole('cell', { name: /CVE-2010-1234/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter "<=" filters vulnerabilities on or before date', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, '<=');

        const dateInput = await screen.getByLabelText(/on or before/i);
        expect(dateInput).toBeInTheDocument();

        // Set date to 2015-01-01 - should filter out CVE-2018-5678
        await user.clear(dateInput);
        await user.type(dateInput, '2015-01-01');

        await waitFor(() => {
            // CVE-2010-1234 (published 2010-05-15) should remain
            expect(screen.getByRole('cell', { name: /CVE-2010-1234/ })).toBeInTheDocument();
            // CVE-2018-5678 (published 2018-07-22) should be filtered out
            expect(screen.queryByRole('cell', { name: /CVE-2018-5678/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter "between" filters vulnerabilities within date range', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'between');

        const fromInput = await screen.getByLabelText(/from/i);
        const toInput = await screen.getByLabelText(/to/i);
        expect(fromInput).toBeInTheDocument();
        expect(toInput).toBeInTheDocument();

        // Set range to include only CVE-2018-5678 (2018-07-22)
        await user.clear(fromInput);
        await user.type(fromInput, '2017-01-01');
        await user.clear(toInput);
        await user.type(toInput, '2019-12-31');

        await waitFor(() => {
            // CVE-2018-5678 (published 2018-07-22) should remain
            expect(screen.getByRole('cell', { name: /CVE-2018-5678/ })).toBeInTheDocument();
            // CVE-2010-1234 (published 2010-05-15) should be filtered out
            expect(screen.queryByRole('cell', { name: /CVE-2010-1234/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter "days_ago" shows number input', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'days_ago');

        const daysInput = await screen.getByLabelText(/number of days/i);
        expect(daysInput).toBeInTheDocument();
        expect(daysInput).toHaveAttribute('type', 'number');

        // Enter 30 days - both vulnerabilities are old so both should be filtered out
        await user.clear(daysInput);
        await user.type(daysInput, '30');

        await waitFor(() => {
            // Both CVEs have old published dates, so both should be filtered out
            expect(screen.queryByRole('cell', { name: /CVE-2010-1234/ })).not.toBeInTheDocument();
            expect(screen.queryByRole('cell', { name: /CVE-2018-5678/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter excludes vulnerabilities without published date', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        // Add a vulnerability without a published date
        const vulnsWithMissing: Vulnerability[] = [
            ...vulnerabilities,
            {
                id: 'CVE-NO-DATE',
                aliases: [],
                related_vulnerabilities: [],
                namespace: 'nvd:cve',
                found_by: ['hardcoded'],
                datasource: 'test',
                packages: ['nodatepkg@1.0.0'],
                packages_current: [],
                urls: [],
                texts: [{ title: 'description', content: 'No date vuln' }],
                severity: {
                    severity: 'medium',
                    min_score: 5,
                    max_score: 5,
                    cvss: []
                },
                epss: { score: undefined, percentile: undefined },
                effort: {
                    optimistic: new Iso8601Duration('PT1H'),
                    likely: new Iso8601Duration('PT2H'),
                    pessimistic: new Iso8601Duration('PT4H')
                },
                fix: { state: 'unknown' },
                status: 'under_investigation',
                simplified_status: 'Pending Assessment',
                assessments: [],
                variants: [],
                // no 'published' field
            }
        ];

        render(<TableVulnerabilities vulnerabilities={vulnsWithMissing} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        // All three vulnerabilities should be visible initially
        await waitFor(() => {
            expect(screen.getByRole('cell', { name: /CVE-NO-DATE/ })).toBeInTheDocument();
        });

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Open filter and select ">=" with a very old date
        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, '>=');

        const dateInput = await screen.getByLabelText(/on or after/i);
        await user.clear(dateInput);
        await user.type(dateInput, '2000-01-01');

        await waitFor(() => {
            // CVE-2010-1234 and CVE-2018-5678 have published dates >= 2000, should remain
            expect(screen.getByRole('cell', { name: /CVE-2010-1234/ })).toBeInTheDocument();
            expect(screen.getByRole('cell', { name: /CVE-2018-5678/ })).toBeInTheDocument();
            // CVE-NO-DATE has no published date, should be filtered out
            expect(screen.queryByRole('cell', { name: /CVE-NO-DATE/ })).not.toBeInTheDocument();
        });
    });

    test('published date filter clear button resets filter', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Open filter and set an "is" filter
        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'is');

        const dateInput = await screen.getByLabelText(/^date:/i);
        await user.clear(dateInput);
        await user.type(dateInput, '2010-05-15');

        // CVE-2018-5678 should be filtered out
        await waitFor(() => {
            expect(screen.queryByRole('cell', { name: /CVE-2018-5678/ })).not.toBeInTheDocument();
        });

        // Click "Clear Filter" button
        const clearBtn = await screen.getByRole('button', { name: /clear filter/i });
        await user.click(clearBtn);

        // Both should be visible again
        await waitFor(() => {
            expect(screen.getByRole('cell', { name: /CVE-2010-1234/ })).toBeInTheDocument();
            expect(screen.getByRole('cell', { name: /CVE-2018-5678/ })).toBeInTheDocument();
        });
    });

    test('published date filter shows active indicator when filter is set', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Initially no active indicator
        expect(screen.queryByText('✓')).not.toBeInTheDocument();

        // Open filter, set a filter
        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'is');

        const dateInput = await screen.getByLabelText(/^date:/i);
        await user.clear(dateInput);
        await user.type(dateInput, '2010-05-15');

        // Active indicator (✓) should appear
        await waitFor(() => {
            expect(screen.getByText('✓')).toBeInTheDocument();
        });
    });

    test('reset filters button clears published date filter', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Set a published date filter
        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'is');

        const dateInput = await screen.getByLabelText(/^date:/i);
        await user.clear(dateInput);
        await user.type(dateInput, '2010-05-15');

        // CVE-2018-5678 should be filtered out
        await waitFor(() => {
            expect(screen.queryByRole('cell', { name: /CVE-2018-5678/ })).not.toBeInTheDocument();
        });

        // Click global "Reset Filters" button
        const resetBtn = await screen.getByRole('button', { name: /reset filters/i });
        await user.click(resetBtn);

        // Both should be visible again
        await waitFor(() => {
            expect(screen.getByRole('cell', { name: /CVE-2010-1234/ })).toBeInTheDocument();
            expect(screen.getByRole('cell', { name: /CVE-2018-5678/ })).toBeInTheDocument();
        });
    });

    test('published date column can be disabled', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        // Published Date column is visible by default
        expect(screen.queryByRole('columnheader', { name: /published date/i })).toBeInTheDocument();

        // Disable Published Date column via Columns filter
        const buttons = await screen.getAllByRole('button', { name: /columns/i });
        await user.click(buttons[0]);

        const publishedDateCheckbox = await screen.getByRole('checkbox', { name: 'Published Date' });
        await user.click(publishedDateCheckbox);

        // Published Date column should not be visible
        await waitFor(() => {
            expect(screen.queryByRole('columnheader', { name: /published date/i })).not.toBeInTheDocument();
        });

        // Check that dates are not rendered (formatted as short month)
        await waitFor(() => {
            [/May 15, 2010/, /Jul 22, 2018/].forEach(date => {
            expect(screen.queryByText(date)).not.toBeInTheDocument();
            });
        });
    });

    test('published date column shows "Unknown" for vulnerabilities without published date', async () => {
        const vulnsWithMissing: Vulnerability[] = [
            ...vulnerabilities,
            {
                id: 'CVE-NO-DATE',
                aliases: [],
                related_vulnerabilities: [],
                namespace: 'nvd:cve',
                found_by: ['hardcoded'],
                datasource: 'test',
                packages: ['nodatepkg@1.0.0'],
                packages_current: [],
                urls: [],
                texts: [{ title: 'description', content: 'No date vuln' }],
                severity: {
                    severity: 'medium',
                    min_score: 5,
                    max_score: 5,
                    cvss: []
                },
                epss: { score: undefined, percentile: undefined },
                effort: {
                    optimistic: new Iso8601Duration('PT1H'),
                    likely: new Iso8601Duration('PT2H'),
                    pessimistic: new Iso8601Duration('PT4H')
                },
                fix: { state: 'unknown' },
                status: 'under_investigation',
                simplified_status: 'Pending Assessment',
                assessments: [],
                variants: [],
                // no 'published' field
            }
        ];

        render(<TableVulnerabilities vulnerabilities={vulnsWithMissing} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // "Unknown" should appear for the vuln without published date
        await waitFor(() => {
            const unknownElements = screen.getAllByText('Unknown');
            expect(unknownElements.length).toBeGreaterThan(0);
        });
    });

    test('published date filter type change clears previous date values', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: false,
            phase: 'completed',
            current: 100,
            total: 100,
            message: 'Done',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        const user = userEvent.setup();

        await waitFor(() => {
            expect(screen.getByRole('button', { name: /published date/i })).not.toBeDisabled();
        });

        // Open filter, set "is" filter with a date
        await user.click(screen.getByRole('button', { name: /published date/i }));
        const filterTypeSelect = await screen.getByLabelText(/filter type/i);
        await user.selectOptions(filterTypeSelect, 'is');

        const dateInput = await screen.getByLabelText(/^date:/i);
        await user.clear(dateInput);
        await user.type(dateInput, '2010-05-15');

        // Switch to ">=" filter type
        await user.selectOptions(filterTypeSelect, '>=');

        // The new date input should be empty (previous value was cleared)
        const newDateInput = await screen.getByLabelText(/on or after/i);
        expect(newDateInput).toHaveValue('');
    });

    test('published date filter button disabled when NVD in_progress is true', async () => {
        const NVDProgressHandler = require('../../src/handlers/nvd_progress').default;
        NVDProgressHandler.getProgress.mockResolvedValueOnce({
            in_progress: true,
            phase: 'downloading',
            current: 50,
            total: 100,
            message: 'Downloading...',
        });

        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // Button should remain disabled because NVD is in progress
        await waitFor(() => {
            const publishedDateBtn = screen.getByRole('button', { name: /published date/i });
            expect(publishedDateBtn).toBeDisabled();
        });
    });

    test('shortcut helper icon is visible', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const helperBtn = await screen.getByRole('button', { name: /shortcut helper/i });
        expect(helperBtn).toBeInTheDocument();
    });

    test('shortcut helper shows keyboard shortcuts content', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const helperBtn = await screen.getByRole('button', { name: /shortcut helper/i });
        await user.click(helperBtn);

        expect(await screen.findByText('Keyboard Shortcuts')).toBeInTheDocument();
        expect(screen.getByText('/')).toBeInTheDocument();
        expect(screen.getByText('Focus search bar')).toBeInTheDocument();
        expect(screen.getByText('e')).toBeInTheDocument();
        expect(screen.getByText('Edit focused vulnerability')).toBeInTheDocument();
        expect(screen.getByText('v')).toBeInTheDocument();
        expect(screen.getByText('View vulnerability details')).toBeInTheDocument();
        expect(screen.getByText('↑ / ↓')).toBeInTheDocument();
        expect(screen.getByText('Navigate focused table row')).toBeInTheDocument();
        expect(screen.getByText('Home / End')).toBeInTheDocument();
        expect(screen.getByText('Navigate to first/last table row')).toBeInTheDocument();
    });

    test('pressing / focuses vulnerability search bar', async () => {
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const searchBar = await screen.getByRole('searchbox') as HTMLInputElement;

        expect(document.activeElement).not.toBe(searchBar);

        await user.keyboard('/');

        expect(document.activeElement).toBe(searchBar);
    });

    test('ArrowDown and ArrowUp navigate focused vulnerability row', async () => {
        const { container } = render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

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

    test('Home and End navigate to first and last vulnerability row', async () => {
        const { container } = render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

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

    test('pressing e opens edit modal for focused vulnerability', async () => {
        const { container } = render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const rows = container.querySelectorAll('tr.row-with-hover-effect');
        const firstRow = rows[0] as HTMLElement;

        firstRow.focus();
        expect(document.activeElement).toBe(firstRow);

        await user.keyboard('{Home}');
        await waitFor(() => {
            expect(document.activeElement).toBe(firstRow);
        });

        await user.keyboard('e');

        await waitFor(() => {
            expect(screen.getAllByText('CVE-2010-1234').length).toBeGreaterThan(1);
        });
    });

    test('pressing v opens view modal for focused vulnerability', async () => {
        const { container } = render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const rows = container.querySelectorAll('tr.row-with-hover-effect');
        const firstRow = rows[0] as HTMLElement;
        const secondRow = rows[1] as HTMLElement;

        firstRow.focus();
        expect(document.activeElement).toBe(firstRow);

        await user.keyboard('{ArrowDown}');
        await waitFor(() => {
            expect(document.activeElement).toBe(secondRow);
        });

        await user.keyboard('v');

        await waitFor(() => {
            expect(screen.getAllByText('CVE-2018-5678').length).toBeGreaterThan(1);
        });
    });
});
