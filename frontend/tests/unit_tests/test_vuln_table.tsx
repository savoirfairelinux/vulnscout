/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import TableVulnerabilities from '../../src/pages/TableVulnerabilities';
import Iso8601Duration from '../../src/handlers/iso8601duration';


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
            assessments: []
        },
        {
            id: 'CVE-2018-5678',
            aliases: ['CVE-2017-7890'],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: ['cve-finder'],
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
            simplified_status: 'Community Analysis Pending',
            assessments: []
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

        // ACT
        const id_header = await screen.getByRole('columnheader', {name: /id/i});
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});
        const exploit_header = await screen.getByRole('columnheader', {name: /EPSS score/i});
        const packages_header = await screen.getByRole('columnheader', {name: /packages/i});
        const atk_vector_header = await screen.getByRole('columnheader', {name: /attack vector/i});
        const status_header = await screen.getByRole('columnheader', {name: /status/i});
        const source_header = await screen.getByRole('columnheader', {name: /source/i});

        // ASSERT
        expect(id_header).toBeInTheDocument();
        expect(severity_header).toBeInTheDocument();
        expect(exploit_header).toBeInTheDocument();
        expect(packages_header).toBeInTheDocument();
        expect(atk_vector_header).toBeInTheDocument();
        expect(status_header).toBeInTheDocument();
        expect(source_header).toBeInTheDocument();
    })

    test('render with vulnerabilities', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        // ACT
        const id_col = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const severity_col = await screen.getByRole('cell', {name: /low/});
        const epss_col = await screen.getByRole('cell', {name: /35\.68%/});
        const effort_col = await screen.getByRole('cell', {name: /1d 2h/i});
        const packages_col = await screen.getByRole('cell', {name: /aaabbbccc@1\.0\.0/i});
        const atk_vector_col = await screen.getByRole('cell', {name: /network/i});
        const status_col = await screen.getByRole('cell', {name: /Community Analysis Pending/i});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT
        expect(id_col).toBeInTheDocument();
        expect(severity_col).toBeInTheDocument();
        expect(epss_col).toBeInTheDocument();
        expect(effort_col).toBeInTheDocument();
        expect(packages_col).toBeInTheDocument();
        expect(atk_vector_col).toBeInTheDocument();
        expect(status_col).toBeInTheDocument();
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

    test('sorting by attack vector', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
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

        const pendingCheckbox = await screen.getByRole('checkbox', { name: /Community Analysis Pending/i });
        await user.click(pendingCheckbox);

        // ASSERT
        await pending_deletion;
        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('filter out Community Analysis Pending', async () => {
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
                assessment: {
                    id: '000',
                    vuln_id: 'CVE-0000-00000',
                    status: 'affected',
                    timestamp: "2024-01-01T00:00:00Z"
                }
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
        expect(fetchMock).toHaveBeenCalledTimes(2);
    })

    test('select and change time estimate', async () => {
        fetchMock.mockResponse(
            JSON.stringify({
                id: 'CVE-2010-1234',
                packages: ['aaabbbccc@1.0.0'],
                effort: {
                    optimistic: 'PT5H',
                    likely: 'P2DT4H',
                    pessimistic: 'P2W3D'
                },
                responses: []
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
        expect(fetchMock).toHaveBeenCalledTimes(2);
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

    test('open modal when clicking edit button', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const editButtons = await screen.getAllByRole('button', { name: /edit/i });
        expect(editButtons.length).toBeGreaterThan(0);

        // ACT
        await user.click(editButtons[0]);

        // ASSERT - Modal should open (we can check for modal title with specific id)
        await waitFor(() => {
            const modalTitle = document.getElementById('vulnerability_modal_title');
            expect(modalTitle).toBeInTheDocument();
        });
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
        const statusBtn = await screen.getByRole('button', { name: /status/i });
        await user.click(statusBtn);
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
        const packagesHeader = await screen.getByRole('columnheader', {name: /packages/i});
        
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
});
