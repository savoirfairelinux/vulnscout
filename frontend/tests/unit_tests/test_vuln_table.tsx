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

        const user = userEvent.setup();

        // ACT - Check for default visible columns
        const id_header = await screen.getByRole('columnheader', {name: /id/i});
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});
        const exploit_header = await screen.getByRole('columnheader', {name: /EPSS score/i});
        const packages_header = await screen.getByRole('columnheader', {name: /packages/i});
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
        const columnsBtn = await screen.getByRole('button', { name: /columns/i });
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
        const status_col = await screen.getByRole('cell', {name: /Community Analysis Pending/i});

        // ASSERT - Default visible columns
        expect(id_col).toBeInTheDocument();
        expect(severity_col).toBeInTheDocument();
        expect(epss_col).toBeInTheDocument();
        expect(packages_col).toBeInTheDocument();
        expect(status_col).toBeInTheDocument();

        // Now enable hidden columns to test their content
        const columnsBtn = await screen.getByRole('button', { name: /columns/i });
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
        
        // First, enable the Attack Vector column
        const columnsBtn = await screen.getByRole('button', { name: /columns/i });
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
        const columnsBtn = await screen.getByRole('button', { name: /columns/i });
        await user.click(columnsBtn);
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
                        simplified_status: 'Community analysis pending',
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
});
