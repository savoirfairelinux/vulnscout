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


describe('Packages Table', () => {

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
                cvss: []
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
            simplified_status: 'active',
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
                cvss: []
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
            simplified_status: 'pending analysis',
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
        render(<TableVulnerabilities vulnerabilities={[]} appendAssessment={() => {}} patchVuln={() => {}} />);

        // ACT
        const id_header = await screen.getByRole('columnheader', {name: /id/i});
        const severity_header = await screen.getByRole('columnheader', {name: /severity/i});
        const exploit_header = await screen.getByRole('columnheader', {name: /exploitability/i});
        const packages_header = await screen.getByRole('columnheader', {name: /packages/i});
        const status_header = await screen.getByRole('columnheader', {name: /status/i});
        const source_header = await screen.getByRole('columnheader', {name: /source/i});

        // ASSERT
        expect(id_header).toBeInTheDocument();
        expect(severity_header).toBeInTheDocument();
        expect(exploit_header).toBeInTheDocument();
        expect(packages_header).toBeInTheDocument();
        expect(status_header).toBeInTheDocument();
        expect(source_header).toBeInTheDocument();
    })

    test('render with vulnerabilities', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        // ACT
        const id_col = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        const severity_col = await screen.getByRole('cell', {name: /low/});
        const epss_col = await screen.getByRole('cell', {name: /3[56][ ]?\%/});
        const effort_col = await screen.getByRole('cell', {name: /1d 2h/i});
        const packages_col = await screen.getByRole('cell', {name: /aaabbbccc@1\.0\.0/i});
        const status_col = await screen.getByRole('cell', {name: /pending analysis/i});
        const source_col = await screen.getByRole('cell', {name: /hardcoded/});

        // ASSERT
        expect(id_col).toBeInTheDocument();
        expect(severity_col).toBeInTheDocument();
        expect(epss_col).toBeInTheDocument();
        expect(effort_col).toBeInTheDocument();
        expect(packages_col).toBeInTheDocument();
        expect(status_col).toBeInTheDocument();
        expect(source_col).toBeInTheDocument();
    })

    test('sorting by name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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

    test('sorting by exploitability score', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const exploit_header = await screen.getByRole('columnheader', {name: /exploitability/i});

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '\'2018-5678');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 1000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching for package name', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, 'yyy');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 1000 });

        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('searching for description', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');

        await user.type(search_bar, '\'authentification process');

        await waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2018-5678/}), { timeout: 1000 });

        const vuln_abc = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_abc).toBeInTheDocument();
    })

    test('filter by source', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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

    test('filter out active', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const hide_active = await screen.getByRole('checkbox', {name: /hide active/i});
        const pending_deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2010-1234/}), { timeout: 500 });

        // ACT
        await user.click(hide_active);

        // ASSERT
        await pending_deletion;
        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2018-5678/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('filter out pending analysis', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const hide_pending = await screen.getByRole('checkbox', {name: /hide pending/i});
        const pending_deletion = waitForElementToBeRemoved(() => screen.getByRole('cell', {name: /CVE-2018-5678/}), { timeout: 500 });

        // ACT
        await user.click(hide_pending);

        // ASSERT
        await pending_deletion;
        const vuln_xyz = await screen.getByRole('cell', {name: /CVE-2010-1234/});
        expect(vuln_xyz).toBeInTheDocument();
    })

    test('select all in table and unselecting', async () => {
        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        const thisFetch = fetchMock.mockImplementation(() =>
            Promise.resolve({
                json: () => Promise.resolve({
                    status: 'success',
                    assessment: {
                        id: '000',
                        vuln_id: 'CVE-0000-00000',
                        status: 'affected',
                        timestamp: "2024-01-01T00:00:00Z"
                    }
                }),
                status: 200
            } as Response)
        );

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

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
        expect(thisFetch).toHaveBeenCalledTimes(2);
    })

    test('select and change time estimate', async () => {
        const thisFetch = fetchMock.mockImplementation(() =>
            Promise.resolve({
                json: () => Promise.resolve({
                    id: 'CVE-2010-1234',
                    packages: ['aaabbbccc@1.0.0'],
                    effort: {
                        optimistic: 'PT5H',
                        likely: 'P2DT4H',
                        pessimistic: 'P2W3D'
                    },
                    responses: []
                }),
                text: () => Promise.resolve('Text only usefull when error happens'),
                status: 200
            } as Response)
        );

        // ARRANGE
        render(<TableVulnerabilities vulnerabilities={vulnerabilities} appendAssessment={() => {}} patchVuln={() => {}} />);

        const user = userEvent.setup();
        const select_all = await screen.getByTitle(/select all/i);
        expect(select_all).toBeInTheDocument();

        await user.click(select_all)

        const edit_time_btn = await screen.getByRole('button', {name: /Change estimated time/i});
        expect(edit_time_btn).toBeInTheDocument();
        await user.click(edit_time_btn);

        // TimeEstimateEditor testing, taken from test_vuln_modal
        const optimistic = await screen.getByPlaceholderText(/shortest estimate/i);
        const likely = await screen.getByPlaceholderText(/balanced estimate/i);
        const pessimistic = await screen.getByPlaceholderText(/longest estimate/i);
        const btn = await screen.getByText(/save estimation/i);

        await user.type(optimistic, '5h');
        await user.type(likely, '2.5');
        await user.type(pessimistic, '2w 3d');
        await user.click(btn);

        // ASSERT
        expect(thisFetch).toHaveBeenCalledTimes(2);
    })
});
