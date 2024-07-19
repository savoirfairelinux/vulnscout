import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import VulnModal from '../../src/components/VulnModal';


describe('Vulnerability Modal', () => {

    const vulnerability: Vulnerability = {
        id: 'CVE-2010-1234',
        aliases: ['CVE-2008-3456'],
        related_vulnerabilities: ['OSV-xyz-1234'],
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
        fix: {
            state: 'unknown'
        },
        status: 'affected',
        simplified_status: 'active',
        assessments: [{
            id: 'assessment-1',
            vuln_id: 'CVE-2010-1234',
            packages: ['aaabbbccc@1.0.0'],
            status: 'affected',
            simplified_status: 'active',
            justification: 'because 42',
            impact_statement: 'may impact or not',
            status_notes: 'this is a fictive status note',
            workaround: 'update dependency',
            timestamp: '2021-01-01T00:00:00Z',
            responses: []
        }]
    };


    test('render important data in header', async () => {
        // ARRANGE
        render(<VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} />);

        // ACT
        const id = await screen.getByText(/^\s*CVE-2010-1234\s*$/i);
        const severity = await screen.getByText(/low/i);
        const epss_score = await screen.getByText(/35\.6[78]/i);
        const packages = await screen.getByText(/aaabbbccc@1\.0\.0/i);
        const status = await screen.getAllByText(/active/i);
        const source = await screen.getByText(/hardcoded/i);
        const aliases = await screen.getByText(/CVE-2008-3456/i);
        const related_vulns = await screen.getByText(/OSV-xyz-1234/i);

        // ASSERT
        expect(id).toBeInTheDocument();
        expect(severity).toBeInTheDocument();
        expect(epss_score).toBeInTheDocument();
        expect(packages).toBeInTheDocument();
        expect(status[0]).toBeInTheDocument();
        expect(source).toBeInTheDocument();
        expect(aliases).toBeInTheDocument();
        expect(related_vulns).toBeInTheDocument();
    })

    test('render text description', async () => {
        // ARRANGE
        render(<VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} />);

        // ACT
        const title = await screen.getByText(/description/i);
        const desc = await screen.getByText(/authentification process/i);

        // ASSERT
        expect(title).toBeInTheDocument();
        expect(desc).toBeInTheDocument();
    })

    test('render urls and datasource', async () => {
        // ARRANGE
        render(<VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} />);

        // ACT
        const datasource = await screen.getByText(/nvd\.nist\.gov\/vuln\/detail\/CVE-2010-1234/i);
        const url = await screen.getByText(/security-tracker\.debian\.org\/tracker\/CVE-2010-1234/i);

        // ASSERT
        expect(datasource).toBeInTheDocument();
        expect(url).toBeInTheDocument();
    })

    test('render assessment data', async () => {
        // ARRANGE
        render(<VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} />);

        // ACT
        const status = await screen.getAllByText(/active/i);
        const justification = await screen.getByText(/because 42/i);
        const impact = await screen.getByText(/may impact or not/i);
        const status_notes = await screen.getByText(/this is a fictive status note/i);
        const workaround = await screen.getByText(/update dependency/i);

        // ASSERT
        expect(status[0]).toBeInTheDocument();
        expect(justification).toBeInTheDocument();
        expect(impact).toBeInTheDocument();
        expect(status_notes).toBeInTheDocument();
        expect(workaround).toBeInTheDocument();
    })

    test('closing button', async () => {
        // ARRANGE
        const closeBtn = jest.fn();
        render(<VulnModal vuln={vulnerability} onClose={closeBtn} appendAssessment={() => {}} />);

        const user = userEvent.setup();
        const closeBtns = await screen.getAllByText(/Close/i);

        // ACT
        for (const btn of closeBtns) {
            await user.click(btn);
        }

        // ASSERT
        expect(closeBtn).toHaveBeenCalledTimes(closeBtns.length);
    })

    test('adding assessment', async () => {
        fetchMock.resetMocks();
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve({
                    "status": "success",
                    "assessment": {
                        id: '00-0-0-0-000-00',
                        vuln_id: vulnerability.id,
                        packages: vulnerability.packages,
                        status: 'fixed',
                        status_notes: 'patched by upgrading layer version',
                        workadound: 'upgrade layer version',
                        timestamp: '2021-01-02T00:00:00Z',
                        responses: []
                    }
                })
            } as Response)
        );

        // ARRANGE
        const updateCb = jest.fn();
        const closeBtn = jest.fn();
        render(<VulnModal vuln={vulnerability} onClose={closeBtn} appendAssessment={updateCb} />);
        const user = userEvent.setup();

        // ACT
        const selects = await screen.getAllByRole('combobox');
        const selectSource = selects.find((el) => el.getAttribute('name')?.includes('new_assessment_status')) as HTMLElement;
        expect(selectSource).toBeDefined();
        expect(selectSource).toBeInTheDocument();
        const inputStatus = await screen.getByPlaceholderText(/notes/i);
        const inputWorkaround = await screen.getByPlaceholderText(/workaround/i);
        const btn = await screen.getByText(/add assessment/i);

        await user.selectOptions(selectSource, 'fixed');
        await user.type(inputStatus, 'patched by upgrading layer version');
        await user.type(inputWorkaround, 'upgrade layer version');
        await user.click(btn);

        // ASSERT
        expect(thisFetch).toHaveBeenCalledTimes(1);
        expect(closeBtn).toHaveBeenCalledTimes(1);
        expect(updateCb).toHaveBeenCalledTimes(1);
    })
});
