import { render, screen, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import type { Package } from "../../src/handlers/packages";
import Iso8601Duration from "../../src/handlers/iso8601duration";
import { asPackageVulnerabilities } from "../../src/handlers/patch_finder";
import PatchFinder from '../../src/pages/PatchFinder';

describe('Render patch found', () => {

    const vulns: Vulnerability[] = [
        {
            id: "CVE-2021-37322",
            aliases: [],
            related_vulnerabilities: [],
            namespace: "demo",
            found_by: ["test"],
            datasource: "demo",
            packages: ["aaabbbccc@1.0.0"],
            urls: [],
            texts: [],
            severity: {
                severity: 'low',
                min_score: 3,
                max_score: 3,
                cvss: []
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            effort: {
                optimistic: new Iso8601Duration("P0D"),
                likely: new Iso8601Duration("P0D"),
                pessimistic: new Iso8601Duration("P0D")
            },
            fix: {
                state: 'unknown'
            },
            status: "",
            simplified_status: "",
            assessments: []
        }
    ];
    const pkg: Package[] = [
        {
            id: "aaabbbccc@1.0.0",
            name: "aaabbbccc",
            version: "1.0.0",
            cpe: [],
            purl: [],
            vulnerabilities: {},
            maxSeverity: {},
            source: [],
            licences: "NOASSERTION"
        }
    ]

    test('render version when single update possible', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={vulns}
            packages={pkg}
            patchData={asPackageVulnerabilities({
                "aaabbbccc": {
                    "CVE-2021-37322 (nvd-cpe-match)": {
                        "fix": [">=? 1.2.3"],
                        "affected": ["< 1.2.3"]
                    }
                }
            })}
            db_ready={true}
        />);

        // ACT
        const actual_pkg = await screen.getByText(/^aaabbbccc$/i);
        const actual_version = await screen.getAllByText(/1\.0\.0/i);
        const removed_vulns = await screen.getByText((_, element) => element?.textContent === '-1 vulnerabilities');
        const upgrade_to = await screen.getAllByText(/1\.2\.3/i);

        // ASSERT
        expect(actual_pkg).toBeInTheDocument();
        expect(actual_version.length).toBeGreaterThan(0);
        expect(removed_vulns).toBeInTheDocument();
        expect(upgrade_to.length).toBeGreaterThan(0);
    })

    test('hidden when no update possible', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={vulns}
            packages={pkg}
            patchData={asPackageVulnerabilities({
                "aaabbbccc": {
                    "CVE-2021-37322 (nvd-cpe-match)": {
                        "fix": [],
                        "affected": ["<= 1.2.3"]
                    }
                }
            })}
            db_ready={true}
        />);

        // ACT
        const pkg_name = await screen.queryAllByText(/^aaabbbccc$/i);

        // ASSERT
        expect(pkg_name.length).toBe(0);
    })

    test('render version when multiple update possible', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={vulns}
            packages={pkg}
            patchData={asPackageVulnerabilities({
                "aaabbbccc": {
                    "CVE-2021-37322 (nvd-cpe-match)": {
                        "fix": [">=? 1.2.3"],
                        "affected": ["< 1.2.3"]
                    },
                    "CVE-0000-00000 (nvd-cpe-match)": {
                        "fix": ["> 1.4.0", "> 2.0.0"],
                        "affected": ["<= 1.4.0", "= 2.0.0"]
                    }
                }
            })}
            db_ready={true}
        />);

        // ACT
        const actual_version = await screen.getAllByText('1.0.0');
        const version_minor = await screen.getAllByText('1.2.3');
        const version_major = await screen.getAllByText('2.0.1');
        const removed_minor = await screen.getByText((_, element) => element?.textContent === '-1 vulnerabilities');
        const removed_major = await screen.getByText((_, element) => element?.textContent === '-2 vulnerabilities');

        // ASSERT
        expect(actual_version.length).toBeGreaterThan(0);
        expect(version_minor.length).toBeGreaterThan(0);
        expect(version_major.length).toBeGreaterThan(0);
        expect(removed_minor).toBeInTheDocument();
        expect(removed_major).toBeInTheDocument();
    })

    test('show and hide legend', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={vulns}
            packages={pkg}
            patchData={asPackageVulnerabilities({})}
            db_ready={true}
        />);

        // ACT
        const user = userEvent.setup();
        const legend_btn = await screen.getByRole('button', {name: /hide legend/i});
        const legend_title = await screen.getByRole('heading', { name: /^legend$/i, level: 2 });

        // ASSERT
        expect(legend_btn).toBeInTheDocument();
        expect(legend_title).toBeInTheDocument();

        await user.click(legend_btn);

        expect(legend_title).not.toBeInTheDocument();
        expect(legend_btn).toHaveTextContent(/show legend/i);
    })

    test('search a specific vulnerability', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={vulns}
            packages={pkg}
            patchData={asPackageVulnerabilities({
                "aaabbbccc": {
                    "CVE-2021-37322 (nvd-cpe-match)": {
                        "fix": [">=? 1.2.3"],
                        "affected": ["< 1.2.3"]
                    },
                    "CVE-0000-00000 (nvd-cpe-match)": {
                        "fix": ["> 1.4.0", "> 2.0.0"],
                        "affected": ["<= 1.4.0", "= 2.0.0"]
                    }
                }
            })}
            db_ready={true}
        />);

        // ACT
        const user = userEvent.setup();
        const search_bar = await screen.getByRole('searchbox');
        let version_minor = await screen.getAllByText('1.2.3');
        let version_major = await screen.getAllByText('2.0.1');

        // ASSERT
        expect(search_bar).toBeInTheDocument();
        expect(version_minor.length).toBeGreaterThan(0);
        expect(version_major.length).toBeGreaterThan(0);

        await user.type(search_bar, 'CVE-0000-00000');

        await waitForElementToBeRemoved(() => screen.getAllByText('1.2.3'), { timeout: 1000 });

        version_minor = await screen.queryAllByText('1.2.3');
        version_major = await screen.getAllByText('2.0.1');
        expect(version_minor.length).toBe(0);
        expect(version_major.length).toBeGreaterThan(0);
    })

    test('render when not ready', async () => {
        // ARRANGE
        render(<PatchFinder
            vulnerabilities={[]}
            packages={[]}
            patchData={{}}
            db_ready={false}
        />);

        // ACT
        const db_updating_msg = await screen.getByText(/database(.+)updating/i);

        // ASSERT
        expect(db_updating_msg).toBeInTheDocument();
    })

});
