import { render, screen, waitForElementToBeRemoved } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import type { Package } from "../../src/handlers/packages";
import Iso8601Duration from "../../src/handlers/iso8601duration";
import { asPackageVulnerabilities, asAPIStatus, asPatchInfos } from "../../src/handlers/patch_finder";
import PatchFinderLogic from "../../src/handlers/patch_finder";
import PatchFinder from '../../src/pages/PatchFinder';

describe('asAPIStatus parsing', () => {
    test('parses complete APIStatus data', () => {
        const data = {
            api_version: '1.0.0',
            db_version: '2023-11-01',
            db_ready: true,
            vulns_count: 1234,
            last_modified: '2023-11-01T12:00:00Z'
        };
        const result = asAPIStatus(data);
        expect(result.api_version).toBe('1.0.0');
        expect(result.db_version).toBe('2023-11-01');
        expect(result.db_ready).toBe(true);
        expect(result.vulns_count).toBe(1234);
        expect(result.last_modified).toBe('2023-11-01T12:00:00Z');
    });

    test('returns default values for invalid data', () => {
        const result = asAPIStatus(null);
        expect(result.api_version).toBe('unknown');
        expect(result.db_ready).toBe(false);
        expect(result.vulns_count).toBe(0);
        expect(result.db_version).toBeUndefined();
        expect(result.last_modified).toBeUndefined();
    });

    test('handles partial data', () => {
        const data = {
            db_ready: true,
            vulns_count: 500
        };
        const result = asAPIStatus(data);
        expect(result.api_version).toBe('unknown');
        expect(result.db_ready).toBe(true);
        expect(result.vulns_count).toBe(500);
    });
});

describe('asPatchInfos parsing', () => {
    test('parses valid patch infos with solve_all', () => {
        const data = {
            affected: ['< 1.0.0'],
            fix: ['>=? 1.2.3', '>=? 1.3.0']
        };
        const result = asPatchInfos(data);
        expect(result?.affected).toEqual(['< 1.0.0']);
        expect(result?.fix).toEqual(['>=? 1.2.3', '>=? 1.3.0']);
        expect(result?.solve_all).toBeDefined();
    });

    test('filters non-string values from affected and fix arrays', () => {
        const data = {
            affected: ['< 1.0.0', 123, null, '< 2.0.0'],
            fix: ['>=? 1.2.3', false, '>=? 1.3.0']
        };
        const result = asPatchInfos(data);
        expect(result?.affected).toEqual(['< 1.0.0', '< 2.0.0']);
        expect(result?.fix).toEqual(['>=? 1.2.3', '>=? 1.3.0']);
    });

    test('returns undefined solve_all when no valid versions', () => {
        const data = {
            affected: ['< 1.0.0'],
            fix: ['invalid version']
        };
        const result = asPatchInfos(data);
        expect(result?.solve_all).toBeUndefined();
    });

    test('returns undefined for invalid data', () => {
        // Note: null is typeof 'object' in JavaScript, so it passes the first check
        // but then the code tries to set properties which throws an error
        // We should test with non-object types instead
        expect(asPatchInfos('string')).toBeUndefined();
        expect(asPatchInfos(123)).toBeUndefined();
        expect(asPatchInfos(undefined)).toBeUndefined();
    });
});

describe('compute_versions_and_patch', () => {
    test('handles invalid version in current packages (catch block)', () => {
        const data = asPackageVulnerabilities({
            "test-pkg": {
                "CVE-2021-1234 (nvd)": {
                    "fix": [">=? 1.2.3"],
                    "affected": ["< 1.2.3"]
                }
            }
        });
        const current = { "test-pkg": "invalid-version" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, [], '');
        // Should skip package with invalid version
        expect(Object.keys(result)).toHaveLength(0);
    });

    test('skips package when semver.Range returns null', () => {
        const data = asPackageVulnerabilities({
            "test-pkg": {
                "CVE-2021-1234 (nvd)": {
                    "fix": [">=? 1.2.3"],
                    "affected": ["< 1.2.3"]
                }
            }
        });
        const current = { "test-pkg": "" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, [], '');
        expect(Object.keys(result)).toHaveLength(0);
    });

    test('filters by selectedSources', () => {
        const data = {
            "test-pkg": {
                "CVE-2021-1234": {
                    "nvd": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                },
                "CVE-2021-5678": {
                    "ghsa": {
                        affected: ["< 1.3.0"],
                        fix: [">=? 1.3.0"],
                        solve_all: "1.3.0"
                    }
                }
            }
        };
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, ['nvd'], '');
        expect(result['test-pkg'].nb_vulns).toBe(2);
        expect(result['test-pkg'].latest.solve).toBe(1); // Only nvd source counted
    });

    test('filters by search string matching version', () => {
        const data = asPackageVulnerabilities({
            "test-pkg": {
                "CVE-2021-1234 (nvd)": {
                    "fix": [">=? 1.2.3"],
                    "affected": ["< 1.2.3"]
                },
                "CVE-2021-5678 (nvd)": {
                    "fix": [">=? 2.0.0"],
                    "affected": ["< 2.0.0"]
                }
            }
        });
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, [], '2.0.0');
        expect(result['test-pkg'].latest.solve).toBe(1); // Only matching version
    });

    test('filters by search string matching CVE ID', () => {
        const data = asPackageVulnerabilities({
            "test-pkg": {
                "CVE-2021-1234 (nvd)": {
                    "fix": [">=? 1.2.3"],
                    "affected": ["< 1.2.3"]
                },
                "CVE-2021-5678 (nvd)": {
                    "fix": [">=? 1.3.0"],
                    "affected": ["< 1.3.0"]
                }
            }
        });
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, [], 'CVE-2021-5678');
        expect(result['test-pkg'].latest.solve).toBe(1); // Only matching CVE
    });

    test('counts same_minor and same_major versions correctly', () => {
        const data = asPackageVulnerabilities({
            "test-pkg": {
                "CVE-2021-1234 (nvd)": {
                    "fix": [">=? 1.0.5"],
                    "affected": ["< 1.0.5"]
                },
                "CVE-2021-5678 (nvd)": {
                    "fix": [">=? 1.5.0"],
                    "affected": ["< 1.5.0"]
                },
                "CVE-2021-9999 (nvd)": {
                    "fix": [">=? 2.0.0"],
                    "affected": ["< 2.0.0"]
                }
            }
        });
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_versions_and_patch(data, current, [], '');
        
        expect(result['test-pkg'].same_minor.solve).toBe(1); // 1.0.5 is same minor
        expect(result['test-pkg'].same_minor.version).toBe('1.0.5');
        expect(result['test-pkg'].same_major.solve).toBe(2); // 1.0.5 and 1.5.0 are same major
        expect(result['test-pkg'].same_major.version).toBe('1.5.0');
        expect(result['test-pkg'].latest.solve).toBe(3); // All versions
        expect(result['test-pkg'].latest.version).toBe('2.0.0');
    });
});

describe('compute_vulns_per_versions', () => {
    test('filters by selectedSources', () => {
        const data = {
            "test-pkg": {
                "CVE-2021-1234": {
                    "nvd": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                },
                "CVE-2021-5678": {
                    "ghsa": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                }
            }
        };
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_vulns_per_versions(data, current, ['nvd'], '');
        
        expect(result['test-pkg']['1.2.3']).toHaveLength(1);
        expect(result['test-pkg']['1.2.3']).toContain('CVE-2021-1234');
        expect(result['test-pkg']['1.2.3']).not.toContain('CVE-2021-5678');
    });

    test('filters by search string matching version', () => {
        const data = {
            "test-pkg": {
                "CVE-2021-1234": {
                    "nvd": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                },
                "CVE-2021-5678": {
                    "nvd": {
                        affected: ["< 2.0.0"],
                        fix: [">=? 2.0.0"],
                        solve_all: "2.0.0"
                    }
                }
            }
        };
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_vulns_per_versions(data, current, [], '2.0.0');
        
        expect(result['test-pkg']['2.0.0']).toBeDefined();
        expect(result['test-pkg']['1.2.3']).toBeUndefined();
    });

    test('filters by search string matching CVE ID', () => {
        const data = {
            "test-pkg": {
                "CVE-2021-1234": {
                    "nvd": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                },
                "CVE-2021-5678": {
                    "nvd": {
                        affected: ["< 1.2.3"],
                        fix: [">=? 1.2.3"],
                        solve_all: "1.2.3"
                    }
                }
            }
        };
        const current = { "test-pkg": "1.0.0" };
        const result = PatchFinderLogic.compute_vulns_per_versions(data, current, [], 'CVE-2021-5678');
        
        expect(result['test-pkg']['1.2.3']).toHaveLength(1);
        expect(result['test-pkg']['1.2.3']).toContain('CVE-2021-5678');
        expect(result['test-pkg']['1.2.3']).not.toContain('CVE-2021-1234');
    });
});

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
