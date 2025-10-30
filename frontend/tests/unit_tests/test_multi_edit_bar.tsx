import { render } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import MultiEditBar from '../../src/components/MultiEditBar';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';

describe('MultiEditBar', () => {
    const mockVulnerabilities: Vulnerability[] = [
        {
            id: 'vuln-1',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'test',
            found_by: ['test'],
            datasource: 'test',
            packages: ['pkg1'],
            urls: [],
            texts: [],
            severity: {
                severity: 'LOW',
                min_score: 0,
                max_score: 10,
                cvss: []
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            fix: {
                state: 'unknown'
            },
            status: 'not_affected',
            simplified_status: 'not_affected',
            assessments: [],
            effort: {
                optimistic: { formatAsIso8601: () => 'PT1H' } as any,
                likely: { formatAsIso8601: () => 'PT2H' } as any,
                pessimistic: { formatAsIso8601: () => 'PT3H' } as any
            }
        },
        {
            id: 'vuln-2',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'test',
            found_by: ['test'],
            datasource: 'test',
            packages: ['pkg2'],
            urls: [],
            texts: [],
            severity: {
                severity: 'HIGH',
                min_score: 0,
                max_score: 10,
                cvss: []
            },
            epss: {
                score: undefined,
                percentile: undefined
            },
            fix: {
                state: 'unknown'
            },
            status: 'affected',
            simplified_status: 'affected',
            assessments: [],
            effort: {
                optimistic: { formatAsIso8601: () => 'PT1H' } as any,
                likely: { formatAsIso8601: () => 'PT2H' } as any,
                pessimistic: { formatAsIso8601: () => 'PT3H' } as any
            }
        }
    ];

    const mockProps = {
        vulnerabilities: mockVulnerabilities,
        selectedVulns: [],
        resetVulns: () => {},
        appendAssessment: () => {},
        patchVuln: () => {},
        triggerBanner: () => {},
        hideBanner: () => {}
    };

    test('renders nothing when no selection', () => {
        const { container } = render(<MultiEditBar {...mockProps} />);
        expect(container.firstChild).toBeNull();
    });

    test('renders with selection', () => {
        const props = { ...mockProps, selectedVulns: ['vuln-1'] };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });

    test('handles same status across vulnerabilities', () => {
        const sameStatusVulns = [
            { ...mockVulnerabilities[0], id: 'vuln-1', status: 'affected' },
            { ...mockVulnerabilities[0], id: 'vuln-2', status: 'affected' }
        ];
        const props = {
            ...mockProps,
            vulnerabilities: sameStatusVulns,
            selectedVulns: ['vuln-1', 'vuln-2']
        };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });

    test('handles different status across vulnerabilities', () => {
        const mixedStatusVulns = [
            { ...mockVulnerabilities[0], id: 'vuln-1', status: 'affected' },
            { ...mockVulnerabilities[0], id: 'vuln-2', status: 'not_affected' }
        ];
        const props = {
            ...mockProps,
            vulnerabilities: mixedStatusVulns,
            selectedVulns: ['vuln-1', 'vuln-2']
        };
        const { container } = render(<MultiEditBar {...props} />);
        expect(container.firstChild).not.toBeNull();
    });
});