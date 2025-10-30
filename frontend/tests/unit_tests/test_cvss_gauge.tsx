import { render, screen } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { CVSS } from "../../src/handlers/vulnerabilities";
import CvssGauge from '../../src/components/CvssGauge';



describe('CVSS Gauge', () => {

    const vulnerability_scores: CVSS[] = [
        {
            author: 'nvd@nist',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            severity: 'low',
            base_score: 3.1,
            exploitability_score: 1.8,
            impact_score: 2.2,
        },
        {
            author: 'redhat',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            severity: 'high',
            base_score: 8.1,
            exploitability_score: 4.8,
            impact_score: 5.2,
        },
        {
            author: 'github',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity: 'critical',
            base_score: 9.8,
            exploitability_score: 3.9,
            impact_score: 5.9,
        },
        {
            author: 'vendor',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L',
            severity: 'medium',
            base_score: 5.3,
            exploitability_score: 1.8,
            impact_score: 3.6,
        }
    ];

    test('render low severity CVSS gauge', async () => {
        // ARRANGE
        render(<CvssGauge data={vulnerability_scores[0]} />);

        // ACT
        const score = await screen.getByText(/3\.1/i);
        const author = await screen.getByText(/nvd@nist/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render high severity CVSS gauge', async () => {
        // ARRANGE
        render(<CvssGauge data={vulnerability_scores[1]} />);

        // ACT
        const score = await screen.getByText(/8\.1/i);
        const author = await screen.getByText(/redhat/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render critical severity CVSS gauge (>= 9.0)', async () => {
        // ARRANGE
        render(<CvssGauge data={vulnerability_scores[2]} />);

        // ACT
        const score = await screen.getByText(/9\.8/i);
        const author = await screen.getByText(/github/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render medium severity CVSS gauge (4.0-6.9)', async () => {
        // ARRANGE
        render(<CvssGauge data={vulnerability_scores[3]} />);

        // ACT
        const score = await screen.getByText(/5\.3/i);
        const author = await screen.getByText(/vendor/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render edge case: minimum valid score (0.0)', async () => {
        // ARRANGE
        const minScore: CVSS = {
            author: 'tester',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            severity: 'none',
            base_score: 0.0,
            exploitability_score: 0.0,
            impact_score: 0.0,
        };

        render(<CvssGauge data={minScore} />);

        // ACT
        const score = await screen.getByText(/0/);
        const author = await screen.getByText(/tester/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render edge case: maximum valid score (10.0)', async () => {
        // ARRANGE
        const maxScore: CVSS = {
            author: 'tester',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            severity: 'critical',
            base_score: 10.0,
            exploitability_score: 3.9,
            impact_score: 6.0,
        };

        render(<CvssGauge data={maxScore} />);

        // ACT
        const score = await screen.getByText(/10/);
        const author = await screen.getByText(/tester/i);

        // ASSERT
        expect(score).toBeInTheDocument();
        expect(author).toBeInTheDocument();
    })

    test('render nothing for invalid base_score (not a number)', () => {
        // ARRANGE
        const invalidScore: CVSS = {
            author: 'test',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            severity: 'unknown',
            base_score: 'invalid' as any, // Force invalid type
            exploitability_score: 1.8,
            impact_score: 2.2,
        };

        const { container } = render(<CvssGauge data={invalidScore} />);

        // ASSERT
        expect(container.firstChild).toBeNull();
    })

    test('render nothing for base_score below 0', () => {
        // ARRANGE
        const invalidScore: CVSS = {
            author: 'test',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            severity: 'unknown',
            base_score: -1.0,
            exploitability_score: 1.8,
            impact_score: 2.2,
        };

        const { container } = render(<CvssGauge data={invalidScore} />);

        // ASSERT
        expect(container.firstChild).toBeNull();
    })

    test('render nothing for base_score above 10', () => {
        // ARRANGE
        const invalidScore: CVSS = {
            author: 'test',
            version: '3.1',
            vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            severity: 'unknown',
            base_score: 11.0,
            exploitability_score: 1.8,
            impact_score: 2.2,
        };

        const { container } = render(<CvssGauge data={invalidScore} />);

        // ASSERT
        expect(container.firstChild).toBeNull();
    })
});
