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
});
