import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../../src/components/TableGeneric', () => ({
    __esModule: true,
    default: ({ data }: { data: { id: string }[] }) => (
        <div data-testid="vulnerability-rows">
            {data.map(row => <span key={row.id}>{row.id}</span>)}
        </div>
    ),
}));

const progressHandler = { getProgress: jest.fn().mockResolvedValue(null) };
jest.mock('../../src/handlers/nvd_progress', () => ({ __esModule: true, default: progressHandler }));
jest.mock('../../src/handlers/epss_progress', () => ({ __esModule: true, default: progressHandler }));
jest.mock('../../src/handlers/ghsa_progress', () => ({ __esModule: true, default: progressHandler }));
jest.mock('../../src/handlers/euvd_progress', () => ({ __esModule: true, default: progressHandler }));
jest.mock('../../src/handlers/assessments', () => ({
    __esModule: true,
    default: { listReviewAi: jest.fn().mockResolvedValue([]) },
}));

import Vulnerabilities, { type Vulnerability } from '../../src/handlers/vulnerabilities';
import TableVulnerabilities from '../../src/pages/TableVulnerabilities';

const makeVulnerability = (id: string): Vulnerability => ({
    id,
    namespace: '',
    datasource: '',
    found_by: [],
    packages: [],
    packages_current: [],
    variants: [],
    texts: [],
    severity: { severity: 'high', min_score: 8, max_score: 8, cvss: [] },
    epss: { score: 0.1, percentile: 0.2 },
    effort: {} as Vulnerability['effort'],
    fix: { state: 'unknown' },
    simplified_status: 'unknown',
    assessments: [],
} as unknown as Vulnerability);

describe('Vulnerabilities match condition', () => {
    test('filters the table to matching vulnerability IDs', async () => {
        const vulnerabilities = [makeVulnerability('CVE-HIGH'), makeVulnerability('CVE-LOW')];
        jest.spyOn(Vulnerabilities, 'matchCondition').mockResolvedValue(['CVE-HIGH']);

        render(
            <TableVulnerabilities
                vulnerabilities={vulnerabilities}
                appendAssessment={jest.fn()}
                appendCVSS={jest.fn()}
                patchVuln={jest.fn()}
                missingEuvdDataBannerDismissed={true}
                missingPublishedDateDataBannerDismissed={true}
            />
        );

        expect(screen.getByText('CVE-HIGH')).toBeInTheDocument();
        expect(screen.getByText('CVE-LOW')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Apply' })).not.toBeInTheDocument();

        fireEvent.change(screen.getByLabelText('Match condition'), { target: { value: 'cvss >= 7' } });
        fireEvent.keyDown(screen.getByLabelText('Match condition'), { key: 'Enter' });

        await waitFor(() => expect(Vulnerabilities.matchCondition).toHaveBeenCalledWith('cvss >= 7', vulnerabilities));
        await waitFor(() => expect(screen.queryByText('CVE-LOW')).not.toBeInTheDocument());
        expect(screen.getByText('CVE-HIGH')).toBeInTheDocument();
    });
});