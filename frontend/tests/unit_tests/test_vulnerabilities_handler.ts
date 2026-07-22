
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

jest.mock('ae-cvss-calculator', () => {
  const makeClass = () => {
    return jest.fn().mockImplementation((vector: string) => ({
      calculateScores: () => {
        if (vector.startsWith('INVALID')) {
          throw new Error('invalid vector');
        }
        const m = vector.match(/BS:([0-9.]+)/);
        const base = m ? parseFloat(m[1]) : 0;
        return {
          base,
          overall: base, // fallback field
          vector
        };
      }
    }));
  };
  return {
    Cvss4P0: makeClass(),
    Cvss3P1: makeClass(),
    Cvss3P0: makeClass(),
    Cvss2: makeClass()
  };
});

import Vulnerabilities, {
  buildStatusSummary,
  getTopStatusSummaryLabel,
  isVulnerabilityActive,
  getStatusSortIndex,
  isActiveStatus,
} from '../../src/handlers/vulnerabilities';

// Utility to build raw vulnerability JSON objects returned by backend
const rawVuln = (overrides: any = {}) => ({
  id: 'CVE-TEST-1',
  aliases: ['ALIAS-1', 123],
  related_vulnerabilities: ['CVE-REL-1'],
  namespace: 'nvd:cve',
  found_by: ['scannerX', null],
  datasource: 'https://example',
  packages: ['pkg@1.0.0'],
  urls: ['https://example/CVE'],
  texts: { description: 'Desc', extra: 123 }, // only string values kept
  severity: {
    severity: 'medium',
    min_score: 4,
    max_score: 6,
    cvss: overrides.cvss ?? []
  },
  epss: {
    score: 0.1234,
    percentile: 0.9876
  },
  effort: {
    optimistic: 'PT1H',
    likely: 'PT2H',
    pessimistic: 'P1D'
  },
  fix: { state: 'unknown' },
  ...overrides
});

describe('Vulnerabilities parsing CVSS branches', () => {
  beforeEach(() => {
    fetchMock.resetMocks();
  });

  test('list with compareVariantId and operation sets compare query params', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([rawVuln()]));
    const vulns = await Vulnerabilities.list('variant-1', undefined, 'variant-2', 'difference');
    expect(vulns).toHaveLength(1);
    const calledUrl = new URL(fetchMock.mock.calls[0][0] as string);
    expect(calledUrl.searchParams.get('variant_id')).toBe('variant-1');
    expect(calledUrl.searchParams.get('compare_variant_id')).toBe('variant-2');
    expect(calledUrl.searchParams.get('operation')).toBe('difference');
    expect(calledUrl.searchParams.get('format')).toBe('compact');
  });

  test('parses compact records and preserves explicit attack vectors', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([rawVuln({
      details_loaded: false,
      texts: undefined,
      urls: undefined,
      severity: {
        severity: 'high',
        min_score: 8.1,
        max_score: 8.1,
        cvss: [{ version: '3.1', base_score: 8.1, attack_vector: 'ADJACENT' }],
      },
    })]));

    const [vuln] = await Vulnerabilities.list();
    expect(vuln.details_loaded).toBe(false);
    expect(vuln.texts).toEqual([]);
    expect(vuln.urls).toEqual([]);
    expect(vuln.severity.cvss[0].attack_vector).toBe('ADJACENT');
  });

  test('getDetails requests a scoped full vulnerability', async () => {
    fetchMock.mockResponseOnce(JSON.stringify(rawVuln()));

    const details = await Vulnerabilities.getDetails('CVE-TEST-1', 'variant-1', 'project-1');

    expect(details?.details_loaded).toBe(true);
    const calledUrl = new URL(fetchMock.mock.calls[0][0] as string);
    expect(calledUrl.pathname).toContain('/api/vulnerabilities/CVE-TEST-1');
    expect(calledUrl.searchParams.get('variant_id')).toBe('variant-1');
    expect(calledUrl.searchParams.has('project_id')).toBe(false);
  });

  test('getDetails rejects non-success responses with the status', async () => {
    fetchMock.mockResponseOnce('', { status: 503 });

    await expect(Vulnerabilities.getDetails('CVE-TEST-1')).rejects.toThrow(
      'Failed to load vulnerability details (503)',
    );
  });

  test('list with compareVariantId but no operation omits operation param', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([rawVuln()]));
    const vulns = await Vulnerabilities.list('variant-1', undefined, 'variant-2');
    expect(vulns).toHaveLength(1);
    const calledUrl = new URL(fetchMock.mock.calls[0][0] as string);
    expect(calledUrl.searchParams.get('variant_id')).toBe('variant-1');
    expect(calledUrl.searchParams.get('compare_variant_id')).toBe('variant-2');
    expect(calledUrl.searchParams.has('operation')).toBe(false);
  });

  test('filters invalid cvss entries and keeps valid ones with attack vector', async () => {
    const cvssArray = [
      { version: '3.1', base_score: 5.5, vector_string: 'CVSS:3.1/AV:N/BS:5.5' },
      { version: '2.0', base_score: 0 },
      { version: '3.0', base_score: 7.2, vector_string: 'CVSS:3.0/AV:L/BS:7.2' },
      null,
      5,
      { version: '3.1', base_score: 'x' },
      { base_score: 5 },
      { version: '4.0' }
    ] as any[];

    fetchMock.mockResponseOnce(JSON.stringify([
      rawVuln({
        severity: {
          severity: 'medium',
            min_score: 4,
            max_score: 6,
            cvss: cvssArray
          }
        })
    ]));

    const vulns = await Vulnerabilities.list();
    expect(vulns).toHaveLength(1);
    const v: any = vulns[0];

    // Only 3 valid entries should remain
    expect(v.severity.cvss).toHaveLength(3);
    const versions = v.severity.cvss.map((c: any) => c.version).sort();
    expect(versions).toEqual(['2.0','3.0','3.1'].sort());

    const v31 = v.severity.cvss.find((c: any) => c.version === '3.1');
    const v30 = v.severity.cvss.find((c: any) => c.version === '3.0');
    expect(v31.attack_vector).toBe('NETWORK');
    expect(v30.attack_vector).toBe('LOCAL');
  });
});

describe('calculate_cvss_from_vector branches', () => {
  test('supports multiple versions and invalid vectors', () => {
    const v4 = Vulnerabilities.calculate_cvss_from_vector('CVSS:4.0/AV:N/BS:5.5');
    expect(v4?.version).toBe('4.0');
    expect(v4?.attack_vector).toBe('NETWORK');

    const v31 = Vulnerabilities.calculate_cvss_from_vector('CVSS:3.1/AV:A/BS:3.2');
    expect(v31?.version).toBe('3.1');
    expect(v31?.attack_vector).toBe('ADJACENT');

    const v30 = Vulnerabilities.calculate_cvss_from_vector('CVSS:3.0/AV:L/BS:7.2');
    expect(v30?.version).toBe('3.0');
    expect(v30?.attack_vector).toBe('LOCAL');

    const v2 = Vulnerabilities.calculate_cvss_from_vector('AV:P/BS:9.0');
    expect(v2?.version).toBe('2.0');
    expect(v2?.attack_vector).toBe('PHYSICAL');

    const invalid = Vulnerabilities.calculate_cvss_from_vector('INVALID_VECTOR');
    expect(invalid).toBeNull();
  });
});

describe('enrich_with_assessments', () => {
  test('enriches vulnerabilities with assessments and sorts by timestamp', () => {
    const vulns = [
      rawVuln({ id: 'CVE-2021-1' }),
      rawVuln({ id: 'CVE-2021-2' }),
      rawVuln({ id: 'CVE-2021-3' })
    ].map((v: any) => {
      return {
        ...v,
        simplified_status: 'unknown',
        assessments: []
      };
    });

    const assessments = [
      {
        vuln_id: 'CVE-2021-1',
        status: 'investigating',
        simplified_status: 'open',
        timestamp: '2023-11-03T10:00:00Z',
        comment: 'First assessment'
      },
      {
        vuln_id: 'CVE-2021-1',
        status: 'resolved',
        simplified_status: 'closed',
        timestamp: '2023-11-03T12:00:00Z',
        comment: 'Resolved'
      },
      {
        vuln_id: 'CVE-2021-1',
        status: 'not_affected',
        simplified_status: 'closed',
        timestamp: '2023-11-03T11:00:00Z',
        comment: 'Actually not affected'
      },
      {
        vuln_id: 'CVE-2021-2',
        status: 'affected',
        simplified_status: 'open',
        timestamp: '2023-11-03T10:00:00Z',
        comment: 'Single assessment'
      }
    ] as any[];

    const enriched = Vulnerabilities.enrich_with_assessments(vulns, assessments);

    // CVE-2021-1 should have latest assessment (most recent timestamp)
    const cve1 = enriched.find((v: any) => v.id === 'CVE-2021-1');
    expect(cve1?.simplified_status).toBe('closed');
    expect(cve1?.assessments).toHaveLength(3);
    // Assessments should be sorted by timestamp
    expect(cve1?.assessments[0].timestamp).toBe('2023-11-03T10:00:00Z');
    expect(cve1?.assessments[1].timestamp).toBe('2023-11-03T11:00:00Z');
    expect(cve1?.assessments[2].timestamp).toBe('2023-11-03T12:00:00Z');

    // CVE-2021-2 should have single assessment
    const cve2 = enriched.find((v: any) => v.id === 'CVE-2021-2');
    expect(cve2?.simplified_status).toBe('open');
    expect(cve2?.assessments).toHaveLength(1);

    // CVE-2021-3 should remain unchanged
    const cve3 = enriched.find((v: any) => v.id === 'CVE-2021-3');
    expect(cve3?.simplified_status).toBe('unknown');
    expect(cve3?.assessments).toHaveLength(0);
  });

  test('handles empty assessments list', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        simplified_status: 'unknown',
        assessments: []
      }
    ];

    const enriched = Vulnerabilities.enrich_with_assessments(vulns, []);
    expect(enriched[0].simplified_status).toBe('unknown');
    expect(enriched[0].assessments).toHaveLength(0);
  });

  test('handles vulnerability with empty assessment array', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        simplified_status: 'unknown',
        assessments: []
      }
    ];

    // This simulates the case where no assessments exist for the vulnerability
    const enriched = Vulnerabilities.enrich_with_assessments(vulns, []);
    expect(enriched[0].simplified_status).toBe('unknown');
  });
});

describe('append_assessment', () => {
  test('appends assessment to matching vulnerability', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        simplified_status: 'unknown',
        assessments: []
      },
      {
        ...rawVuln({ id: 'CVE-2021-2' }),
        simplified_status: 'unknown',
        assessments: []
      }
    ];

    const assessment = {
      vuln_id: 'CVE-2021-1',
      status: 'investigating',
      simplified_status: 'open',
      timestamp: '2023-11-03T10:00:00Z',
      comment: 'New assessment'
    } as any;

    const result = Vulnerabilities.append_assessment(vulns, assessment);

    const cve1 = result.find((v: any) => v.id === 'CVE-2021-1');
    expect(cve1?.simplified_status).toBe('open');
    expect(cve1?.assessments).toHaveLength(1);

    const cve2 = result.find((v: any) => v.id === 'CVE-2021-2');
    expect(cve2?.simplified_status).toBe('unknown');
    expect(cve2?.assessments).toHaveLength(0);
  });
});

describe('append_cvss', () => {
  test('appends CVSS to matching vulnerability', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        simplified_status: 'unknown',
        assessments: [],
        severity: {
          severity: 'medium',
          min_score: 4,
          max_score: 6,
          cvss: []
        }
      }
    ];

    const cvss = {
      author: 'test',
      severity: 'HIGH',
      version: '3.1',
      vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      attack_vector: 'NETWORK',
      base_score: 7.5,
      exploitability_score: 3.9,
      impact_score: 3.6
    };

    const result = Vulnerabilities.append_cvss(vulns, 'CVE-2021-1', cvss);

    expect(result[0].severity.cvss).toHaveLength(1);
    expect(result[0].severity.cvss[0]).toEqual(cvss);
  });

  test('does not modify non-matching vulnerabilities', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        simplified_status: 'unknown',
        assessments: [],
        severity: {
          severity: 'medium',
          min_score: 4,
          max_score: 6,
          cvss: []
        }
      },
      {
        ...rawVuln({ id: 'CVE-2021-2' }),
        simplified_status: 'unknown',
        assessments: [],
        severity: {
          severity: 'medium',
          min_score: 4,
          max_score: 6,
          cvss: []
        }
      }
    ];

    const cvss = {
      author: 'test',
      severity: 'HIGH',
      version: '3.1',
      vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      attack_vector: 'NETWORK',
      base_score: 7.5,
      exploitability_score: 3.9,
      impact_score: 3.6
    };

    const result = Vulnerabilities.append_cvss(vulns, 'CVE-2021-1', cvss);

    expect(result[0].severity.cvss).toHaveLength(1);
    expect(result[1].severity.cvss).toHaveLength(0);
  });
});

describe('calculate_cvss_from_vector error handling', () => {
  test('handles non-invalid vector errors by logging them', () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    // Mock the CVSS calculator to throw a different error
    const originalCvss3P1 = require('ae-cvss-calculator').Cvss3P1;
    require('ae-cvss-calculator').Cvss3P1 = jest.fn().mockImplementation(() => ({
      calculateScores: () => {
        throw new Error('unexpected error');
      }
    }));

    const result = Vulnerabilities.calculate_cvss_from_vector('CVSS:3.1/AV:N/BS:5.5');

    expect(result).toBeNull();
    expect(consoleErrorSpy).toHaveBeenCalled();

    // Restore mocks
    require('ae-cvss-calculator').Cvss3P1 = originalCvss3P1;
    consoleErrorSpy.mockRestore();
  });

  test('suppresses expected invalid vector errors', () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const result = Vulnerabilities.calculate_cvss_from_vector('INVALID_VECTOR');

    expect(result).toBeNull();
    // Should NOT log the error since it's an expected 'invalid vector' error
    expect(consoleErrorSpy).not.toHaveBeenCalled();

    consoleErrorSpy.mockRestore();
  });
});

describe('buildStatusSummary helpers', () => {
  const makeAssessment = (simplified_status: string, timestamp: string, variant_id?: string) => ({
    id: 'a',
    vuln_id: 'CVE-1',
    packages: [],
    origin: 'sbom',
    status: simplified_status,
    simplified_status,
    timestamp,
    responses: [],
    variant_id,
  });

  test('empty assessments returns unknown summary', () => {
    const summary = buildStatusSummary([]);
    expect(summary.dominant_status).toBe('unknown');
    expect(summary.total_assessments).toBe(0);
    expect(summary.has_active_status).toBe(false);
  });

  test('single assessment builds correct summary', () => {
    const summary = buildStatusSummary([makeAssessment('Fixed', '2024-01-01T00:00:00')]);
    expect(summary.dominant_status).toBe('Fixed');
    expect(summary.total_assessments).toBe(1);
    expect(summary.has_active_status).toBe(false);
  });

  test('multiple variants each contribute one slot', () => {
    // v1 → Fixed, v2 → Exploitable; dominant_status should be Exploitable
    const assessments = [
      makeAssessment('Fixed', '2024-01-01T00:00:00', 'v1'),
      makeAssessment('Exploitable', '2024-01-02T00:00:00', 'v2'),
    ];
    const summary = buildStatusSummary(assessments);
    expect(summary.counts['Fixed']).toBe(1);
    expect(summary.counts['Exploitable']).toBe(1);
    expect(summary.dominant_status).toBe('Exploitable');
    expect(summary.has_active_status).toBe(true);
    // ordered should have 2 entries, triggering the sort comparator
    expect(summary.ordered.length).toBe(2);
  });

  test('sort comparator uses count as tiebreaker', () => {
    // v1 and v2 → Pending Assessment, v3 → Exploitable
    const assessments = [
      makeAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v1'),
      makeAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v2'),
      makeAssessment('Exploitable', '2024-01-01T00:00:00', 'v3'),
    ];
    const summary = buildStatusSummary(assessments);
    // Exploitable has higher priority (lower index) so it's first despite lower count
    expect(summary.dominant_status).toBe('Exploitable');
    expect(summary.ordered[0].status).toBe('Exploitable');
    expect(summary.ordered[1].status).toBe('Pending Assessment');
  });

  test('sort comparator uses localeCompare when priority and count tie', () => {
    // Two unknown statuses from two variants, both non-standard
    const assessments = [
      makeAssessment('ZStatus', '2024-01-01T00:00:00', 'v1'),
      makeAssessment('AStatus', '2024-01-01T00:00:00', 'v2'),
    ];
    const summary = buildStatusSummary(assessments);
    // Both are equal priority and equal count → sorted alphabetically
    expect(summary.ordered[0].status).toBe('AStatus');
    expect(summary.ordered[1].status).toBe('ZStatus');
  });

  test('keeps latest assessment per variant', () => {
    const assessments = [
      makeAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v1'),
      makeAssessment('Fixed', '2024-01-02T00:00:00', 'v1'), // latest for v1
    ];
    const summary = buildStatusSummary(assessments);
    expect(summary.dominant_status).toBe('Fixed');
    expect(summary.counts['Fixed']).toBe(1);
    expect(summary.counts['Pending Assessment']).toBeUndefined();
  });

  test('assessments without variant_id share one slot', () => {
    const assessments = [
      makeAssessment('Pending Assessment', '2024-01-01T00:00:00'),  // no variant
      makeAssessment('Fixed', '2024-01-02T00:00:00'),               // no variant, later
    ];
    const summary = buildStatusSummary(assessments);
    // Both share __no_variant__ → only Fixed (latest) counts
    expect(summary.dominant_status).toBe('Fixed');
    expect(Object.keys(summary.counts)).toHaveLength(1);
  });

  const makePkgAssessment = (
    simplified_status: string, timestamp: string, variant_id: string, packages: string[],
  ) => ({ ...makeAssessment(simplified_status, timestamp, variant_id), packages });

  test('ignores assessments on deprecated packages when current packages given', () => {
    // Active package is linux-yocto@6.6.129 (Pending). The deprecated
    // linux-yocto@6.6.122 (Not affected) is more recent but must not count.
    const assessments = [
      makePkgAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v1', ['linux-yocto@6.6.129']),
      makePkgAssessment('Not affected', '2024-02-01T00:00:00', 'v1', ['linux-yocto@6.6.122']),
    ];
    const summary = buildStatusSummary(assessments, ['linux-yocto@6.6.129']);
    expect(summary.dominant_status).toBe('Pending Assessment');
    expect(summary.counts['Not affected']).toBeUndefined();
  });

  test('keeps assessments without packages when current packages given', () => {
    const assessments = [
      makePkgAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v1', []),
    ];
    const summary = buildStatusSummary(assessments, ['linux-yocto@6.6.129']);
    expect(summary.dominant_status).toBe('Pending Assessment');
  });

  test('falls back to all assessments when none reference a current package', () => {
    // All packages are deprecated → do not collapse to "unknown".
    const assessments = [
      makePkgAssessment('Not affected', '2024-01-01T00:00:00', 'v1', ['linux-yocto@6.6.111']),
    ];
    const summary = buildStatusSummary(assessments, ['linux-yocto@6.6.129']);
    expect(summary.dominant_status).toBe('Not affected');
  });

  test('empty current packages disables filtering', () => {
    const assessments = [
      makePkgAssessment('Pending Assessment', '2024-01-01T00:00:00', 'v1', ['linux-yocto@6.6.129']),
      makePkgAssessment('Not affected', '2024-02-01T00:00:00', 'v2', ['linux-yocto@6.6.122']),
    ];
    const summary = buildStatusSummary(assessments, []);
    expect(summary.counts['Pending Assessment']).toBe(1);
    expect(summary.counts['Not affected']).toBe(1);
  });
});

describe('getTopStatusSummaryLabel', () => {
  test('returns all statuses when 2 or fewer', () => {
    const summary = buildStatusSummary([
      { id: 'a', vuln_id: 'CVE-1', packages: [], origin: '', status: 'Fixed', simplified_status: 'Fixed', timestamp: '2024-01-01T00:00:00', responses: [] }
    ]);
    expect(getTopStatusSummaryLabel(summary)).toBe('Fixed');
  });

  test('lists every status without any "+N more" placeholder', () => {
    const summary = {
      counts: { 'Exploitable': 1, 'Pending Assessment': 1, 'Fixed': 1 },
      ordered: [
        { status: 'Exploitable', count: 1 },
        { status: 'Pending Assessment', count: 1 },
        { status: 'Fixed', count: 1 },
      ],
      total_assessments: 3,
      dominant_status: 'Exploitable',
      has_active_status: true,
    };
    const label = getTopStatusSummaryLabel(summary);
    expect(label).toBe('Exploitable, Pending Assessment, Fixed');
    expect(label).not.toContain('more');
  });

  test('never truncates even with many statuses', () => {
    const summary = {
      counts: { 'A': 1, 'B': 1, 'C': 1, 'D': 1 },
      ordered: [
        { status: 'A', count: 1 },
        { status: 'B', count: 1 },
        { status: 'C', count: 1 },
        { status: 'D', count: 1 },
      ],
      total_assessments: 4,
      dominant_status: 'A',
      has_active_status: false,
    };
    const label = getTopStatusSummaryLabel(summary);
    expect(label).toBe('A, B, C, D');
    expect(label).not.toContain('more');
  });
});

describe('isVulnerabilityActive', () => {
  const makeVuln = (simplified_status: string, status_summary?: any) => ({
    id: 'CVE-1',
    aliases: [],
    related_vulnerabilities: [],
    namespace: '',
    found_by: [],
    datasource: '',
    packages: [],
    packages_current: [],
    variants: [],
    urls: [],
    texts: [],
    severity: { severity: 'unknown', min_score: 0, max_score: 0, cvss: [] },
    epss: { score: undefined, percentile: undefined },
    effort: { optimistic: null as any, likely: null as any, pessimistic: null as any },
    fix: { state: 'unknown' },
    simplified_status,
    assessments: [],
    status_summary,
  });

  test('returns false for Fixed', () => {
    expect(isVulnerabilityActive(makeVuln('Fixed') as any)).toBe(false);
  });

  test('returns false for Not affected', () => {
    expect(isVulnerabilityActive(makeVuln('Not affected') as any)).toBe(false);
  });

  test('returns false for unknown', () => {
    expect(isVulnerabilityActive(makeVuln('unknown') as any)).toBe(false);
  });

  test('returns true for Exploitable', () => {
    expect(isVulnerabilityActive(makeVuln('Exploitable') as any)).toBe(true);
  });

  test('returns true for Pending Assessment', () => {
    expect(isVulnerabilityActive(makeVuln('Pending Assessment') as any)).toBe(true);
  });

  test('uses status_summary when present', () => {
    const vuln = makeVuln('unknown', {
      counts: { 'Exploitable': 1 },
      ordered: [{ status: 'Exploitable', count: 1 }],
      total_assessments: 1,
      dominant_status: 'Exploitable',
      has_active_status: true,
    });
    expect(isVulnerabilityActive(vuln as any)).toBe(true);
  });
});

describe('isActiveStatus', () => {
  test('Fixed is not active', () => expect(isActiveStatus('Fixed')).toBe(false));
  test('Not affected is not active', () => expect(isActiveStatus('Not affected')).toBe(false));
  test('unknown is not active', () => expect(isActiveStatus('unknown')).toBe(false));
  test('Exploitable is active', () => expect(isActiveStatus('Exploitable')).toBe(true));
  test('Pending Assessment is active', () => expect(isActiveStatus('Pending Assessment')).toBe(true));
});

describe('getStatusSortIndex', () => {
  test('known statuses return expected index', () => {
    expect(getStatusSortIndex('unknown')).toBe(0);
    expect(getStatusSortIndex('Pending Assessment')).toBe(1);
    expect(getStatusSortIndex('Exploitable')).toBe(2);
    expect(getStatusSortIndex('Not affected')).toBe(3);
    expect(getStatusSortIndex('Fixed')).toBe(4);
  });

  test('unknown status returns length of order array', () => {
    expect(getStatusSortIndex('NonExistent')).toBe(5);
  });
});

describe('append_assessment via sort comparator', () => {
  const makeVuln = (id: string) => ({
    ...rawVuln({ id }),
    simplified_status: 'unknown',
    assessments: [],
  });

  test('append_assessment with two assessments triggers sort comparator', () => {
    const vulns = [makeVuln('CVE-2021-1')];
    const a1 = {
      vuln_id: 'CVE-2021-1', status: 'fixed', simplified_status: 'Fixed',
      timestamp: '2024-01-02T00:00:00', packages: [], responses: [], id: 'a1', origin: 'sbom',
    } as any;
    vulns[0].assessments = [a1];

    const a2 = {
      vuln_id: 'CVE-2021-1', status: 'affected', simplified_status: 'Exploitable',
      timestamp: '2024-01-01T00:00:00', packages: [], responses: [], id: 'a2', origin: 'sbom',
    } as any;

    const result = Vulnerabilities.append_assessment(vulns as any, a2);
    // a2 is earlier, a1 is later → sorted order [a2, a1] → latest is Fixed
    expect(result[0].assessments).toHaveLength(2);
    expect(result[0].assessments[0].id).toBe('a2'); // earlier first after sort
    expect(result[0].assessments[1].id).toBe('a1');
  });

  test('dominant status reflects highest-priority variant', () => {
    // enrich_with_assessments with two variants: Fixed and Exploitable
    // Exploitable has higher priority so it should be dominant
    const vuln = {
      ...rawVuln({ id: 'CVE-X' }),
      simplified_status: 'unknown',
      assessments: [],
    };
    const assessments = [
      {
        vuln_id: 'CVE-X',
        id: 'b1',
        status: 'fixed',
        simplified_status: 'Fixed',
        timestamp: '2024-01-01T00:00:00',
        packages: [],
        responses: [],
        variant_id: 'v1',
        origin: 'sbom',
      },
      {
        vuln_id: 'CVE-X',
        id: 'b2',
        status: 'affected',
        simplified_status: 'Exploitable',
        timestamp: '2024-01-01T00:00:00',
        packages: [],
        responses: [],
        variant_id: 'v2',
        origin: 'sbom',
      },
    ] as any[];

    const enriched = Vulnerabilities.enrich_with_assessments([vuln as any], assessments);
    expect(enriched[0].simplified_status).toBe('Exploitable');
  });
});
