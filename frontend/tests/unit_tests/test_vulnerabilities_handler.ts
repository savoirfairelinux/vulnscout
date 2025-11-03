
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

import Vulnerabilities from '../../src/handlers/vulnerabilities';

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
        status: 'unknown',
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
    expect(cve1?.status).toBe('resolved');
    expect(cve1?.simplified_status).toBe('closed');
    expect(cve1?.assessments).toHaveLength(3);
    // Assessments should be sorted by timestamp
    expect(cve1?.assessments[0].timestamp).toBe('2023-11-03T10:00:00Z');
    expect(cve1?.assessments[1].timestamp).toBe('2023-11-03T11:00:00Z');
    expect(cve1?.assessments[2].timestamp).toBe('2023-11-03T12:00:00Z');

    // CVE-2021-2 should have single assessment
    const cve2 = enriched.find((v: any) => v.id === 'CVE-2021-2');
    expect(cve2?.status).toBe('affected');
    expect(cve2?.simplified_status).toBe('open');
    expect(cve2?.assessments).toHaveLength(1);

    // CVE-2021-3 should remain unchanged
    const cve3 = enriched.find((v: any) => v.id === 'CVE-2021-3');
    expect(cve3?.status).toBe('unknown');
    expect(cve3?.simplified_status).toBe('unknown');
    expect(cve3?.assessments).toHaveLength(0);
  });

  test('handles empty assessments list', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        status: 'unknown',
        simplified_status: 'unknown',
        assessments: []
      }
    ];

    const enriched = Vulnerabilities.enrich_with_assessments(vulns, []);
    expect(enriched[0].status).toBe('unknown');
    expect(enriched[0].assessments).toHaveLength(0);
  });

  test('handles vulnerability with empty assessment array', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        status: 'unknown',
        simplified_status: 'unknown',
        assessments: []
      }
    ];

    // This simulates the case where no assessments exist for the vulnerability
    const enriched = Vulnerabilities.enrich_with_assessments(vulns, []);
    expect(enriched[0].status).toBe('unknown');
  });
});

describe('append_assessment', () => {
  test('appends assessment to matching vulnerability', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        status: 'unknown',
        simplified_status: 'unknown',
        assessments: []
      },
      {
        ...rawVuln({ id: 'CVE-2021-2' }),
        status: 'unknown',
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
    expect(cve1?.status).toBe('investigating');
    expect(cve1?.simplified_status).toBe('open');
    expect(cve1?.assessments).toHaveLength(1);
    
    const cve2 = result.find((v: any) => v.id === 'CVE-2021-2');
    expect(cve2?.status).toBe('unknown');
    expect(cve2?.assessments).toHaveLength(0);
  });
});

describe('append_cvss', () => {
  test('appends CVSS to matching vulnerability', () => {
    const vulns = [
      {
        ...rawVuln({ id: 'CVE-2021-1' }),
        status: 'unknown',
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
        status: 'unknown',
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
        status: 'unknown',
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
