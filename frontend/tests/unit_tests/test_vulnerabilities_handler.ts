
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
