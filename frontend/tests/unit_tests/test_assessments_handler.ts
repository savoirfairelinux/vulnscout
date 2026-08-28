
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Assessments, { asAssessment, asStringArray, removeDuplicateAssessments, isMultiTargetGroup } from '../../src/handlers/assessments';
import type { AssessmentTarget } from '../../src/handlers/assessments';

describe('asStringArray', () => {
  test('non array returns empty array', () => {
    expect(asStringArray(123 as any)).toEqual([]);
    expect(asStringArray(null as any)).toEqual([]);
    expect(asStringArray({} as any)).toEqual([]);
  });

  test('filters to only strings', () => {
    const input = ['a', 1, null, 'b', { x: 1 }, 'c'];
    expect(asStringArray(input as any)).toEqual(['a', 'b', 'c']);
  });

  test('empty array returns empty array', () => {
    expect(asStringArray([])).toEqual([]);
  });
});

describe('asAssessment validation', () => {
  test('reject non object', () => {
    expect(asAssessment(42 as any)).toEqual([]);
  });

  test('reject missing id', () => {
    const data = { vuln_id: 'CVE-X', status: 'fixed', timestamp: '2024-01-01T00:00:00' };
    expect(asAssessment(data as any)).toEqual([]);
  });

  test('reject missing vuln_id', () => {
    const data = { id: '1', status: 'fixed', timestamp: '2024-01-01T00:00:00' };
    expect(asAssessment(data as any)).toEqual([]);
  });

  test('reject missing status', () => {
    const data = { id: '1', vuln_id: 'CVE-X', timestamp: '2024-01-01T00:00:00' };
    expect(asAssessment(data as any)).toEqual([]);
  });

  test('reject missing timestamp', () => {
    const data = { id: '1', vuln_id: 'CVE-X', status: 'fixed' };
    expect(asAssessment(data as any)).toEqual([]);
  });

  test('unknown status simplified_status invalid marker', () => {
    const data = { id: '1', vuln_id: 'CVE-X', status: 'weird_status', timestamp: '2024-01-01T00:00:00', packages: ['pkg@1'], responses: [] };
    const assessed = asAssessment(data as any) as any;
    expect(Array.isArray(assessed)).toBe(false);
    expect(assessed.simplified_status.startsWith('[invalid status]')).toBe(true);
  });

  test('known statuses map simplified_status', () => {
    const statuses = ['under_investigation','in_triage','false_positive','not_affected','exploitable','affected','resolved','fixed','resolved_with_pedigree'];
    statuses.forEach(st => {
      const data = { id: `k-${st}`, vuln_id: 'CVE-Z', status: st, timestamp: '2024-03-01T00:00:00', packages: [], responses: [] };
      const assessed = asAssessment(data as any) as any;
      expect(Array.isArray(assessed)).toBe(false);
      expect(assessed.simplified_status).not.toContain('[invalid status]');
    });
  });

  test('non-array packages/responses become empty arrays', () => {
    const data = { id: 'na1', vuln_id: 'CVE-NA', status: 'fixed', timestamp: '2024-04-01T00:00:00', packages: 'str' as any, responses: 5 as any };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.packages).toEqual([]);
    expect(assessed.responses).toEqual([]);
  });
});

describe('asAssessment optional fields', () => {
  test('sets optional string fields when present', () => {
    const data = {
      id: '2',
      vuln_id: 'CVE-Y',
      status: 'fixed',
      timestamp: '2024-02-02T00:00:00',
      packages: ['pkg@2', 3, null, 'pkg2@3'] as any,
      responses: ['resp1', { a: 1 }, 'resp2'] as any,
      status_notes: 'note',
      justification: 'justification text',
      impact_statement: 'impact',
      workaround: 'do something',
      workaround_timestamp: '2024-02-03T00:00:00',
      last_update: '2024-02-04T00:00:00'
    };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.simplified_status).toEqual('Fixed');
    expect(assessed.status_notes).toEqual('note');
    expect(assessed.justification).toEqual('justification text');
    expect(assessed.impact_statement).toEqual('impact');
    expect(assessed.workaround).toEqual('do something');
    expect(assessed.packages).toEqual(['pkg@2', 'pkg2@3']);
    expect(assessed.responses).toEqual(['resp1', 'resp2']);
    expect(assessed.workaround_timestamp).toEqual('2024-02-03T00:00:00');
    expect(assessed.last_update).toEqual('2024-02-04T00:00:00');
  });

  test('optional fields absent remain undefined', () => {
    const data = { id: '3', vuln_id: 'CVE-A', status: 'affected', timestamp: '2024-05-01T00:00:00', packages: [], responses: [] };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.status_notes).toBeUndefined();
    expect(assessed.justification).toBeUndefined();
    expect(assessed.impact_statement).toBeUndefined();
    expect(assessed.workaround).toBeUndefined();
    expect(assessed.workaround_timestamp).toBeUndefined();
    expect(assessed.last_update).toBeUndefined();
  });

  test('sets origin from data when string', () => {
    const data = { id: '4', vuln_id: 'CVE-B', status: 'fixed', timestamp: '2024-06-01T00:00:00', packages: [], responses: [], origin: 'custom' };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.origin).toBe('custom');
  });

  test('sets vuln_texts when object and not null', () => {
    const data = { id: '5', vuln_id: 'CVE-C', status: 'fixed', timestamp: '2024-07-01T00:00:00', packages: [], responses: [], vuln_texts: [{ title: 'val' }] };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.vuln_texts).toEqual([{ title: 'val' }]);
  });

  test('ignores null vuln_texts', () => {
    const data = { id: '6', vuln_id: 'CVE-D', status: 'fixed', timestamp: '2024-08-01T00:00:00', packages: [], responses: [], vuln_texts: null };
    const assessed = asAssessment(data as any) as any;
    expect(assessed.vuln_texts).toBeUndefined();
  });

  test('parses variant_ids when present', () => {
    const data = {
      id: 'a1', vuln_id: 'CVE-2020-1', status: 'fixed',
      timestamp: '2021-01-02T00:00:00Z',
      packages: ['pkgA@1.0', 'pkgB@1.0'],
      variant_ids: ['v1', 'v2'],
    };
    const parsed = asAssessment(data as any) as any;
    expect(parsed.variant_ids).toEqual(['v1', 'v2']);
  });

  test('defaults variant_ids to an empty array when absent', () => {
    const data = {
      id: 'a1', vuln_id: 'CVE-2020-1', status: 'fixed',
      timestamp: '2021-01-02T00:00:00Z', packages: [],
    };
    const parsed = asAssessment(data as any) as any;
    expect(parsed.variant_ids).toEqual([]);
  });
});

describe('removeDuplicateAssessments', () => {
  const makeAssessment = (overrides: any = {}) => ({
    id: 'a1',
    vuln_id: 'CVE-2024-1',
    packages: ['pkg@1.0'],
    origin: 'sbom',
    status: 'fixed',
    simplified_status: 'Fixed',
    timestamp: '2024-01-01T00:00:00',
    responses: [],
    variant_id: undefined,
    ...overrides,
  });

  test('returns same assessments when no duplicates', () => {
    const a1 = makeAssessment({ id: 'a1', vuln_id: 'CVE-1', packages: ['pkg@1'] });
    const a2 = makeAssessment({ id: 'a2', vuln_id: 'CVE-2', packages: ['pkg@1'] });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(2);
  });

  test('removes exact duplicate assessment', () => {
    const a1 = makeAssessment({ id: 'a1' });
    const a2 = makeAssessment({ id: 'a2' }); // same content, different id
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(1);
  });

  test('does not deduplicate when packages differ', () => {
    const a1 = makeAssessment({ packages: ['pkg@1.0'] });
    const a2 = makeAssessment({ packages: ['pkg@2.0'] });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(2);
  });

  test('does not deduplicate when status differs', () => {
    const a1 = makeAssessment({ status: 'fixed' });
    const a2 = makeAssessment({ status: 'affected' });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(2);
  });

  test('key includes descriptions so differing notes are not deduplicated', () => {
    const a1 = makeAssessment({ status_notes: 'note1' });
    const a2 = makeAssessment({ status_notes: 'note2' });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(2);
  });

  test('key includes variant_id', () => {
    const a1 = makeAssessment({ variant_id: 'v1' });
    const a2 = makeAssessment({ variant_id: 'v2' });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(2);
  });

  test('sorts packages before building key so order does not matter', () => {
    const a1 = makeAssessment({ packages: ['pkg@1', 'pkg@2'] });
    const a2 = makeAssessment({ packages: ['pkg@2', 'pkg@1'] });
    expect(removeDuplicateAssessments([a1, a2])).toHaveLength(1);
  });

  test('empty array returns empty array', () => {
    expect(removeDuplicateAssessments([])).toEqual([]);
  });
});

describe('isMultiTargetGroup', () => {
  const makeTarget = (overrides: Partial<AssessmentTarget> = {}): AssessmentTarget => ({
    variant_id: 'v1',
    package: 'pkg@1.0',
    outdated: false,
    assessment_id: 'a1',
    ...overrides,
  });

  test('single target is not a group', () => {
    expect(isMultiTargetGroup([makeTarget()])).toBe(false);
  });

  test('two or more targets is a group', () => {
    expect(isMultiTargetGroup([makeTarget({ assessment_id: 'a1' }), makeTarget({ assessment_id: 'a2' })])).toBe(true);
  });

  test('empty targets is not a group', () => {
    expect(isMultiTargetGroup([])).toBe(false);
  });
});

describe('Assessments API', () => {
  beforeEach(() => {
    fetchMock.resetMocks();
  });

  const sampleAssessmentData = [
    { id: 'a1', vuln_id: 'CVE-1', status: 'fixed', timestamp: '2024-01-01T00:00:00', packages: [], responses: [] },
    { id: 'a2', vuln_id: 'CVE-2', status: 'affected', timestamp: '2024-02-01T00:00:00', packages: [], responses: [] },
  ];

  test('list returns parsed assessments', async () => {
    fetchMock.mockResponseOnce(JSON.stringify(sampleAssessmentData));
    const result = await Assessments.list();
    expect(result).toHaveLength(2);
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('format')).toBe('compact');
  });

  test('list with variantId sets variant_id param', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.list('var-1');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('variant_id')).toBe('var-1');
    expect(url.searchParams.has('project_id')).toBe(false);
  });

  test('list with projectId sets project_id param when no variantId', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.list(undefined, 'proj-1');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('project_id')).toBe('proj-1');
    expect(url.searchParams.has('variant_id')).toBe(false);
  });

  test('list deduplicates returned assessments', async () => {
    const dup = { id: 'a1', vuln_id: 'CVE-1', status: 'fixed', timestamp: '2024-01-01T00:00:00', packages: [], responses: [] };
    fetchMock.mockResponseOnce(JSON.stringify([dup, dup]));
    const result = await Assessments.list();
    expect(result).toHaveLength(1);
  });

  test('listReview returns parsed assessments', async () => {
    fetchMock.mockResponseOnce(JSON.stringify(sampleAssessmentData));
    const result = await Assessments.listReview();
    expect(result).toHaveLength(2);
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toContain('/review');
  });

  test('listReview with variantId sets param', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.listReview('var-2');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('variant_id')).toBe('var-2');
  });

  test('listReview with projectId sets param when no variantId', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.listReview(undefined, 'proj-2');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('project_id')).toBe('proj-2');
  });

  test('listReviewTimeEstimates returns array', async () => {
    const data = [{ vuln_id: 'CVE-1', optimistic: 1, likely: 2, pessimistic: 3, optimistic_iso: 'PT1H', likely_iso: 'PT2H', pessimistic_iso: 'PT3H' }];
    fetchMock.mockResponseOnce(JSON.stringify(data));
    const result = await Assessments.listReviewTimeEstimates('var-1');
    expect(result).toHaveLength(1);
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('variant_id')).toBe('var-1');
  });

  test('listReviewTimeEstimates returns empty array for non-array response', async () => {
    fetchMock.mockResponseOnce(JSON.stringify(null));
    const result = await Assessments.listReviewTimeEstimates();
    expect(result).toEqual([]);
  });

  test('listReviewTimeEstimates with projectId sets param', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.listReviewTimeEstimates(undefined, 'proj-3');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('project_id')).toBe('proj-3');
  });

  test('listReviewCustomCvss returns array', async () => {
    const data = [{ vuln_id: 'CVE-1', version: '3.1', vector_string: 'CVSS:3.1/AV:N', base_score: 7.5, author: 'user' }];
    fetchMock.mockResponseOnce(JSON.stringify(data));
    const result = await Assessments.listReviewCustomCvss('var-1');
    expect(result).toHaveLength(1);
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toContain('custom-cvss');
  });

  test('listReviewCustomCvss returns empty array for non-array response', async () => {
    fetchMock.mockResponseOnce(JSON.stringify('not an array'));
    const result = await Assessments.listReviewCustomCvss();
    expect(result).toEqual([]);
  });

  test('listReviewCustomCvss with projectId sets param', async () => {
    fetchMock.mockResponseOnce(JSON.stringify([]));
    await Assessments.listReviewCustomCvss(undefined, 'proj-4');
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('project_id')).toBe('proj-4');
  });

});

describe('asAssessment outdated flag', () => {
  const base = {
    id: 'out-1',
    vuln_id: 'CVE-OUTDATED',
    status: 'not_affected',
    timestamp: '2024-01-01T00:00:00',
    packages: ['firefox@1.0'],
    responses: [],
    origin: 'custom',
    variant_id: 'v-uuid',
  };

  test('outdated=true and superseded_by parsed when present', () => {
    const data = { ...base, outdated: true, superseded_by: ['firefox@2.0'] };
    const result = asAssessment(data as any) as any;
    expect(result.outdated).toBe(true);
    expect(result.superseded_by).toEqual(['firefox@2.0']);
  });

  test('outdated=false when server returns false leaves field absent', () => {
    // outdated:false is the default — we don't store it. An explicit empty
    // superseded_by array is stored as [] (valid array, just empty).
    const data = { ...base, outdated: false, superseded_by: [] };
    const result = asAssessment(data as any) as any;
    expect(result.outdated).toBeUndefined();
    expect(result.superseded_by).toEqual([]);
  });

  test('outdated absent when server omits it', () => {
    const result = asAssessment(base as any) as any;
    expect(result.outdated).toBeUndefined();
    expect(result.superseded_by).toBeUndefined();
  });

  test('superseded_by non-string entries are filtered out', () => {
    const data = { ...base, outdated: true, superseded_by: ['firefox@2.0', 42, null, 'pkg@3.0'] };
    const result = asAssessment(data as any) as any;
    expect(result.superseded_by).toEqual(['firefox@2.0', 'pkg@3.0']);
  });

  test('superseded_by non-array is ignored', () => {
    const data = { ...base, outdated: true, superseded_by: 'firefox@2.0' };
    const result = asAssessment(data as any) as any;
    expect(result.superseded_by).toBeUndefined();
  });

  test('stale_packages and superseded_map parsed when present', () => {
    const data = {
      ...base,
      packages: ['firefox@1.0', 'chrome@1.0'],
      outdated: true,
      superseded_by: ['firefox@2.0'],
      stale_packages: ['firefox@1.0'],
      superseded_map: { 'firefox@1.0': ['firefox@2.0'] },
    };
    const result = asAssessment(data as any) as any;
    expect(result.stale_packages).toEqual(['firefox@1.0']);
    expect(result.superseded_map).toEqual({ 'firefox@1.0': ['firefox@2.0'] });
  });

  test('stale_packages non-string entries are filtered out', () => {
    const data = { ...base, outdated: true, stale_packages: ['firefox@1.0', 7, null, 'pkg@3.0'] };
    const result = asAssessment(data as any) as any;
    expect(result.stale_packages).toEqual(['firefox@1.0', 'pkg@3.0']);
  });

  test('superseded_map array or non-object is ignored', () => {
    const data = { ...base, outdated: true, superseded_map: ['firefox@2.0'] };
    const result = asAssessment(data as any) as any;
    expect(result.superseded_map).toBeUndefined();
  });

  test('superseded_map non-array values are filtered out', () => {
    const data = {
      ...base,
      outdated: true,
      superseded_map: { 'firefox@1.0': ['firefox@2.0'], 'bad@1.0': 'not-an-array' },
    };
    const result = asAssessment(data as any) as any;
    expect(result.superseded_map).toEqual({ 'firefox@1.0': ['firefox@2.0'] });
  });
});
