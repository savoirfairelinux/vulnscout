
import { asAssessment, asStringArray } from '../../src/handlers/assessments';

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
});
