import Assessments, { reconcileTargetPairs } from "../../src/handlers/assessments";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

const response = (data: unknown = {}, ok = true, status = 200) => ({
  ok,
  status,
  json: async () => data,
}) as Response;

const makeAssessment = (overrides: Record<string, unknown> = {}) => ({
  id: "a1",
  vuln_id: "CVE-2026-0001",
  status: "not_affected",
  timestamp: "2026-08-19T00:00:00Z",
  targets: [],
  ...overrides,
});

beforeEach(() => {
  fetchSpy.mockReset();
});

describe("Assessments target/reconcile handlers", () => {
  test("reconcileTargetPairs preserves sparse existing coverage", () => {
    const existing = [
      { variant_id: "variant-a", package: "openssl@1", outdated: false },
      { variant_id: "variant-b", package: "zlib@1", outdated: false },
    ];

    expect(reconcileTargetPairs(
      existing, ["openssl@1", "zlib@1"], ["variant-a", "variant-b"],
    )).toEqual([
      { package: "openssl@1", variant_id: "variant-a" },
      { package: "zlib@1", variant_id: "variant-b" },
    ]);
  });

  test("reconcileTargetPairs expands a newly selected variant", () => {
    const existing = [
      { variant_id: "variant-a", package: "openssl@1", outdated: false },
      { variant_id: "variant-b", package: "zlib@1", outdated: false },
    ];

    expect(reconcileTargetPairs(
      existing, ["openssl@1", "zlib@1"], ["variant-a", "variant-b", "variant-c"],
    )).toEqual([
      { package: "openssl@1", variant_id: "variant-a" },
      { package: "openssl@1", variant_id: "variant-c" },
      { package: "zlib@1", variant_id: "variant-b" },
      { package: "zlib@1", variant_id: "variant-c" },
    ]);
  });

  test("listByVuln requests the vulnerability-scoped endpoint", async () => {
    fetchSpy.mockResolvedValueOnce(response([makeAssessment({ id: "a1" })]));

    const assessments = await Assessments.listByVuln("CVE-2026-0001");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/vulnerabilities/CVE-2026-0001/assessments");
    expect(assessments[0].id).toBe("a1");
  });

  test("listByVuln includes the project_id filter when provided", async () => {
    fetchSpy.mockResolvedValueOnce(response([]));

    await Assessments.listByVuln("CVE-2026-0001", "project 1");

    expect(fetchSpy.mock.calls[0][0]).toContain("project_id=project+1");
  });

  test("listByVuln throws when the response is not ok", async () => {
    fetchSpy.mockResolvedValueOnce(response({}, false, 500));

    await expect(Assessments.listByVuln("CVE-2026-0001")).rejects.toThrow("Failed to load assessments: 500");
  });

  test("listForReview requests the review endpoint with filters", async () => {
    fetchSpy.mockResolvedValueOnce(response([makeAssessment({ id: "a2" })]));

    const assessments = await Assessments.listForReview("variant-1", "project-1", "ai");

    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain("/api/reviews/assessments");
    expect(url).toContain("variant_id=variant-1");
    expect(url).toContain("project_id=project-1");
    expect(url).toContain("origin=ai");
    expect(assessments[0].id).toBe("a2");
  });

  test("get fetches a single assessment by id", async () => {
    fetchSpy.mockResolvedValueOnce(response(makeAssessment({ id: "a1" })));

    const assessment = await Assessments.get("a1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1");
    expect((assessment as { id: string }).id).toBe("a1");
  });

  test("reconcile posts the desired state and returns the summary", async () => {
    fetchSpy.mockResolvedValueOnce(response({ status: "success", updated: [{ id: "a1" }], created: [], deleted: [] }));

    const result = await Assessments.reconcile("a1", { status: "not_affected" });

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1/reconcile");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ status: "not_affected" }),
    }));
    expect(result.status).toBe("success");
  });

  test("reconcile throws with the server error message on failure", async () => {
    fetchSpy.mockResolvedValueOnce(response({ error: "conflict" }, false, 409));

    await expect(Assessments.reconcile("a1", {})).rejects.toThrow("conflict");
  });

  test("remove deletes the assessment", async () => {
    fetchSpy.mockResolvedValueOnce(response({ status: "success" }));

    await Assessments.remove("a1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "DELETE" }));
  });

  test("remove throws when the response is not ok", async () => {
    fetchSpy.mockResolvedValueOnce(response({}, false, 404));

    await expect(Assessments.remove("a1")).rejects.toThrow("Failed to delete assessment: 404");
  });

  test("approveAi posts to the approve endpoint and returns assessments", async () => {
    fetchSpy.mockResolvedValueOnce(response({
      assessments: [{ id: "a1", vuln_id: "CVE-2026-0001", status: "not_affected", timestamp: "2026-08-19T00:00:00Z" }],
    }));

    const assessments = await Assessments.approveAi("a1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1/approve");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST" }));
    expect(assessments[0].id).toBe("a1");
  });

  test("rejectAi posts to the reject endpoint and returns deleted ids", async () => {
    fetchSpy.mockResolvedValueOnce(response({ deleted: ["a1"] }));

    const deleted = await Assessments.rejectAi("a1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1/reject");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST" }));
    expect(deleted).toEqual(["a1"]);
  });

  test("createBatch posts every item in a single request and returns the batch result", async () => {
    fetchSpy.mockResolvedValueOnce(response({
      status: "success",
      assessments: [],
      count: 2,
      vuln_count: 1,
    }));

    const items = [
      {
        vuln_id: "CVE-2026-0001",
        packages: ["pkg-a"],
        status: "not_affected",
        variant_ids: ["variant-a", "variant-b"],
      },
      { vuln_id: "CVE-2026-0001", packages: ["pkg-b"], status: "not_affected" },
    ];
    const result = await Assessments.createBatch(items);

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/batch");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ assessments: items }),
    }));
    expect(result.count).toBe(2);
  });

  test("createBatch throws with the backend detail when the batch is rejected", async () => {
    fetchSpy.mockResolvedValueOnce(response({
      status: "error",
      errors: [{ vuln_id: "CVE-2026-0001", error: "variant_id is required" }],
      error_count: 1,
    }, false, 400));

    await expect(Assessments.createBatch([
      { vuln_id: "CVE-2026-0001", packages: ["pkg-a"], status: "not_affected" },
    ])).rejects.toThrow("variant_id is required");
  });

  test("createBatch throws the status code when the failure body has no error text", async () => {
    fetchSpy.mockResolvedValueOnce(response({}, false, 500));

    await expect(Assessments.createBatch([
      { vuln_id: "CVE-2026-0001", packages: ["pkg-a"], status: "not_affected" },
    ])).rejects.toThrow("HTTP 500");
  });
});
