import Assessments from "../../src/handlers/assessments";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

const response = (data: unknown = {}, ok = true, status = 200) => ({
  ok,
  status,
  json: async () => data,
}) as Response;

beforeEach(() => {
  fetchSpy.mockReset();
});

describe("Assessments group handlers", () => {
  test("listGroups requests the grouped endpoint for the vulnerability", async () => {
    fetchSpy.mockResolvedValueOnce(response([{ group_id: "g1", targets: [], assessment_ids: ["a1"] }]));

    const groups = await Assessments.listGroups("CVE-2026-0001");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/vulnerabilities/CVE-2026-0001/assessment-groups");
    expect(groups[0].group_id).toBe("g1");
  });

  test("listGroups includes the project_id filter when provided", async () => {
    fetchSpy.mockResolvedValueOnce(response([]));

    await Assessments.listGroups("CVE-2026-0001", "project 1");

    expect(fetchSpy.mock.calls[0][0]).toContain("project_id=project+1");
  });

  test("listGroups throws when the response is not ok", async () => {
    fetchSpy.mockResolvedValueOnce(response({}, false, 500));

    await expect(Assessments.listGroups("CVE-2026-0001")).rejects.toThrow("Failed to load assessment groups: 500");
  });

  test("listReviewGroups requests the review endpoint with filters", async () => {
    fetchSpy.mockResolvedValueOnce(response([{ group_id: "g2", targets: [], assessment_ids: ["a2"] }]));

    const groups = await Assessments.listReviewGroups("variant-1", "project-1", "ai");

    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain("/api/reviews/assessment-groups");
    expect(url).toContain("variant_id=variant-1");
    expect(url).toContain("project_id=project-1");
    expect(url).toContain("origin=ai");
    expect(groups[0].group_id).toBe("g2");
  });

  test("getGroup fetches a single group by id", async () => {
    fetchSpy.mockResolvedValueOnce(response({ group_id: "g1", targets: [], assessment_ids: ["a1"] }));

    const group = await Assessments.getGroup("g1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessment-groups/g1");
    expect(group.group_id).toBe("g1");
  });

  test("reconcileGroup posts the desired state and returns the updated group", async () => {
    fetchSpy.mockResolvedValueOnce(response({ group_id: "g1", targets: [], assessment_ids: ["a1"] }));

    const group = await Assessments.reconcileGroup("g1", { status: "not_affected" });

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessment-groups/g1/reconcile");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ status: "not_affected" }),
    }));
    expect(group.group_id).toBe("g1");
  });

  test("reconcileGroup throws with the server error message on failure", async () => {
    fetchSpy.mockResolvedValueOnce(response({ error: "conflict" }, false, 409));

    await expect(Assessments.reconcileGroup("g1", {})).rejects.toThrow("conflict");
  });

  test("deleteGroup returns the deleted assessment ids", async () => {
    fetchSpy.mockResolvedValueOnce(response({ status: "success", deleted_ids: ["a1", "a2"] }));

    const deletedIds = await Assessments.deleteGroup("g1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessment-groups/g1");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "DELETE" }));
    expect(deletedIds).toEqual(["a1", "a2"]);
  });

  test("approveAiGroup posts to the group approve endpoint and returns assessments", async () => {
    fetchSpy.mockResolvedValueOnce(response({
      assessments: [{ id: "a1", vuln_id: "CVE-2026-0001", status: "not_affected", timestamp: "2026-08-19T00:00:00Z" }],
    }));

    const assessments = await Assessments.approveAiGroup("g1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessment-groups/g1/approve");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST" }));
    expect(assessments[0].id).toBe("a1");
  });

  test("rejectAiGroup posts to the group reject endpoint and returns deleted ids", async () => {
    fetchSpy.mockResolvedValueOnce(response({ deleted: ["a1", "a2"] }));

    const deleted = await Assessments.rejectAiGroup("g1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessment-groups/g1/reject");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST" }));
    expect(deleted).toEqual(["a1", "a2"]);
  });

  test("promoteToGroup posts to the assessment group endpoint and returns the group id", async () => {
    fetchSpy.mockResolvedValueOnce(response({ group_id: "g3" }));

    const groupId = await Assessments.promoteToGroup("a1");

    expect(fetchSpy.mock.calls[0][0]).toContain("/api/assessments/a1/group");
    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({ method: "POST" }));
    expect(groupId).toBe("g3");
  });

  test("createBatch posts every item in a single request and returns the batch result", async () => {
    fetchSpy.mockResolvedValueOnce(response({
      status: "success",
      assessments: [],
      count: 2,
      vuln_count: 1,
    }));

    const items = [
      { vuln_id: "CVE-2026-0001", packages: ["pkg-a"], status: "not_affected" },
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
