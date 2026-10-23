import { describeReviewSummary, verdictOf } from "../../src/handlers/assessmentReviews";
import type { AssessmentReview } from "../../src/handlers/assessmentReviews";

const review = (verdict: "agrees" | "differs", isStale = false): AssessmentReview => ({
  id: "review",
  assessment_id: "assessment",
  variant_id: "variant",
  package: "openssl@3.0.8",
  status: "not_affected",
  status_notes: "",
  justification: "",
  impact_statement: "",
  workaround: "",
  responses: [],
  rationale: "because",
  timestamp: "2026-08-26T00:00:00Z",
  verdict,
  is_stale: isStale,
});

describe("verdictOf", () => {
  test("reports none when the target has no review", () => {
    expect(verdictOf(undefined)).toBe("none");
  });

  test.each(["agrees", "differs"] as const)("preserves a current %s verdict", verdict => {
    expect(verdictOf(review(verdict))).toBe(verdict);
  });

  test.each(["agrees", "differs"] as const)("reports stale before the underlying %s verdict", verdict => {
    expect(verdictOf(review(verdict, true))).toBe("stale");
  });
});

describe("describeReviewSummary", () => {
  test.each([
    [{ total: 2, reviewed: 0, agrees: 0, differs: 0, stale: 0 }, "Not reviewed"],
    [{ total: 3, reviewed: 3, agrees: 2, differs: 1, stale: 0 }, "2 agree · 1 differ"],
    [{ total: 3, reviewed: 1, agrees: 1, differs: 0, stale: 0 }, "1 agree · 2 not reviewed"],
    [{ total: 2, reviewed: 2, agrees: 1, differs: 0, stale: 1 }, "1 agree · 1 stale"],
    [{ total: 1, reviewed: 1, agrees: 0, differs: 1, stale: 0 }, "1 differ"],
  ])("formats the server-provided counts %j", (summary, expected) => {
    expect(describeReviewSummary(summary)).toBe(expected);
  });
});
