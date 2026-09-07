import { summarizeReviews, describeReviewSummary } from "../../src/handlers/assessmentReviews";
import type { AssessmentReview } from "../../src/handlers/assessmentReviews";

const review = (
  assessmentId: string,
  verdict: "agrees" | "differs",
  isStale = false,
): AssessmentReview => ({
  id: `r-${assessmentId}`,
  assessment_id: assessmentId,
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

describe("summarizeReviews", () => {
  test("reports nothing reviewed when the group has no reviews", () => {
    const summary = summarizeReviews(["a1", "a2"], {});

    expect(summary).toEqual({ total: 2, reviewed: 0, agrees: 0, differs: 0, stale: 0 });
    expect(describeReviewSummary(summary)).toBe("Not reviewed");
  });

  test("counts each member independently rather than letting one speak for all", () => {
    const summary = summarizeReviews(["a1", "a2", "a3"], {
      a1: review("a1", "agrees"),
      a2: review("a2", "differs"),
      a3: review("a3", "agrees"),
    });

    expect(summary).toEqual({ total: 3, reviewed: 3, agrees: 2, differs: 1, stale: 0 });
    expect(describeReviewSummary(summary)).toBe("2 agree · 1 differ");
  });

  test("surfaces members that have not been reviewed yet", () => {
    const summary = summarizeReviews(["a1", "a2", "a3"], { a1: review("a1", "agrees") });

    expect(summary.reviewed).toBe(1);
    expect(describeReviewSummary(summary)).toBe("1 agree · 2 not reviewed");
  });

  test("a stale review counts as stale, not as its underlying verdict", () => {
    const summary = summarizeReviews(["a1", "a2"], {
      a1: review("a1", "agrees", true),
      a2: review("a2", "agrees"),
    });

    expect(summary).toEqual({ total: 2, reviewed: 2, agrees: 1, differs: 0, stale: 1 });
    expect(describeReviewSummary(summary)).toBe("1 agree · 1 stale");
  });

  test("an ungrouped assessment is just a group of one", () => {
    const summary = summarizeReviews(["a1"], { a1: review("a1", "differs") });

    expect(summary).toEqual({ total: 1, reviewed: 1, agrees: 0, differs: 1, stale: 0 });
  });
});
