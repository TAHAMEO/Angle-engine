import { describe, expect, it } from "vitest";

import type { EventOut } from "@/lib/api/types";

import { bucketize } from "./density-chart";

const event = (iso: string, status = "unverified") => ({ occurred_start: iso, verification_status: status }) as EventOut;

describe("bucketize", () => {
  it("groups short spans by month and fills gaps", () => {
    const { buckets, unit } = bucketize([event("2026-01-05T00:00:00Z"), event("2026-03-20T00:00:00Z", "contradicted")]);
    expect(unit).toBe("month");
    expect(buckets.map((b) => b.key)).toEqual(["2026-01", "2026-02", "2026-03"]);
    expect(buckets[2]).toEqual({ key: "2026-03", count: 1, contradicted: 1 });
  });

  it("groups long spans by year", () => {
    const { buckets, unit } = bucketize([event("2016-02-14T00:00:00Z"), event("2026-06-14T00:00:00Z")]);
    expect(unit).toBe("year");
    expect(buckets).toHaveLength(11);
  });

  it("handles no events", () => {
    expect(bucketize([]).buckets).toEqual([]);
  });
});
