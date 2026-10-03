import { describe, expect, it } from "vitest";

import { activeFilterCount, parseFilters, toQuery, writeFilters } from "./filters";

describe("finding filters in the URL", () => {
  it("round-trips structured filters and keeps other params", () => {
    const base = new URLSearchParams("finding=abc&tab=items");
    const filters = parseFilters(new URLSearchParams("status=corroborated&status=unverified&domain=example.org&captured_from=2026-01-01"));
    const next = writeFilters(base, filters);
    expect(next.getAll("status")).toEqual(["corroborated", "unverified"]);
    expect(next.get("domain")).toBe("example.org");
    expect(next.get("finding")).toBe("abc");
    expect(parseFilters(next)).toEqual(filters);
  });

  it("never writes the free-text keyword into the URL", () => {
    const next = writeFilters(new URLSearchParams(), parseFilters(new URLSearchParams()));
    expect(next.has("q")).toBe(false);
    expect(toQuery(parseFilters(new URLSearchParams()), "secret words").q).toBe("secret words");
  });

  it("drops invalid values instead of failing", () => {
    const filters = parseFilters(new URLSearchParams("country=gbr&captured_from=yesterday&status=confirmed_by_source"));
    expect(filters.country).toBeUndefined();
    expect(filters.captured_from).toBeUndefined();
    expect(filters.status).toEqual(["confirmed_by_source"]);
  });

  it("counts active filters and converts dates to UTC day bounds", () => {
    const filters = parseFilters(new URLSearchParams("status=contradicted&published_to=2026-03-31&sort=created"));
    expect(activeFilterCount(filters)).toBe(2);
    expect(toQuery(filters, "").published_to).toBe("2026-03-31T23:59:59Z");
  });
});
