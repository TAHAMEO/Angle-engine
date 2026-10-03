import { describe, expect, it } from "vitest";

import { safeNext } from "./session";

describe("safeNext", () => {
  it("keeps same-site relative paths", () => {
    expect(safeNext("/investigations/123?tab=items")).toBe("/investigations/123?tab=items");
  });
  it.each(["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)", "", null, undefined])(
    "rejects %s",
    (value) => {
      expect(safeNext(value)).toBe("/dashboard");
    },
  );
});
