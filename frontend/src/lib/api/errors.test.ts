import { describe, expect, it } from "vitest";

import {
  ApiError,
  ConflictError,
  NotFoundOrForbiddenError,
  PolicyRefusalError,
  RateLimitError,
  ReauthRequiredError,
  ValidationError,
  errorFor,
  messageOf,
} from "./errors";

const problem = (slug: string, status: number, extra: Record<string, unknown> = {}) => ({
  type: `https://angel-engine.invalid/problems/${slug}`,
  title: "Title",
  status,
  code: slug.replaceAll("-", "_"),
  detail: "Detail text",
  ...extra,
});

describe("errorFor", () => {
  it("maps problem types to typed errors", () => {
    expect(errorFor(422, problem("policy-refused", 422, { policy: { decision: "refuse", categories: ["doxxing"] } }))).toBeInstanceOf(PolicyRefusalError);
    expect(errorFor(422, problem("validation-error", 422))).toBeInstanceOf(ValidationError);
    expect(errorFor(404, problem("not-found", 404))).toBeInstanceOf(NotFoundOrForbiddenError);
    expect(errorFor(403, problem("forbidden", 403))).toBeInstanceOf(NotFoundOrForbiddenError);
    expect(errorFor(409, problem("conflict-state", 409))).toBeInstanceOf(ConflictError);
    expect(errorFor(429, problem("rate-limited", 429, { retry_after: 12 }))).toBeInstanceOf(RateLimitError);
    expect(errorFor(401, problem("reauth-required", 401))).toBeInstanceOf(ReauthRequiredError);
  });

  it("exposes policy details without the refused text", () => {
    const error = errorFor(
      422,
      problem("policy-refused", 422, { policy: { decision: "refuse", categories: ["home_address"], alternatives: [{ kind: "template", label: "Use HQ" }] } }),
    ) as PolicyRefusalError;
    expect(error.policy.categories).toEqual(["home_address"]);
    expect(error.policy.alternatives?.[0]?.label).toBe("Use HQ");
  });

  it("exposes failed preconditions on conflicts", () => {
    const error = errorFor(409, problem("conflict-state", 409, { failed_preconditions: { corroborated: ["Needs two origins."] } })) as ConflictError;
    expect(error.failedPreconditions.corroborated).toEqual(["Needs two origins."]);
  });

  it("falls back to a generic error for non-problem bodies", () => {
    const error = errorFor(502, "<html>bad gateway</html>");
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(502);
    expect(messageOf(error)).toMatch(/server could not complete/i);
  });

  it("adds the request reference only to server errors", () => {
    expect(messageOf(errorFor(500, problem("internal", 500, { request_id: "req-1" })))).toContain("req-1");
    expect(messageOf(errorFor(404, problem("not-found", 404, { request_id: "req-2" })))).not.toContain("req-2");
  });
});
