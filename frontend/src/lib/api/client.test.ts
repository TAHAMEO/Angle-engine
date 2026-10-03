import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BACKGROUND, api, formCsrfToken } from "./client";
import { expireSession, recordExpiry } from "./session";

vi.mock("./session", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./session")>();
  return { ...actual, recordExpiry: vi.fn(), expireSession: vi.fn() };
});

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

describe("API client middleware", () => {
  const fetchMock = vi.fn<typeof fetch>();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    document.cookie = "ae_csrf=token-123; path=/";
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
    document.cookie = "ae_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("sends the CSRF token on unsafe methods only", async () => {
    fetchMock.mockImplementation(async () => json({ status: "ok" }));
    await api.POST("/api/v1/auth/logout");
    await api.GET("/api/v1/me");
    const [post, get] = fetchMock.mock.calls.map(([request]) => request as Request);
    expect(post!.headers.get("X-CSRF-Token")).toBe("token-123");
    expect(get!.headers.get("X-CSRF-Token")).toBeNull();
  });

  it("sends an anonymous form's fresh token, not a leftover session cookie", async () => {
    fetchMock.mockImplementation(async (input) =>
      (input instanceof Request ? input.url : String(input)).endsWith("/api/v1/auth/csrf")
        ? json({ csrf_token: "form-456" })
        : json({ state: "mfa_pending" }),
    );
    const token = await formCsrfToken();
    await api.POST("/api/v1/auth/login", {
      body: { email: "someone@agency.example", password: "correct-horse-battery" },
      headers: { "X-CSRF-Token": token },
    });
    expect(token).toBe("form-456");
    expect((fetchMock.mock.calls[1]![0] as Request).headers.get("X-CSRF-Token")).toBe("form-456");
  });

  it("reports a failed form-token request instead of submitting without one", async () => {
    fetchMock.mockResolvedValueOnce(json({ type: "/problems/rate-limited", title: "Too many requests", status: 429 }, 429));
    const error = await formCsrfToken().then(
      () => null,
      (reason: unknown) => reason,
    );
    expect((error as { status?: number } | null)?.status).toBe(429);
  });

  it("marks polling requests as background activity", async () => {
    fetchMock.mockResolvedValue(json({}));
    await api.GET("/api/v1/me", { headers: BACKGROUND });
    expect((fetchMock.mock.calls[0]![0] as Request).headers.get("X-Angel-Activity")).toBe("background");
  });

  it("records session expiry headers", async () => {
    fetchMock.mockResolvedValue(json({}, 200, { "X-Session-Idle-Expires-In": "1700", "X-Session-Absolute-Expires-In": "40000" }));
    await api.GET("/api/v1/me");
    expect(recordExpiry).toHaveBeenCalledWith(1700, 40000);
  });

  it("expires the session on 401 but not on a re-authentication request", async () => {
    const expire = vi.mocked(expireSession);
    fetchMock.mockResolvedValueOnce(json({ type: "/problems/reauth-required", status: 401, code: "reauth_required", title: "x" }, 401));
    await api.GET("/api/v1/me");
    expect(expire).not.toHaveBeenCalled();
    fetchMock.mockResolvedValueOnce(json({ type: "/problems/unauthenticated", status: 401, code: "session_expired", title: "x" }, 401));
    await api.GET("/api/v1/me");
    expect(expire).toHaveBeenCalledWith("session_expired");
  });
});
