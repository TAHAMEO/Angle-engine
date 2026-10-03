import createClient, { type Middleware } from "openapi-fetch";

import { errorFor } from "./errors";
import type { paths } from "./schema";
import { expireSession, recordExpiry } from "./session";

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIES = ["__Host-ae_csrf", "ae_csrf"];

/** Polling requests set this header so the backend does not slide the idle timeout. */
export const BACKGROUND = { "X-Angel-Activity": "background" } as const;

export function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;
  for (const part of document.cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name && CSRF_COOKIES.includes(name)) return decodeURIComponent(rest.join("="));
  }
  return null;
}

/** Anonymous forms (login, access request, abuse report) first fetch a server-signed CSRF token. */
export async function ensureCsrf(): Promise<string> {
  const existing = readCsrfCookie();
  if (existing) return existing;
  const response = await fetch("/api/v1/auth/csrf", { credentials: "same-origin" });
  const body = (await response.json()) as { csrf_token: string };
  return body.csrf_token;
}

const middleware: Middleware = {
  onRequest({ request }) {
    if (UNSAFE.has(request.method)) {
      const token = readCsrfCookie();
      if (token) request.headers.set("X-CSRF-Token", token);
    }
    return request;
  },
  async onResponse({ request, response }) {
    const idle = response.headers.get("X-Session-Idle-Expires-In");
    const absolute = response.headers.get("X-Session-Absolute-Expires-In");
    if (idle !== null || absolute !== null) {
      recordExpiry(idle === null ? null : Number(idle), absolute === null ? null : Number(absolute));
    }
    if (response.status === 401 && !request.url.includes("/auth/")) {
      const body = await response
        .clone()
        .json()
        .catch(() => null);
      if (body?.code !== "reauth_required") expireSession(body?.code ?? "expired");
    }
    return response;
  },
};

export const api = createClient<paths>({ baseUrl: "", credentials: "same-origin" });
api.use(middleware);

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Return the data or throw a typed ApiError built from the problem+json body. */
export async function unwrap<T>(promise: Promise<FetchResult<T>>): Promise<T> {
  const { data, error, response } = await promise;
  if (!response.ok) throw errorFor(response.status, error);
  return data as T;
}

/** For binary uploads (raw request body) with progress, which fetch cannot report. */
export function uploadWithProgress(
  url: string,
  body: Blob,
  headers: Record<string, string>,
  onProgress: (fraction: number) => void,
  signal?: AbortSignal,
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.withCredentials = true;
    const token = readCsrfCookie();
    if (token) xhr.setRequestHeader("X-CSRF-Token", token);
    for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    xhr.onload = () => {
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(xhr.responseText);
      } catch {
        parsed = null;
      }
      if (xhr.status === 401) expireSession("expired");
      resolve({ status: xhr.status, body: parsed });
    };
    xhr.onerror = () => reject(new Error("The upload failed. Check your connection and try again."));
    xhr.onabort = () => reject(new DOMException("Upload cancelled", "AbortError"));
    signal?.addEventListener("abort", () => xhr.abort());
    xhr.send(body);
  });
}
