import { withReauth } from "@/features/auth/reauth";

import { errorFor } from "./api/errors";
import { expireSession } from "./api/session";

function filenameFrom(header: string | null, fallback: string): string {
  const match = header ? /filename="?([^";]+)"?/i.exec(header) : null;
  const name = match?.[1]?.trim() ?? fallback;
  return name.replace(/[\\/]/g, "_");
}

/** Download an authenticated file (exports need a recent re-authentication) without navigating away. */
export async function downloadFile(url: string, fallbackName: string): Promise<void> {
  const response = await withReauth(async () => {
    const res = await fetch(url, { credentials: "same-origin" });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      const error = errorFor(res.status, body);
      if (res.status === 401 && error.code !== "reauth_required") expireSession(error.code);
      throw error;
    }
    return res;
  });
  const blob = await response.blob();
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filenameFrom(response.headers.get("Content-Disposition"), fallbackName);
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 10_000);
}
