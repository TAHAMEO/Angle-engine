/**
 * Session lifetime as reported by the API (relative seconds, converted to local deadlines so clock skew does
 * not matter) plus a single-flight "session expired" handler shared by all requests and tabs.
 */
import { useSyncExternalStore } from "react";

export interface SessionClock {
  idleDeadline: number | null; // epoch ms
  absoluteDeadline: number | null;
}

let clock: SessionClock = { idleDeadline: null, absoluteDeadline: null };
const listeners = new Set<() => void>();
let expiring = false;
const CHANNEL = "angel-engine-session";

function emit() {
  for (const listener of listeners) listener();
}

export function recordExpiry(idleSeconds: number | null, absoluteSeconds: number | null): void {
  const now = Date.now();
  clock = {
    idleDeadline: idleSeconds === null ? clock.idleDeadline : now + idleSeconds * 1000,
    absoluteDeadline: absoluteSeconds === null ? clock.absoluteDeadline : now + absoluteSeconds * 1000,
  };
  emit();
  broadcast({ type: "activity", clock });
}

export function useSessionClock(): SessionClock {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => clock,
    () => clock,
  );
}

type Message = { type: "activity"; clock: SessionClock } | { type: "expired"; reason: string };

function broadcast(message: Message): void {
  if (typeof BroadcastChannel === "undefined") return;
  try {
    const channel = new BroadcastChannel(CHANNEL);
    channel.postMessage(message);
    channel.close();
  } catch {
    // ignore (private mode, unsupported)
  }
}

export function listenAcrossTabs(onExpired: (reason: string) => void): () => void {
  if (typeof BroadcastChannel === "undefined") return () => undefined;
  const channel = new BroadcastChannel(CHANNEL);
  channel.onmessage = (event: MessageEvent<Message>) => {
    if (event.data.type === "activity") {
      clock = event.data.clock;
      emit();
    } else if (event.data.type === "expired") {
      onExpired(event.data.reason);
    }
  };
  return () => channel.close();
}

/** Only allow same-site relative paths as post-login destinations. */
const NEXT_BASE = "https://angel-engine.invalid";

/**
 * A post-sign-in destination: only a path on this site. URL parsers drop tabs and newlines and treat "\\" like
 * "/", so "/<TAB>/evil.example" would become "//evil.example"; reject those characters and re-check the origin.
 */
export function safeNext(path: string | null | undefined): string {
  if (!path || !path.startsWith("/") || path.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(path)) return "/dashboard";
  try {
    const url = new URL(path, NEXT_BASE);
    return url.origin === NEXT_BASE ? `${url.pathname}${url.search}${url.hash}` : "/dashboard";
  } catch {
    return "/dashboard";
  }
}

let onExpire: ((reason: string) => void) | null = null;

export function setExpireHandler(handler: (reason: string) => void): void {
  onExpire = handler;
}

/** Called once per expiry, however many requests fail at the same time. */
export function expireSession(reason = "expired"): void {
  if (expiring) return;
  expiring = true;
  broadcast({ type: "expired", reason });
  if (onExpire) {
    onExpire(reason);
  } else if (typeof window !== "undefined") {
    const next = safeNext(window.location.pathname + window.location.search);
    // Fallback before the app shell has registered its router-based handler.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.assign(`/login?reason=${encodeURIComponent(reason)}&next=${encodeURIComponent(next)}`);
  }
}

export function resetExpiry(): void {
  expiring = false;
}
