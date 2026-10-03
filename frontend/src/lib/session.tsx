"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { LoadingBlock } from "@/components/ui/feedback";
import { api } from "@/lib/api/client";
import { listenAcrossTabs, recordExpiry, resetExpiry, safeNext, setExpireHandler } from "@/lib/api/session";
import type { Session } from "@/lib/api/types";

export const SESSION_KEY = ["session"] as const;

export async function fetchSession(): Promise<Session | null> {
  const { data, response } = await api.GET("/api/v1/auth/session");
  if (response.status === 401) return null;
  if (!response.ok || !data) throw new Error("Could not load your session.");
  recordExpiry(data.idle_expires_in, data.absolute_expires_in);
  return data;
}

export function useSession() {
  return useQuery({ queryKey: SESSION_KEY, queryFn: fetchSession, staleTime: 60_000, retry: 1 });
}

/** Where a session in a given state must go before the app can be used. */
export function gateFor(session: Session | null | undefined): string | null {
  if (!session) return "/login";
  if (session.state === "mfa_pending") return "/login";
  if (session.state === "mfa_enroll") return "/mfa-setup";
  if (!session.terms_current) return "/accept-terms";
  return null;
}

export function useSignOut() {
  const client = useQueryClient();
  const router = useRouter();
  return async (reason?: string) => {
    await api.POST("/api/v1/auth/logout").catch(() => undefined);
    client.clear();
    resetExpiry();
    router.replace(reason ? `/login?reason=${encodeURIComponent(reason)}` : "/login");
  };
}

/** Wraps authenticated pages: loads the session, sends it through the MFA/terms gates, handles expiry. */
export function SessionGate({ children }: { children: (session: Session) => React.ReactNode }) {
  const router = useRouter();
  const client = useQueryClient();
  const { data: session, isPending, isError } = useSession();

  useEffect(() => {
    const expire = (reason: string) => {
      client.clear();
      const next = safeNext(window.location.pathname + window.location.search);
      router.replace(`/login?reason=${encodeURIComponent(reason)}&next=${encodeURIComponent(next)}`);
    };
    setExpireHandler(expire);
    const stop = listenAcrossTabs(expire);
    // Back/forward cache: re-check the session when a page is restored after sign-out.
    const onShow = (event: PageTransitionEvent) => {
      if (event.persisted) void client.invalidateQueries({ queryKey: SESSION_KEY });
    };
    window.addEventListener("pageshow", onShow);
    return () => {
      stop();
      window.removeEventListener("pageshow", onShow);
    };
  }, [client, router]);

  const target = isPending ? null : gateFor(session ?? null);
  useEffect(() => {
    if (target) {
      const next = safeNext(window.location.pathname + window.location.search);
      router.replace(target === "/login" ? `/login?next=${encodeURIComponent(next)}` : target);
    }
  }, [target, router]);

  if (isError) {
    return <LoadingBlock label="Reconnecting" />;
  }
  if (isPending || target || !session) {
    return <LoadingBlock label="Checking your session" className="min-h-screen" />;
  }
  return <>{children(session)}</>;
}
