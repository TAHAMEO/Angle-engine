"use client";

import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, LockKeyhole } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/data";
import { Alert } from "@/components/ui/feedback";
import { Field, Input } from "@/components/ui/form";
import { api, ensureCsrf } from "@/lib/api/client";
import { errorFor, messageOf } from "@/lib/api/errors";
import { resetExpiry, safeNext } from "@/lib/api/session";
import type { Session } from "@/lib/api/types";
import { SESSION_KEY, gateFor } from "@/lib/session";

const REASONS: Record<string, string> = {
  idle: "You were signed out after 30 minutes of inactivity.",
  absolute: "Sessions end after 12 hours. Please sign in again.",
  expired: "Your session has ended. Please sign in again.",
  session_expired: "Your session has ended. Please sign in again.",
};

export function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const client = useQueryClient();
  const next = safeNext(params.get("next"));
  const reason = params.get("reason");
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const proceed = (session: Session) => {
    resetExpiry();
    client.setQueryData(SESSION_KEY, session);
    const gate = gateFor(session);
    if (gate === "/login") {
      setStep("mfa");
      return;
    }
    router.replace(gate ?? next);
  };

  const submitPassword = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const token = await ensureCsrf();
      const { data, error: problem, response } = await api.POST("/api/v1/auth/login", {
        body: { email, password },
        headers: { "X-CSRF-Token": token },
      });
      if (!response.ok || !data) throw errorFor(response.status, problem);
      setPassword("");
      proceed(data);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data, error: problem, response } = await api.POST("/api/v1/auth/mfa/verify", {
        body: { code: code.replace(/\s+/g, "") },
      });
      if (!response.ok || !data) throw errorFor(response.status, problem);
      proceed(data);
    } catch (err) {
      setError(messageOf(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="w-full max-w-sm space-y-6">
      <div className="space-y-1 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="text-sm text-muted">Multi-factor authentication is required for every account.</p>
      </div>
      {reason && REASONS[reason] ? <Alert tone="info">{REASONS[reason]}</Alert> : null}
      <Card className="p-5">
        {step === "password" ? (
          <form onSubmit={submitPassword} className="space-y-4" noValidate>
            <Field label="Email">
              {(props) => (
                <Input {...props} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
              )}
            </Field>
            <Field label="Password">
              {(props) => (
                <Input
                  {...props}
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              )}
            </Field>
            {error ? <Alert tone="danger">{error}</Alert> : null}
            <Button type="submit" variant="primary" className="w-full justify-center" loading={busy}>
              <LockKeyhole className="h-4 w-4" aria-hidden />
              Continue
            </Button>
          </form>
        ) : (
          <form onSubmit={submitCode} className="space-y-4" noValidate>
            <p className="text-sm text-muted">
              Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>
            <Field label="Authentication code">
              {(props) => (
                <Input
                  {...props}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="font-mono tracking-[0.3em]"
                  autoFocus
                  required
                />
              )}
            </Field>
            {error ? <Alert tone="danger">{error}</Alert> : null}
            <Button type="submit" variant="primary" className="w-full justify-center" loading={busy}>
              <KeyRound className="h-4 w-4" aria-hidden />
              Verify
            </Button>
          </form>
        )}
      </Card>
      <p className="text-center text-sm text-muted">
        No account? <Link href="/request-access" className="text-primary underline underline-offset-2 hover:decoration-2">Request access</Link> — an
        administrator approves every account.
      </p>
    </div>
  );
}
