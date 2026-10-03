"use client";

import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/data";
import { Alert } from "@/components/ui/feedback";
import { Checkbox, Field, Input, Textarea } from "@/components/ui/form";
import { api, ensureCsrf } from "@/lib/api/client";
import { errorFor, messageOf } from "@/lib/api/errors";

export function RequestAccessForm() {
  const [form, setForm] = useState({ email: "", display_name: "", organization_unit: "", password: "", justification: "" });
  const [checks, setChecks] = useState({ accept_terms: false, attest_lawful_use: false, attest_no_misuse: false });
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm({ ...form, [key]: e.target.value });

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!checks.accept_terms || !checks.attest_lawful_use || !checks.attest_no_misuse) {
      setError("Please confirm all three statements.");
      return;
    }
    setBusy(true);
    try {
      const token = await ensureCsrf();
      const { error: problem, response } = await api.POST("/api/v1/auth/registration-requests", {
        body: { ...form, organization_unit: form.organization_unit || null, ...checks },
        headers: { "X-CSRF-Token": token },
      });
      if (!response.ok) throw errorFor(response.status, problem);
      setDone(true);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="w-full max-w-lg space-y-4">
        <h1 className="text-2xl font-semibold tracking-tight">Request received</h1>
        <Alert tone="success">
          An administrator will review your request. You will be able to sign in once it is approved, and you will set up
          multi-factor authentication at your first sign-in.
        </Alert>
        <Link href="/login" className="text-sm text-primary underline underline-offset-2 hover:decoration-2">Back to sign in</Link>
      </div>
    );
  }
  return (
    <div className="w-full max-w-lg space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Request access</h1>
        <p className="text-sm text-muted">
          Angel Engine is for lawful investigations of public information. An administrator approves every account.
        </p>
      </div>
      <Card className="p-5">
        <form onSubmit={submit} className="space-y-4">
          <Field label="Work email" required>
            {(p) => <Input {...p} type="email" autoComplete="email" value={form.email} onChange={set("email")} />}
          </Field>
          <Field label="Your name" required>
            {(p) => <Input {...p} autoComplete="name" value={form.display_name} onChange={set("display_name")} />}
          </Field>
          <Field label="Team or unit" hint="Optional">
            {(p) => <Input {...p} value={form.organization_unit} onChange={set("organization_unit")} />}
          </Field>
          <Field label="Password" required hint="At least 12 characters. Long passphrases are best; common passwords are refused.">
            {(p) => <Input {...p} type="password" autoComplete="new-password" value={form.password} onChange={set("password")} />}
          </Field>
          <Field label="Why do you need access?" required hint="At least 30 characters: your role and the kind of investigations you run.">
            {(p) => <Textarea {...p} value={form.justification} onChange={set("justification")} />}
          </Field>
          <fieldset className="space-y-3 rounded-md border border-border p-3">
            <legend className="px-1 text-sm font-medium">Please confirm</legend>
            <Checkbox
              label={<>I accept the <Link className="text-primary underline" href="/legal/terms">Terms of Use</Link> and the <Link className="text-primary underline" href="/legal/acceptable-use">Acceptable Use Policy</Link>.</>}
              checked={checks.accept_terms}
              onChange={(e) => setChecks({ ...checks, accept_terms: e.target.checked })}
            />
            <Checkbox
              label="I will only investigate for lawful purposes and only public information."
              checked={checks.attest_lawful_use}
              onChange={(e) => setChecks({ ...checks, attest_lawful_use: e.target.checked })}
            />
            <Checkbox
              label="I will not use Angel Engine to identify, track, harass or expose private individuals."
              checked={checks.attest_no_misuse}
              onChange={(e) => setChecks({ ...checks, attest_no_misuse: e.target.checked })}
            />
          </fieldset>
          {error ? <Alert tone="danger">{error}</Alert> : null}
          <Button type="submit" variant="primary" loading={busy}>Send request</Button>
        </form>
      </Card>
    </div>
  );
}
