"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/data";
import { Alert } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { api, formCsrfToken } from "@/lib/api/client";
import { errorFor, messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";

const CATEGORIES: { value: S<"AbuseCategory">; label: string }[] = [
  { value: "targeted_by_investigation", label: "I believe I am being targeted by an investigation" },
  { value: "data_removal_request", label: "Request removal of information about me" },
  { value: "inaccurate_information", label: "Report inaccurate information" },
  { value: "platform_misuse", label: "Report misuse of the platform" },
  { value: "security_vulnerability", label: "Report a security vulnerability" },
  { value: "other", label: "Something else" },
];

export function ReportAbuseForm() {
  const [category, setCategory] = useState<S<"AbuseCategory">>("platform_misuse");
  const [description, setDescription] = useState("");
  const [contact, setContact] = useState("");
  const [targetRef, setTargetRef] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const token = await formCsrfToken();
      const { error: problem, response } = await api.POST("/api/v1/abuse-reports", {
        body: { category, description, contact: contact || null, target_ref: targetRef || null },
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

  return (
    <div className="w-full max-w-lg space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Report abuse or request removal</h1>
        <p className="text-sm text-muted">
          Anyone can use this form, without an account. Reports are encrypted, reviewed by administrators, and kept for
          two years. Do not include passwords or other secrets.
        </p>
      </div>
      {done ? (
        <Alert tone="success" title="Thank you — your report was received">
          {contact ? "We will contact you at the address you gave if we need more information." : "You did not leave contact details, so we cannot reply."}
        </Alert>
      ) : (
        <Card className="p-5">
          <form onSubmit={submit} className="space-y-4">
            <Field label="What is this about?" required>
              {(p) => (
                <Select {...p} value={category} onChange={(e) => setCategory(e.target.value as S<"AbuseCategory">)}>
                  {CATEGORIES.map((c) => (
                    <option key={c.value} value={c.value}>{c.label}</option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Description" required hint="At least 20 characters.">
              {(p) => <Textarea {...p} rows={6} value={description} onChange={(e) => setDescription(e.target.value)} />}
            </Field>
            <Field label="Investigation or report reference" hint="Optional, e.g. AE-2026-000123">
              {(p) => <Input {...p} value={targetRef} onChange={(e) => setTargetRef(e.target.value)} />}
            </Field>
            <Field label="How can we reach you?" hint="Optional email address.">
              {(p) => <Input {...p} type="email" autoComplete="email" value={contact} onChange={(e) => setContact(e.target.value)} />}
            </Field>
            {error ? <Alert tone="danger">{error}</Alert> : null}
            <Button type="submit" variant="primary" loading={busy}>Send report</Button>
          </form>
        </Card>
      )}
    </div>
  );
}
