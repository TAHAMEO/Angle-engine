"use client";

import { useMutation } from "@tanstack/react-query";
import { Copy, Download, KeyRound, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/data";
import { Alert } from "@/components/ui/feedback";
import { Field, Input } from "@/components/ui/form";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { api, unwrap } from "@/lib/api/client";
import { ValidationError, messageOf } from "@/lib/api/errors";
import { useSignOut } from "@/lib/session";

function PasswordForm() {
  const signOut = useSignOut();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const change = useMutation({
    mutationFn: () => unwrap(api.PUT("/api/v1/auth/password", { body: { current_password: current, new_password: next } })),
    onSuccess: () => {
      toast("Password changed", { description: "Other sessions were signed out. Please sign in again.", tone: "success" });
      void signOut("password_changed");
    },
    onError: (e) => setError(e instanceof ValidationError ? e.fieldErrors.map((f) => f.msg).join(" ") || e.message : messageOf(e)),
  });
  const mismatch = repeat.length > 0 && next !== repeat;
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        setError(null);
        change.mutate();
      }}
    >
      {error ? <Alert tone="danger">{error}</Alert> : null}
      <Field label="Current password" required>
        {(props) => <Input {...props} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />}
      </Field>
      <Field label="New password" required hint="12–128 characters. Long passphrases are best; common passwords are refused.">
        {(props) => <Input {...props} type="password" autoComplete="new-password" minLength={12} maxLength={128} value={next} onChange={(e) => setNext(e.target.value)} />}
      </Field>
      <Field label="Repeat new password" required error={mismatch ? "The passwords do not match." : undefined}>
        {(props) => <Input {...props} type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />}
      </Field>
      <Button type="submit" variant="primary" loading={change.isPending} disabled={!current || next.length < 12 || next !== repeat}>
        <KeyRound className="h-4 w-4" aria-hidden /> Change password
      </Button>
    </form>
  );
}

function RecoveryCodes() {
  const [confirming, setConfirming] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const regenerate = useMutation({
    mutationFn: () => withReauth(() => unwrap(api.POST("/api/v1/auth/mfa/recovery-codes"))),
    onSuccess: (result) => {
      setConfirming(false);
      setCodes(result.recovery_codes);
    },
    onError: (e) => toast("New codes were not generated", { description: messageOf(e), tone: "danger" }),
  });
  const text = codes?.join("\n") ?? "";
  return (
    <div className="space-y-3 text-sm">
      <p>
        Recovery codes let you sign in if you lose your authenticator. Each code works once. Generating new codes invalidates the old ones.
      </p>
      {codes ? (
        <div className="space-y-3">
          <Alert tone="warning" title="Save these codes now">
            They will not be shown again.
          </Alert>
          <ul className="grid grid-cols-2 gap-1.5 rounded-md border border-border bg-surface-2 p-3 font-mono text-sm">
            {codes.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void navigator.clipboard.writeText(text).then(() => toast("Copied to the clipboard"))}
            >
              <Copy className="h-3.5 w-3.5" aria-hidden /> Copy
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                const href = URL.createObjectURL(new Blob([`${text}\n`], { type: "text/plain" }));
                const a = document.createElement("a");
                a.href = href;
                a.download = "angel-engine-recovery-codes.txt";
                a.click();
                URL.revokeObjectURL(href);
              }}
            >
              <Download className="h-3.5 w-3.5" aria-hidden /> Download
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="secondary" onClick={() => setConfirming(true)}>
          <ShieldCheck className="h-4 w-4" aria-hidden /> Generate new recovery codes
        </Button>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        tone="primary"
        title="Replace your recovery codes?"
        description="Your current recovery codes stop working immediately."
        confirmLabel="Generate new codes"
        loading={regenerate.isPending}
        onConfirm={() => regenerate.mutate()}
      />
    </div>
  );
}

export function SecuritySettings() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Password" description="Changing it signs out your other sessions." />
        <div className="p-4">
          <PasswordForm />
        </div>
      </Card>
      <Card>
        <CardHeader title="Two-factor authentication" description="Required for every account. To move to a new device, ask an administrator to reset your enrollment." />
        <div className="p-4">
          <RecoveryCodes />
        </div>
      </Card>
    </div>
  );
}
