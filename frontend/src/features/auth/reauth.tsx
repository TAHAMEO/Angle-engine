"use client";

import { KeyRound } from "lucide-react";
import { useState, useSyncExternalStore } from "react";

import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/feedback";
import { Field, Input } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { api } from "@/lib/api/client";
import { ReauthRequiredError } from "@/lib/api/errors";

/**
 * Step-up authentication. Sensitive actions (deletion, exports, downloads, MFA and password changes) need a password
 * confirmation within the last five minutes; the API answers 401 `reauth_required` otherwise and the action is retried
 * after the user confirms.
 */
let resolver: ((ok: boolean) => void) | null = null;
let isOpen = false;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((listener) => listener());

export function requestReauth(): Promise<boolean> {
  resolver?.(false);
  isOpen = true;
  emit();
  return new Promise((resolve) => {
    resolver = resolve;
  });
}

function settle(ok: boolean) {
  isOpen = false;
  emit();
  const resolve = resolver;
  resolver = null;
  resolve?.(ok);
}

export async function withReauth<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (error) {
    if (error instanceof ReauthRequiredError && (await requestReauth())) return action();
    throw error;
  }
}

export function ReauthDialogHost() {
  const open = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => isOpen,
    () => false,
  );
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const { response } = await api.POST("/api/v1/auth/reauth", { body: { password } }).catch(() => ({
      response: new Response(null, { status: 503 }),
    }));
    setBusy(false);
    if (response.ok) {
      setPassword("");
      settle(true);
    } else if (response.status === 429) {
      setError("Too many attempts. Wait a minute and try again.");
    } else {
      setError("That password is not correct.");
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setPassword("");
          setError(null);
          settle(false);
        }
      }}
      title="Confirm it's you"
      description="This action is sensitive. Enter your password to continue — you won't be asked again for five minutes."
    >
      <form onSubmit={submit} className="space-y-4">
        {error ? <Alert tone="danger">{error}</Alert> : null}
        <Field label="Password" required>
          {(props) => (
            <Input
              {...props}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoFocus
            />
          )}
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={() => settle(false)}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={busy} disabled={!password}>
            <KeyRound className="h-4 w-4" aria-hidden /> Confirm
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
