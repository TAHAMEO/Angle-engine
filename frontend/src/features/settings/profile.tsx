"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Save } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardHeader, DefinitionList } from "@/components/ui/data";
import { LoadingBlock } from "@/components/ui/feedback";
import { Field, Input } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { User } from "@/lib/api/types";
import { SESSION_KEY, useSession } from "@/lib/session";

const ROLE_HELP: Record<string, string> = {
  admin: "Administers users and settings. Cannot read investigation content.",
  supervisor: "Approves sensitive investigations and reviews policy decisions.",
  investigator: "Creates investigations and works with evidence.",
  viewer: "Reads investigations they are a member of.",
  auditor: "Reads the audit log; no investigation content.",
};

function ProfileForm({ user }: { user: User }) {
  const client = useQueryClient();
  const [name, setName] = useState(user.display_name);
  const save = useMutation({
    mutationFn: () => unwrap(api.PATCH("/api/v1/me", { body: { display_name: name.trim() } })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: SESSION_KEY });
      toast("Profile saved", { tone: "success" });
    },
    onError: (e) => toast("The profile was not saved", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate();
      }}
    >
      <Field label="Display name" hint="Shown to members of your investigations and in the audit trail.">
        {(props) => <Input {...props} value={name} maxLength={120} onChange={(e) => setName(e.target.value)} autoComplete="name" />}
      </Field>
      <Button type="submit" variant="primary" loading={save.isPending} disabled={name.trim().length < 2}>
        <Save className="h-4 w-4" aria-hidden /> Save
      </Button>
    </form>
  );
}

export function ProfileSettings() {
  const { data } = useSession();
  const user = data?.user as User | undefined;
  if (!user) return <LoadingBlock />;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Profile" />
        <div className="p-4">
          <ProfileForm user={user} />
        </div>
      </Card>
      <Card>
        <CardHeader title="Account" description="Managed by an administrator." />
        <div className="p-4">
          <DefinitionList
            items={[
              ["Email", user.email],
              ["Role", <span key="r"><span className="capitalize">{user.role}</span><span className="block text-xs text-muted">{ROLE_HELP[user.role]}</span></span>],
              ["Organization unit", user.organization_unit ?? "—"],
              ["Terms accepted", user.terms_version_accepted ? `Version ${user.terms_version_accepted}` : "—"],
              ["Two-factor authentication", user.mfa_enabled ? "On" : "Off"],
            ]}
          />
        </div>
      </Card>
    </div>
  );
}
