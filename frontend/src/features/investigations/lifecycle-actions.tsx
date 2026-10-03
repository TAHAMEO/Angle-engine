"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Archive, ArchiveRestore, CirclePause, CirclePlay, FolderOpen, Lock, Send } from "lucide-react";
import { useState } from "react";

import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { ConfirmDialog, Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import { useInvestigation } from "@/lib/investigation";
import { useSession } from "@/lib/session";

type Action = "close" | "reopen" | "archive" | "restore" | "suspend" | "resume";

const PATHS = {
  close: "/api/v1/investigations/{investigation_id}/close",
  reopen: "/api/v1/investigations/{investigation_id}/reopen",
  archive: "/api/v1/investigations/{investigation_id}/archive",
  restore: "/api/v1/investigations/{investigation_id}/restore",
  suspend: "/api/v1/investigations/{investigation_id}/suspend",
  resume: "/api/v1/investigations/{investigation_id}/resume",
} as const;

const ACTIONS: Record<Action, { label: string; icon: React.ComponentType<{ className?: string }>; confirm: string; from: string[]; supervisor?: boolean }> = {
  close: { label: "Close", icon: Lock, confirm: "Closing makes the investigation read-only. Reports can still be exported, and it can be reopened.", from: ["active", "suspended"] },
  reopen: { label: "Reopen", icon: FolderOpen, confirm: "Reopening makes the investigation editable again.", from: ["closed"] },
  archive: { label: "Archive", icon: Archive, confirm: "Archived investigations are kept read-only until their retention period ends.", from: ["closed"] },
  restore: { label: "Restore", icon: ArchiveRestore, confirm: "Restore the investigation to the closed state.", from: ["archived"], supervisor: true },
  suspend: { label: "Suspend", icon: CirclePause, confirm: "Suspending blocks all work on the investigation until a supervisor resumes it.", from: ["active"], supervisor: true },
  resume: { label: "Resume", icon: CirclePlay, confirm: "Resume work on the investigation.", from: ["suspended"], supervisor: true },
};

export function LifecycleActions() {
  const { investigation: inv, can } = useInvestigation();
  const { data: session } = useSession();
  const client = useQueryClient();
  const [pending, setPending] = useState<Action | null>(null);
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const isSupervisor = session?.user?.role === "supervisor";
  const isOwner = inv.role === "owner";

  const refresh = () => client.invalidateQueries({ queryKey: ["investigations"] });
  const transition = useMutation({
    mutationFn: (action: Action) =>
      unwrap(
        api.POST(PATHS[action], {
          params: { path: { investigation_id: inv.id } },
        }),
      ),
    onSuccess: (_, action) => {
      setPending(null);
      toast(`Investigation ${action === "close" ? "closed" : action === "reopen" ? "reopened" : `${action}d`}`, { tone: "success" });
      void refresh();
    },
    onError: (error) => toast("The action failed", { description: messageOf(error), tone: "danger" }),
  });
  const submit = useMutation({
    mutationFn: (acknowledge: boolean) =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/submit", {
          params: { path: { investigation_id: inv.id } },
          body: { acknowledge_policy_notices: acknowledge },
        }),
      ),
    onSuccess: (result) => {
      setPolicy(null);
      const status = result.investigation.status;
      toast(status === "pending_review" ? "Sent for supervisor review" : "Investigation activated", { tone: "success" });
      void refresh();
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError || error instanceof PolicyAcknowledgementError) setPolicy(error.policy);
      else toast("Could not submit", { description: messageOf(error), tone: "danger" });
    },
  });

  const available = (Object.keys(ACTIONS) as Action[]).filter((action) => {
    const meta = ACTIONS[action];
    if (!meta.from.includes(inv.status)) return false;
    if (meta.supervisor || (action === "reopen" && inv.restricted_mode)) return isSupervisor;
    return can("investigation:manage");
  });
  const canSubmit = isOwner && inv.status === "draft";

  if (!available.length && !canSubmit) return null;
  return (
    <>
      {canSubmit ? (
        <Button variant="primary" onClick={() => submit.mutate(false)} loading={submit.isPending}>
          <Send className="h-4 w-4" aria-hidden /> Submit
        </Button>
      ) : null}
      {available.map((action) => {
        const Icon = ACTIONS[action].icon;
        return (
          <Button key={action} variant="secondary" onClick={() => setPending(action)}>
            <Icon className="h-4 w-4" aria-hidden /> {ACTIONS[action].label}
          </Button>
        );
      })}
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && setPending(null)}
        title={pending ? `${ACTIONS[pending].label} ${inv.ref}?` : ""}
        description={pending ? ACTIONS[pending].confirm : null}
        confirmLabel={pending ? ACTIONS[pending].label : "Confirm"}
        tone={pending === "suspend" || pending === "close" ? "danger" : "primary"}
        loading={transition.isPending}
        onConfirm={() => pending && transition.mutate(pending)}
      />
      <Dialog open={policy !== null} onOpenChange={(open) => !open && setPolicy(null)} title="Acceptable-use check">
        {policy ? (
          <PolicyDecisionPanel policy={policy} onAcknowledge={() => submit.mutate(true)} acknowledging={submit.isPending} />
        ) : null}
      </Dialog>
    </>
  );
}
