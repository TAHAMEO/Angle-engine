"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus, UserMinus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/data";
import { Alert, Spinner } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/form";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

export function TeamCard() {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const manage = can("members:manage");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"editor" | "viewer">("viewer");
  const [removing, setRemoving] = useState<{ id: string; name: string } | null>(null);
  const params = { path: { investigation_id: inv.id } };
  const { data, isPending, error } = useQuery({
    queryKey: qk.members(inv.id),
    queryFn: () => unwrap(api.GET("/api/v1/investigations/{investigation_id}/members", { params })),
  });
  const invalidate = () => client.invalidateQueries({ queryKey: qk.members(inv.id) });
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/investigations/{investigation_id}/members", { params, body: { email, role } })),
    onSuccess: () => {
      setEmail("");
      toast("Member added", { tone: "success" });
      void invalidate();
    },
    onError: (e) => toast("Could not add the member", { description: messageOf(e), tone: "danger" }),
  });
  const change = useMutation({
    mutationFn: ({ userId, newRole }: { userId: string; newRole: "editor" | "viewer" }) =>
      unwrap(
        api.PATCH("/api/v1/investigations/{investigation_id}/members/{user_id}", {
          params: { path: { investigation_id: inv.id, user_id: userId } },
          body: { role: newRole },
        }),
      ),
    onSuccess: () => void invalidate(),
    onError: (e) => toast("Could not change the role", { description: messageOf(e), tone: "danger" }),
  });
  const remove = useMutation({
    mutationFn: (userId: string) =>
      unwrap(
        api.DELETE("/api/v1/investigations/{investigation_id}/members/{user_id}", {
          params: { path: { investigation_id: inv.id, user_id: userId } },
        }),
      ),
    onSuccess: () => {
      setRemoving(null);
      toast("Member removed");
      void invalidate();
    },
    onError: (e) => toast("Could not remove the member", { description: messageOf(e), tone: "danger" }),
  });

  return (
    <Card>
      <CardHeader title="Team" description="Only members can see this investigation. Every view and change is audited." />
      <div className="space-y-3 p-4">
        {isPending ? <Spinner /> : error ? <Alert tone="danger">{messageOf(error)}</Alert> : null}
        <ul className="divide-y divide-border">
          {data?.map((member) => (
            <li key={member.user_id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium">{member.display_name}</p>
                <p className="truncate text-xs text-muted">{member.email}</p>
              </div>
              {manage && member.role !== "owner" ? (
                <>
                  <Select
                    aria-label={`Role of ${member.display_name}`}
                    className="h-8 w-28"
                    value={member.role}
                    onChange={(event) => change.mutate({ userId: member.user_id, newRole: event.target.value as "editor" | "viewer" })}
                  >
                    <option value="editor">Editor</option>
                    <option value="viewer">Viewer</option>
                  </Select>
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label={`Remove ${member.display_name}`}
                    onClick={() => setRemoving({ id: member.user_id, name: member.display_name })}
                  >
                    <UserMinus className="h-4 w-4" aria-hidden />
                  </Button>
                </>
              ) : (
                <span className="text-xs text-muted capitalize">{member.role}</span>
              )}
            </li>
          ))}
        </ul>
        {manage ? (
          <form
            className="flex flex-wrap items-end gap-2 border-t border-border pt-3"
            onSubmit={(event) => {
              event.preventDefault();
              add.mutate();
            }}
          >
            <label className="min-w-48 flex-1 space-y-1 text-sm">
              <span className="font-medium">Add a colleague by email</span>
              <Input type="email" required value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="off" />
            </label>
            <label className="space-y-1 text-sm">
              <span className="font-medium">Role</span>
              <Select value={role} onChange={(event) => setRole(event.target.value as "editor" | "viewer")} className="w-28">
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
              </Select>
            </label>
            <Button type="submit" variant="secondary" loading={add.isPending}>
              <UserPlus className="h-4 w-4" aria-hidden /> Add
            </Button>
          </form>
        ) : null}
      </div>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={`Remove ${removing?.name ?? "member"}?`}
        description="They lose access to this investigation immediately."
        confirmLabel="Remove"
        loading={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </Card>
  );
}
