"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Users } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Table, Tabs, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Select } from "@/components/ui/form";
import { Menu } from "@/components/ui/menu";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { NotFoundOrNoAccess, QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { AdminUserOut, S } from "@/lib/api/types";
import { formatDateTime, relative } from "@/lib/format";

import { useRole } from "./admin-nav";

type Role = S<"Role">;
type Action = "approve" | "disable" | "enable" | "unlock" | "reset-mfa" | "clear-flag";
const ROLES: Role[] = ["investigator", "viewer", "supervisor", "auditor", "admin"];

const ACTION_PATHS = {
  approve: "/api/v1/admin/users/{user_id}/approve",
  disable: "/api/v1/admin/users/{user_id}/disable",
  enable: "/api/v1/admin/users/{user_id}/enable",
  unlock: "/api/v1/admin/users/{user_id}/unlock",
  "reset-mfa": "/api/v1/admin/users/{user_id}/reset-mfa",
  "clear-flag": "/api/v1/admin/users/{user_id}/clear-flag",
} as const;

const CONFIRM: Record<Action, string> = {
  approve: "The person can sign in and must enroll two-factor authentication.",
  disable: "All their sessions end immediately. Their investigations keep their data.",
  enable: "They can sign in again.",
  unlock: "Clears the sign-in lockout after failed attempts.",
  "reset-mfa": "They must enroll a new authenticator at their next sign-in. Their sessions end.",
  "clear-flag": "Clears the refusal flag after you have reviewed their refused requests.",
};

function UserTable({ users, pending }: { users: AdminUserOut[]; pending?: boolean }) {
  const client = useQueryClient();
  const [confirm, setConfirm] = useState<{ user: AdminUserOut; action: Action } | null>(null);
  const [approveRole, setApproveRole] = useState<Record<string, Role>>({});
  const act = useMutation({
    mutationFn: ({ user, action }: { user: AdminUserOut; action: Action }) => {
      const params = { path: { user_id: user.id } };
      if (action === "approve") return unwrap(api.POST(ACTION_PATHS.approve, { params, body: { role: approveRole[user.id] ?? "investigator" } }));
      return unwrap(api.POST(ACTION_PATHS[action], { params }));
    },
    onSuccess: () => {
      setConfirm(null);
      void client.invalidateQueries({ queryKey: ["admin"] });
      toast("Saved", { tone: "success" });
    },
    onError: (e) => toast("The action failed", { description: messageOf(e), tone: "danger" }),
  });
  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => unwrap(api.PATCH("/api/v1/admin/users/{user_id}", { params: { path: { user_id: id } }, body: { role } })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["admin"] });
      toast("Role changed", { description: "Their sessions were renewed with the new role." });
    },
    onError: (e) => toast("The role was not changed", { description: messageOf(e), tone: "danger" }),
  });
  if (!users.length) return <EmptyState icon={Users} title={pending ? "No pending access requests" : "No users"} />;
  return (
    <>
      <Table caption="Users" className="rounded-lg border border-border">
        <thead>
          <tr>
            <Th>Person</Th>
            <Th>Role</Th>
            <Th>Status</Th>
            <Th>{pending ? "Justification" : "Last sign-in"}</Th>
            <Th><span className="sr-only">Actions</span></Th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <Td>
                <p className="font-medium">{user.display_name}</p>
                <p className="text-xs text-muted">
                  {user.email}
                  {user.organization_unit ? ` · ${user.organization_unit}` : ""}
                </p>
              </Td>
              <Td>
                {pending ? (
                  <Select
                    aria-label={`Role for ${user.display_name}`}
                    className="h-8 w-36"
                    value={approveRole[user.id] ?? "investigator"}
                    onChange={(e) => setApproveRole((r) => ({ ...r, [user.id]: e.target.value as Role }))}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <Select
                    aria-label={`Role of ${user.display_name}`}
                    className="h-8 w-36"
                    value={user.role}
                    onChange={(e) => setRole.mutate({ id: user.id, role: e.target.value as Role })}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                )}
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  <Badge>{user.status}</Badge>
                  {user.locked ? <Badge className="border-warning/50 text-warning">Locked</Badge> : null}
                  {!user.mfa_enabled && user.status === "active" ? <Badge>No MFA yet</Badge> : null}
                  {user.refusal_flag_level > 0 ? <Badge className="border-danger/50 text-danger">Refusal flag {user.refusal_flag_level}</Badge> : null}
                </div>
              </Td>
              <Td className="max-w-sm text-[13px]">
                {pending ? (user.access_justification ?? "—") : user.last_login_at ? `${formatDateTime(user.last_login_at)} (${relative(user.last_login_at)})` : "Never"}
              </Td>
              <Td className="text-right">
                {pending ? (
                  <Button size="sm" variant="primary" onClick={() => setConfirm({ user, action: "approve" })}>
                    Approve
                  </Button>
                ) : (
                  <Menu
                    label={`Actions for ${user.display_name}`}
                    trigger={
                      <Button size="sm" variant="secondary">
                        Actions
                      </Button>
                    }
                    items={[
                      user.status === "disabled"
                        ? { label: "Enable", onSelect: () => setConfirm({ user, action: "enable" }) }
                        : { label: "Disable", onSelect: () => setConfirm({ user, action: "disable" }), danger: true },
                      { label: "Unlock sign-in", onSelect: () => setConfirm({ user, action: "unlock" }), disabled: !user.locked },
                      { label: "Reset two-factor", onSelect: () => setConfirm({ user, action: "reset-mfa" }) },
                      { label: "Clear refusal flag", onSelect: () => setConfirm({ user, action: "clear-flag" }), disabled: user.refusal_flag_level === 0 },
                    ]}
                  />
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={confirm ? `${confirm.action === "reset-mfa" ? "Reset two-factor for" : confirm.action.replace("-", " ").replace(/^./, (c) => c.toUpperCase())} ${confirm.user.display_name}?` : ""}
        description={confirm ? CONFIRM[confirm.action] : null}
        tone={confirm?.action === "disable" || confirm?.action === "reset-mfa" ? "danger" : "primary"}
        confirmLabel="Confirm"
        loading={act.isPending}
        onConfirm={() => confirm && act.mutate(confirm)}
      />
    </>
  );
}

function UserList({ status }: { status?: "pending" | "active" | "disabled" }) {
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "users", status ?? "all"],
    queryFn: () => unwrap(api.GET("/api/v1/admin/users", { params: { query: { status } } })),
  });
  if (isPending) return <LoadingBlock />;
  if (error) return <QueryError error={error} retry={() => void refetch()} />;
  return <UserTable users={data ?? []} pending={status === "pending"} />;
}

function FlaggedList() {
  const { data, error, isPending, refetch } = useQuery({ queryKey: ["admin", "flags"], queryFn: () => unwrap(api.GET("/api/v1/admin/flags")) });
  if (isPending) return <LoadingBlock />;
  if (error) return <QueryError error={error} retry={() => void refetch()} />;
  return <UserTable users={data ?? []} />;
}

export function AdminUsers() {
  const role = useRole();
  if (role && role !== "admin") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader title="Users" description="Approve access requests, assign roles and handle lockouts. Role and two-factor changes end the person's sessions." />
      <Tabs
        label="Users"
        tabs={[
          { value: "pending", label: "Access requests", content: <UserList status="pending" /> },
          { value: "active", label: "Active", content: <UserList status="active" /> },
          { value: "disabled", label: "Disabled", content: <UserList status="disabled" /> },
          { value: "flagged", label: "Flagged", content: <FlaggedList /> },
        ]}
      />
    </>
  );
}
