"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderSearch, Gavel, Search, Trash2 } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Menu } from "@/components/ui/menu";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { InvestigationStatus, NotFoundOrNoAccess, QueryError } from "@/features/common/states";
import { PURPOSE_CATEGORIES, SUBJECT_TYPES } from "@/features/investigations/labels";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { formatDate } from "@/lib/format";

import { useRole } from "./admin-nav";

type Row = S<"AdminInvestigationOut">;
type LookupKind = S<"LookupIn">["kind"];
type Reason = S<"LookupIn">["reason"];

function LookupCard() {
  const [kind, setKind] = useState<LookupKind>("url");
  const [value, setValue] = useState("");
  const [platform, setPlatform] = useState("");
  const [reason, setReason] = useState<Reason>("data_subject_request");
  const lookup = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(
          api.POST("/api/v1/admin/data-subject-lookup", {
            body: { kind, value: value.trim(), platform: kind === "username" && platform ? platform : null, reason },
          }),
        ),
      ),
    onError: (e) => toast("The lookup failed", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Card>
      <CardHeader
        title="Locate references for a data-subject or abuse request"
        description="Matches the value against each investigation's keyed hashes. You see where it occurs — never the content. The lookup is audited (without the value) and needs a recent password confirmation."
      />
      <form
        className="space-y-3 p-4"
        onSubmit={(event) => {
          event.preventDefault();
          lookup.mutate();
        }}
      >
        <div className="grid gap-3 md:grid-cols-[10rem_1fr_14rem]">
          <Field label="Kind">
            {(props) => (
              <Select {...props} value={kind} onChange={(e) => setKind(e.target.value as LookupKind)}>
                <option value="url">Web address</option>
                <option value="domain">Domain</option>
                <option value="username">Public username</option>
                <option value="name">Name (public figure / organization)</option>
              </Select>
            )}
          </Field>
          <Field label="Value" required>
            {(props) => <Input {...props} value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" />}
          </Field>
          <Field label="Reason">
            {(props) => (
              <Select {...props} value={reason} onChange={(e) => setReason(e.target.value as Reason)}>
                <option value="data_subject_request">Data-subject request</option>
                <option value="abuse_report">Abuse report</option>
                <option value="legal_request">Legal request</option>
              </Select>
            )}
          </Field>
        </div>
        {kind === "username" ? (
          <Field label="Platform (optional)" hint="For example mastodon.example or github.">
            {(props) => <Input {...props} value={platform} onChange={(e) => setPlatform(e.target.value)} className="max-w-xs" />}
          </Field>
        ) : null}
        <Button type="submit" variant="secondary" loading={lookup.isPending} disabled={value.trim().length < 2}>
          <Search className="h-4 w-4" aria-hidden /> Locate
        </Button>
        {lookup.data ? (
          lookup.data.matches.length ? (
            <Table caption="Investigations that reference the value">
              <thead>
                <tr>
                  <Th>Reference</Th>
                  <Th>Status</Th>
                  <Th>Owner</Th>
                  <Th className="text-right">Sources</Th>
                  <Th className="text-right">Entities</Th>
                  <Th>Legal hold</Th>
                </tr>
              </thead>
              <tbody>
                {lookup.data.matches.map((m) => (
                  <tr key={m.investigation_id}>
                    <Td className="font-mono text-xs">{m.ref}</Td>
                    <Td>
                      <InvestigationStatus status={m.status} />
                    </Td>
                    <Td>{m.owner_name ?? "—"}</Td>
                    <Td className="text-right tabular">{m.sources}</Td>
                    <Td className="text-right tabular">{m.entities}</Td>
                    <Td>{m.legal_hold ? "Yes" : "No"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Alert tone="info">No investigation references this value ({lookup.data.checked} checked).</Alert>
          )
        ) : null}
      </form>
    </Card>
  );
}

function LegalHoldDialog({ row, onClose }: { row: Row | null; onClose: () => void }) {
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const enable = row ? !row.legal_hold : true;
  const save = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(
          api.PUT("/api/v1/investigations/{investigation_id}/legal-hold", {
            params: { path: { investigation_id: row!.id } },
            body: { enabled: enable, reason: enable ? reason.trim() : null },
          }),
        ),
      ),
    onSuccess: () => {
      onClose();
      setReason("");
      void client.invalidateQueries({ queryKey: ["admin", "investigations"] });
      toast(enable ? "Legal hold placed" : "Legal hold lifted", { tone: "success" });
    },
    onError: (e) => toast("The legal hold was not changed", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <ConfirmDialog
      open={row !== null}
      onOpenChange={(open) => !open && onClose()}
      tone={enable ? "primary" : "danger"}
      title={enable ? `Place ${row?.ref} under legal hold?` : `Lift the legal hold on ${row?.ref}?`}
      description={
        enable
          ? "Retention purges and deletion pause until the hold is lifted (at most three years). The reason is stored encrypted."
          : "Scheduled retention resumes; the investigation may be deleted when its period ends."
      }
      confirmLabel={enable ? "Place hold" : "Lift hold"}
      confirmDisabled={enable && reason.trim().length < 10}
      loading={save.isPending}
      onConfirm={() => save.mutate()}
    >
      {enable ? (
        <Field label="Reason" required hint="At least 10 characters, e.g. the legal matter reference.">
          {(props) => <Textarea {...props} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      ) : null}
    </ConfirmDialog>
  );
}

function DeleteDialog({ row, onClose }: { row: Row | null; onClose: () => void }) {
  const client = useQueryClient();
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const remove = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(
          api.POST("/api/v1/investigations/{investigation_id}/deletion", {
            params: { path: { investigation_id: row!.id } },
            body: { confirm_ref: confirm.trim(), reason: reason.trim() },
          }),
        ),
      ),
    onSuccess: () => {
      onClose();
      setConfirm("");
      setReason("");
      void client.invalidateQueries({ queryKey: ["admin", "investigations"] });
      toast(`${row?.ref} deleted`, { description: "Its keys were destroyed; the purge runs in the background.", tone: "success" });
    },
    onError: (e) => toast("The investigation was not deleted", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <ConfirmDialog
      open={row !== null}
      onOpenChange={(open) => !open && onClose()}
      title={`Delete ${row?.ref} for abuse handling?`}
      description={<p>Administrators may delete an investigation only to handle abuse. This crypto-shreds its content and cannot be undone.</p>}
      confirmLabel="Delete permanently"
      confirmDisabled={confirm.trim().toUpperCase() !== row?.ref || reason.trim().length < 5}
      loading={remove.isPending}
      onConfirm={() => remove.mutate()}
    >
      <div className="space-y-3">
        <Field label={`Type ${row?.ref ?? ""}`} required>
          {(props) => <Input {...props} value={confirm} onChange={(e) => setConfirm(e.target.value)} className="font-mono" autoComplete="off" />}
        </Field>
        <Field label="Reason" required hint="Recorded in the audit log, e.g. the abuse report reference.">
          {(props) => <Textarea {...props} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </div>
    </ConfirmDialog>
  );
}

export function AdminInvestigations() {
  const role = useRole();
  const [status, setStatus] = useState("");
  const [hold, setHold] = useState<Row | null>(null);
  const [remove, setRemove] = useState<Row | null>(null);
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["admin", "investigations", status],
    enabled: role === "admin",
    queryFn: () =>
      unwrap(api.GET("/api/v1/admin/investigations", { params: { query: { status: (status || undefined) as S<"InvestigationStatus"> | undefined } } })),
  });
  if (role && role !== "admin") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Investigations"
        description="The investigation register as metadata only — no titles, purposes or content. Use it for legal holds, data-subject requests and abuse handling."
      />
      <div className="space-y-6">
        <LookupCard />
        <div className="space-y-3">
          <label className="inline-flex items-center gap-2 text-sm">
            <span className="font-medium">Status</span>
            <Select value={status} onChange={(e) => setStatus(e.target.value)} className="h-8 w-44">
              <option value="">All</option>
              {["active", "draft", "pending_review", "suspended", "closed", "archived", "refused", "deleted"].map((s) => (
                <option key={s} value={s}>
                  {s.replace("_", " ")}
                </option>
              ))}
            </Select>
          </label>
          {isPending ? (
            <LoadingBlock />
          ) : error ? (
            <QueryError error={error} retry={() => void refetch()} />
          ) : data?.length ? (
            <Table caption="Investigation register" className="rounded-lg border border-border">
              <thead>
                <tr>
                  <Th>Reference</Th>
                  <Th>Status</Th>
                  <Th>Subject</Th>
                  <Th>Purpose</Th>
                  <Th>Owner</Th>
                  <Th className="text-right">Members</Th>
                  <Th>Created</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {data.map((row) => (
                  <tr key={row.id}>
                    <Td className="font-mono text-xs whitespace-nowrap">
                      {row.ref}
                      {row.legal_hold ? (
                        <Badge className="ml-1.5 border-warning/60 text-warning">
                          <Gavel className="h-3 w-3" aria-hidden /> Hold
                        </Badge>
                      ) : null}
                    </Td>
                    <Td>
                      <InvestigationStatus status={row.status} />
                    </Td>
                    <Td>
                      {SUBJECT_TYPES[row.subject_type]?.label ?? row.subject_type}
                      {row.restricted_mode ? <span className="block text-xs text-warning">Restricted mode</span> : null}
                    </Td>
                    <Td>{PURPOSE_CATEGORIES[row.purpose_category] ?? row.purpose_category}</Td>
                    <Td>{row.owner_name ?? "—"}</Td>
                    <Td className="text-right tabular">{row.member_count}</Td>
                    <Td className="whitespace-nowrap">{formatDate(row.created_at)}</Td>
                    <Td className="text-right">
                      {row.status !== "deleted" ? (
                        <Menu
                          label={`Actions for ${row.ref}`}
                          trigger={
                            <Button size="sm" variant="secondary">
                              Actions
                            </Button>
                          }
                          items={[
                            { label: <><Gavel className="h-4 w-4" aria-hidden /> {row.legal_hold ? "Lift legal hold" : "Place legal hold"}</>, onSelect: () => setHold(row) },
                            {
                              label: <><Trash2 className="h-4 w-4" aria-hidden /> Delete for abuse handling</>,
                              onSelect: () => setRemove(row),
                              danger: true,
                              disabled: row.legal_hold,
                            },
                          ]}
                        />
                      ) : null}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <EmptyState icon={FolderSearch} title="No investigations" />
          )}
        </div>
      </div>
      <LegalHoldDialog row={hold} onClose={() => setHold(null)} />
      <DeleteDialog row={remove} onClose={() => setRemove(null)} />
    </>
  );
}
