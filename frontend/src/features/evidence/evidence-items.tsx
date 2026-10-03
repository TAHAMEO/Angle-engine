"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSearch, Search, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { ProvenanceBadge, VerificationStatusBadge } from "@/components/provenance/badges";
import { ExternalLink } from "@/components/security/external-link";
import { Button } from "@/components/ui/button";
import { Badge, DefinitionList, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/form";
import { ConfirmDialog, Sheet } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { QueryError } from "@/features/common/states";
import { NotesPanel } from "@/features/notes/notes-panel";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { EvidenceOut } from "@/lib/api/types";
import { formatDate, formatDateTime, humanize } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { EVIDENCE_TYPES } from "./labels";

export function EvidenceItemsTable({ onOpen }: { onOpen: (id: string) => void }) {
  const { investigation: inv } = useInvestigation();
  const [type, setType] = useState("");
  const [provenance, setProvenance] = useState("");
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const query = useInfiniteQuery({
    queryKey: qk.evidence(inv.id, { type, provenance, q }),
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/evidence", {
          params: {
            path: { investigation_id: inv.id },
            query: {
              evidence_type: type ? [type] : undefined,
              provenance: provenance ? [provenance as "observed" | "source_reported"] : undefined,
              q: q || undefined,
              limit: 50,
              cursor: pageParam ?? undefined,
            },
          },
        }),
      ),
    getNextPageParam: (last) => (last.has_more ? (last.next_cursor ?? null) : null),
  });
  const rows: EvidenceOut[] = query.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <div className="space-y-4">
      <form
        role="search"
        className="flex flex-wrap items-end gap-2 rounded-lg border border-border bg-surface p-3"
        onSubmit={(event) => {
          event.preventDefault();
          setQ(draft.trim());
        }}
      >
        <label className="min-w-48 flex-1 space-y-1 text-sm">
          <span className="font-medium">Keyword</span>
          <Input value={draft} onChange={(e) => setDraft(e.target.value)} autoComplete="off" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Type</span>
          <Select value={type} onChange={(e) => setType(e.target.value)} className="w-48">
            <option value="">All types</option>
            {Object.entries(EVIDENCE_TYPES).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </Select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Provenance</span>
          <Select value={provenance} onChange={(e) => setProvenance(e.target.value)} className="w-40">
            <option value="">Any</option>
            <option value="observed">Observed</option>
            <option value="source_reported">Source-reported</option>
          </Select>
        </label>
        <Button type="submit" variant="secondary">
          <Search className="h-4 w-4" aria-hidden /> Search
        </Button>
      </form>
      {query.isPending ? (
        <LoadingBlock />
      ) : query.error ? (
        <QueryError error={query.error} retry={() => void query.refetch()} />
      ) : rows.length ? (
        <>
          <Table caption="Evidence items" className="rounded-lg border border-border">
            <thead>
              <tr>
                <Th className="w-24">Item</Th>
                <Th>Excerpt</Th>
                <Th>Source</Th>
                <Th>Type</Th>
                <Th>Captured</Th>
                <Th>Published</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id} className="cursor-pointer hover:bg-surface-2/60" onClick={() => onOpen(item.id)}>
                  <Td>
                    <button
                      type="button"
                      className="font-mono text-xs font-semibold text-primary underline underline-offset-2 hover:decoration-2"
                      onClick={(event) => {
                        event.stopPropagation();
                        onOpen(item.id);
                      }}
                    >
                      {item.label}
                    </button>
                    <span className="mt-1 block">
                      <ProvenanceBadge provenance={item.provenance} size="sm" />
                    </span>
                  </Td>
                  <Td className="max-w-md">
                    {item.excerpt_hidden ? (
                      <span className="text-muted italic">Hidden (flagged as sensitive)</span>
                    ) : (
                      <span className="line-clamp-3">{item.excerpt ?? "—"}</span>
                    )}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {item.source ? (
                      <>
                        <span className="font-mono text-xs">{item.source.label}</span>
                        <span className="block text-xs text-muted">{item.source.host}</span>
                      </>
                    ) : item.origin_image_id ? (
                      <span className="text-xs text-muted">Uploaded image</span>
                    ) : (
                      "—"
                    )}
                  </Td>
                  <Td>{EVIDENCE_TYPES[item.evidence_type] ?? humanize(item.evidence_type)}</Td>
                  <Td className="whitespace-nowrap">{formatDate(item.captured_at)}</Td>
                  <Td className="whitespace-nowrap">{formatDate(item.published_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {query.hasNextPage ? (
            <Button variant="secondary" onClick={() => void query.fetchNextPage()} loading={query.isFetchingNextPage}>
              Load more
            </Button>
          ) : null}
        </>
      ) : (
        <EmptyState icon={FileSearch} title="No evidence matches" />
      )}
    </div>
  );
}

export function EvidenceDrawer({ evidenceId, onClose, onOpenFinding }: { evidenceId: string | null; onClose: () => void; onOpenFinding: (id: string) => void }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const [reveal, setReveal] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { data: item, error, isPending, refetch } = useQuery({
    queryKey: [...qk.evidenceItem(inv.id, evidenceId ?? ""), reveal],
    enabled: Boolean(evidenceId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/evidence/{evidence_id}", {
          params: { path: { investigation_id: inv.id, evidence_id: evidenceId ?? "" }, query: { reveal: reveal || undefined } },
        }),
      ),
  });
  const remove = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(api.DELETE("/api/v1/investigations/{investigation_id}/evidence/{evidence_id}", { params: { path: { investigation_id: inv.id, evidence_id: evidenceId ?? "" } } })),
      ),
    onSuccess: () => {
      setDeleting(false);
      onClose();
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast("Evidence deleted", { description: "Findings that relied on it were re-checked and flagged." });
    },
    onError: (e) => toast("Could not delete the evidence", { description: messageOf(e), tone: "danger" }),
  });
  const redactions = Object.entries(item?.redaction_counts ?? {}).filter(([, n]) => n > 0);
  return (
    <Sheet open={Boolean(evidenceId)} onOpenChange={(open) => !open && onClose()} className="sm:max-w-2xl" title={item ? `Evidence ${item.label}` : "Evidence"} description="Evidence is immutable: its content and capture time never change.">
      {isPending ? (
        <LoadingBlock />
      ) : error || !item ? (
        <div className="p-5">
          <QueryError error={error} retry={() => void refetch()} />
        </div>
      ) : (
        <div className="space-y-6 p-5">
          <div className="flex flex-wrap items-center gap-1.5">
            <ProvenanceBadge provenance={item.provenance} />
            <Badge>{EVIDENCE_TYPES[item.evidence_type] ?? humanize(item.evidence_type)}</Badge>
            {item.sensitivity_flags.map((flag) => (
              <Badge key={flag} className="border-warning/50 text-warning">
                {humanize(flag)}
              </Badge>
            ))}
          </div>
          {item.excerpt_hidden ? (
            <Alert
              tone="warning"
              title="Excerpt hidden"
              action={
                <Button size="sm" variant="secondary" onClick={() => setReveal(true)}>
                  Show (audited)
                </Button>
              }
            >
              This excerpt was flagged as sensitive and is excluded from AI context.
            </Alert>
          ) : item.excerpt ? (
            <blockquote className="rounded-md border border-border bg-surface-2/50 p-3 text-sm leading-relaxed whitespace-pre-line">{item.excerpt}</blockquote>
          ) : null}
          {redactions.length ? (
            <p className="text-xs text-muted">
              Redacted before storage: {redactions.map(([kind, n]) => `${humanize(kind)} × ${n}`).join(", ")}.
            </p>
          ) : null}
          <DefinitionList
            items={[
              [
                "Source",
                item.source ? (
                  <span key="s">
                    <Link href={`${path(inv.id, "sources")}/${item.source.id}`} className="font-mono text-primary underline underline-offset-2 hover:decoration-2">
                      {item.source.label}
                    </Link>{" "}
                    <ExternalLink href={item.source.url} />
                  </span>
                ) : item.origin_image_id ? (
                  <Link key="i" href={`${path(inv.id, "images")}/${item.origin_image_id}`} className="text-primary underline underline-offset-2 hover:decoration-2">
                    Uploaded image
                  </Link>
                ) : (
                  "—"
                ),
              ],
              ["Captured", formatDateTime(item.captured_at)],
              ["Published", formatDateTime(item.published_at)],
              ["Location (generalized)", [item.region, item.country].filter(Boolean).join(", ") || "—"],
              ["Credibility (1–6)", item.credibility ?? "—"],
            ]}
          />
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">Findings citing this evidence</h3>
            {item.findings.length ? (
              <ul className="space-y-1.5">
                {item.findings.map((f) => (
                  <li key={f.id}>
                    <button type="button" onClick={() => onOpenFinding(f.id)} className="w-full rounded-md border border-border p-2.5 text-left text-sm hover:bg-surface-2">
                      <span className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-xs font-semibold">{f.label}</span>
                        <VerificationStatusBadge status={f.verification_status} size="sm" />
                        <span className="text-xs text-muted">{humanize(f.stance)}</span>
                      </span>
                      <span className="mt-1 line-clamp-2 block">{f.statement}</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">Not cited by any finding yet.</p>
            )}
          </section>
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">Notes</h3>
            <NotesPanel targetType="evidence" targetId={item.id} />
          </section>
          {can("content:write") ? (
            <div className="border-t border-border pt-4">
              <Button variant="ghost" size="sm" className="text-danger" onClick={() => setDeleting(true)}>
                <Trash2 className="h-3.5 w-3.5" aria-hidden /> Delete this evidence
              </Button>
            </div>
          ) : null}
          <ConfirmDialog
            open={deleting}
            onOpenChange={setDeleting}
            title={`Delete ${item.label}?`}
            description="The excerpt is destroyed. Relationships that lose their last supporting evidence are removed, and findings that relied on it are downgraded and flagged."
            confirmLabel="Delete evidence"
            loading={remove.isPending}
            onConfirm={() => remove.mutate()}
          />
        </div>
      )}
    </Sheet>
  );
}
