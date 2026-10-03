"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ClipboardCheck, RotateCcw, XCircle } from "lucide-react";
import { useState } from "react";

import { CATEGORY_LABELS } from "@/components/security/policy-panel";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card, DefinitionList } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Field, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { NotFoundOrNoAccess, QueryError } from "@/features/common/states";
import { LAWFUL_BASES, PURPOSE_CATEGORIES, SUBJECT_TYPES } from "@/features/investigations/labels";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { ReviewItem, User } from "@/lib/api/types";
import { formatDateTime, humanize } from "@/lib/format";
import { useSession } from "@/lib/session";

type Decision = "approve" | "reject" | "request_changes";

const DECISIONS: Record<Decision, { label: string; help: string; noteRequired: boolean }> = {
  approve: { label: "Approve", help: "The investigation becomes active. Individual subjects run in restricted mode.", noteRequired: false },
  request_changes: { label: "Request changes", help: "Returned to the requester as a draft with your note.", noteRequired: true },
  reject: { label: "Refuse", help: "The investigation is refused and cannot be used. The requester sees your note.", noteRequired: true },
};

function ReviewCard({ item }: { item: ReviewItem }) {
  const client = useQueryClient();
  const [decision, setDecision] = useState<Decision | null>(null);
  const [note, setNote] = useState("");
  const review = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/review", {
          params: { path: { investigation_id: item.id } },
          body: { decision: decision!, note: note.trim() || null },
        }),
      ),
    onSuccess: () => {
      toast(`${item.ref}: decision recorded`, { description: DECISIONS[decision!].help, tone: "success" });
      setDecision(null);
      setNote("");
      void client.invalidateQueries({ queryKey: ["reviews"] });
    },
    onError: (e) => toast("The decision was not recorded", { description: messageOf(e), tone: "danger" }),
  });
  const meta = decision ? DECISIONS[decision] : null;
  return (
    <Card className="space-y-4 p-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-mono text-xs text-muted">{item.ref}</p>
          <h2 className="text-base font-semibold">{item.title}</h2>
          <p className="text-xs text-muted">
            Requested by {item.requested_by ?? "a former member"} · submitted {formatDateTime(item.submitted_at)}
          </p>
        </div>
        <Badge className={item.subject_type === "individual" ? "border-warning/60 text-warning" : ""}>{SUBJECT_TYPES[item.subject_type]?.label ?? item.subject_type}</Badge>
      </div>
      <div>
        <p className="mb-1 text-sm font-medium">Stated purpose</p>
        <p className="rounded-md border border-border bg-surface-2/50 p-3 text-sm whitespace-pre-line">{item.purpose}</p>
      </div>
      <DefinitionList
        items={[
          ["Purpose category", PURPOSE_CATEGORIES[item.purpose_category] ?? item.purpose_category],
          ["Lawful basis", LAWFUL_BASES[item.lawful_basis] ?? item.lawful_basis],
          ["Authorization reference", item.authorization_ref ?? "—"],
          ["Jurisdiction", item.jurisdiction ?? "—"],
        ]}
      />
      {item.policy_categories.length || item.policy_rationale ? (
        <Alert tone="info" title="Why it needs review">
          {item.policy_rationale}
          {item.policy_categories.length ? (
            <span className="block text-xs text-muted">{item.policy_categories.map((c) => CATEGORY_LABELS[c] ?? humanize(c)).join(" · ")}</span>
          ) : null}
        </Alert>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => setDecision("approve")}>
          <CheckCircle2 className="h-4 w-4" aria-hidden /> Approve
        </Button>
        <Button variant="secondary" onClick={() => setDecision("request_changes")}>
          <RotateCcw className="h-4 w-4" aria-hidden /> Request changes
        </Button>
        <Button variant="ghost" className="text-danger" onClick={() => setDecision("reject")}>
          <XCircle className="h-4 w-4" aria-hidden /> Refuse
        </Button>
      </div>
      <Dialog
        open={decision !== null}
        onOpenChange={(open) => !open && setDecision(null)}
        title={meta ? `${meta.label}: ${item.ref}` : ""}
        description={meta?.help}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDecision(null)}>
              Cancel
            </Button>
            <Button
              variant={decision === "reject" ? "danger" : "primary"}
              loading={review.isPending}
              disabled={Boolean(meta?.noteRequired && note.trim().length < 10)}
              onClick={() => review.mutate()}
            >
              {meta?.label}
            </Button>
          </>
        }
      >
        <Field label="Note to the requester" required={meta?.noteRequired} hint="Stored encrypted and recorded with your decision.">
          {(props) => <Textarea {...props} rows={3} value={note} onChange={(e) => setNote(e.target.value)} />}
        </Field>
      </Dialog>
    </Card>
  );
}

export function ReviewQueue() {
  const { data: session } = useSession();
  const user = session?.user as User | undefined;
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["reviews"],
    queryFn: () => unwrap(api.GET("/api/v1/reviews")),
    enabled: user?.role === "supervisor",
  });
  if (user && user.role !== "supervisor") return <NotFoundOrNoAccess />;
  return (
    <>
      <PageHeader
        title="Reviews"
        description="Investigations that need a supervisor's approval. You cannot review investigations you created. Your decision is audited."
      />
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.length ? (
        <div className="space-y-4">
          {data.map((item) => (
            <ReviewCard key={item.id} item={item} />
          ))}
        </div>
      ) : (
        <EmptyState icon={ClipboardCheck} title="Nothing to review" />
      )}
    </>
  );
}
