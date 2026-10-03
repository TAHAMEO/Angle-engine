"use client";

import { FileQuestion, RefreshCw } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Alert, EmptyState } from "@/components/ui/feedback";
import { ApiError, NotFoundOrForbiddenError, messageOf } from "@/lib/api/errors";

/** 403 and 404 look the same on purpose: the existence of other teams' investigations is not revealed. */
export function NotFoundOrNoAccess() {
  return (
    <EmptyState icon={FileQuestion} title="Not found or no access" action={<Button asChild variant="secondary"><Link href="/investigations">Back to investigations</Link></Button>}>
      This item does not exist, was deleted, or you are not a member of the investigation it belongs to.
    </EmptyState>
  );
}

export function QueryError({ error, retry }: { error: unknown; retry?: () => void }) {
  if (error instanceof NotFoundOrForbiddenError) return <NotFoundOrNoAccess />;
  return (
    <Alert
      tone="danger"
      title="Could not load this content"
      action={
        retry ? (
          <Button size="sm" variant="secondary" onClick={retry}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Retry
          </Button>
        ) : undefined
      }
    >
      {messageOf(error)}
      {error instanceof ApiError && error.requestId ? <span className="block text-xs text-muted">Reference {error.requestId}</span> : null}
    </Alert>
  );
}

const STATUS_TONES: Record<string, string> = {
  draft: "border-border-strong text-muted",
  pending_review: "border-primary/60 text-primary",
  active: "border-success/60 text-success",
  suspended: "border-warning/60 text-warning",
  closed: "border-border-strong text-muted",
  archived: "border-border-strong text-subtle",
  refused: "border-danger/60 text-danger",
  deleted: "border-danger/60 text-danger",
};

export function InvestigationStatus({ status }: { status: string }) {
  return (
    <span className={`badge inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-medium ${STATUS_TONES[status] ?? ""}`}>
      {status === "pending_review" ? "Pending review" : status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
