"use client";

import { Alert } from "@/components/ui/feedback";
import { useInvestigation } from "@/lib/investigation";

export function StatusBanners() {
  const { investigation: inv } = useInvestigation();
  return (
    <div className="mb-4 space-y-2 empty:hidden">
      {inv.restricted_mode ? (
        <Alert tone="warning" title="Restricted mode — individual subject">
          A supervisor approved this investigation. Contact and location data are excluded, redaction is stricter, AI image
          analysis and reverse image search are off, and promotions need a second approver.
        </Alert>
      ) : null}
      {inv.status === "pending_review" ? (
        <Alert tone="info" title="Waiting for supervisor review">
          The investigation is read-only until a supervisor (not you) approves it.
        </Alert>
      ) : null}
      {inv.status === "draft" ? (
        <Alert tone="info" title="Draft">Submit the investigation to start collecting evidence.</Alert>
      ) : null}
      {inv.status === "suspended" ? (
        <Alert tone="danger" title="Suspended">A supervisor suspended this investigation. It is read-only.</Alert>
      ) : null}
      {inv.status === "closed" || inv.status === "archived" ? (
        <Alert tone="info" title={inv.status === "closed" ? "Closed" : "Archived"}>
          The investigation is read-only. Reports can still be exported.
        </Alert>
      ) : null}
      {inv.status === "refused" ? (
        <Alert tone="danger" title="Refused">A supervisor refused this investigation{inv.review_note ? `: ${inv.review_note}` : "."}</Alert>
      ) : null}
      {inv.oversight ? <Alert tone="info">You have temporary, read-only oversight access. Your views are audited.</Alert> : null}
    </div>
  );
}
