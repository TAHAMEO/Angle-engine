"use client";

import { Ban, Hourglass, Lightbulb, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { PolicyAlternative, PolicyPayload } from "@/lib/api/errors";

export const CATEGORY_LABELS: Record<string, string> = {
  home_address: "Home addresses of individuals",
  location_tracking: "Tracking a person's location or movements",
  facial_identification: "Identifying people by their face",
  private_contact_info: "Private contact details",
  private_personal_data: "Private personal data",
  harassment_stalking: "Harassment or stalking",
  doxxing: "Exposing someone's identity (doxxing)",
  privacy_circumvention: "Bypassing privacy controls, logins or paywalls",
  leaked_or_restricted_data: "Leaked, breached or restricted data",
  targeted_surveillance: "Targeted surveillance of a person",
  sensitive_attribute_inference: "Inferring sensitive personal attributes",
  impersonation: "Impersonation",
  individual_subject: "Research focused on an individual",
  broad_location_only: "Locations more precise than a region",
};

export function LawfulAlternatives({
  alternatives,
  onUse,
}: {
  alternatives: PolicyAlternative[];
  onUse?: (alternative: PolicyAlternative) => void;
}) {
  if (!alternatives.length) return null;
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">Lawful alternatives</p>
      <ul className="grid gap-2 sm:grid-cols-2">
        {alternatives.map((alt, index) => (
          <li key={index} className="flex flex-col gap-2 rounded-md border border-border bg-surface p-3">
            <div className="flex items-start gap-2 text-sm">
              <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
              <span>{alt.label}</span>
            </div>
            {alt.template ? <p className="rounded bg-surface-2 px-2 py-1 text-[13px] text-muted">{alt.template}</p> : null}
            {onUse && (alt.template || alt.connector_id) ? (
              <Button size="sm" variant="outline" className="self-start" onClick={() => onUse(alt)}>
                Use this instead
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The outcome of an acceptable-use screening. A refusal never echoes the submitted text back; it explains the
 * category and offers lawful alternatives that prefill a safe template.
 */
export function PolicyDecisionPanel({
  policy,
  onUseAlternative,
  onAcknowledge,
  acknowledging,
}: {
  policy: PolicyPayload;
  onUseAlternative?: (alternative: PolicyAlternative) => void;
  onAcknowledge?: () => void;
  acknowledging?: boolean;
}) {
  const categories = policy.categories.map((c) => CATEGORY_LABELS[c] ?? c.replaceAll("_", " "));
  if (policy.decision === "refuse") {
    return (
      <section role="alert" aria-labelledby="policy-refused-title" className="space-y-3 rounded-lg border border-danger/50 bg-danger-bg p-4">
        <div className="flex items-start gap-2.5">
          <Ban className="mt-0.5 h-5 w-5 shrink-0 text-danger" aria-hidden />
          <div className="space-y-1">
            <h2 id="policy-refused-title" className="font-semibold">
              Angel Engine can&apos;t help with this request
            </h2>
            {policy.rationale ? <p className="text-sm">{policy.rationale}</p> : null}
            {categories.length ? (
              <p className="text-sm text-muted">Concern: {categories.join(" · ")}</p>
            ) : null}
          </div>
        </div>
        <LawfulAlternatives alternatives={policy.alternatives ?? []} onUse={onUseAlternative} />
        <p className="text-xs text-muted">
          Repeated refused requests are flagged for supervisor review. If you believe this is a mistake, ask a supervisor.
        </p>
      </section>
    );
  }
  if (policy.decision === "review") {
    return (
      <section role="status" className="flex items-start gap-2.5 rounded-lg border border-primary/40 bg-info-bg p-4">
        <Hourglass className="mt-0.5 h-5 w-5 shrink-0 text-primary" aria-hidden />
        <div className="space-y-1 text-sm">
          <p className="font-semibold">This needs a supervisor&apos;s review</p>
          <p>{policy.rationale ?? "A supervisor (not you) must approve this before it runs."}</p>
          {categories.length ? <p className="text-muted">Reason: {categories.join(" · ")}</p> : null}
        </div>
      </section>
    );
  }
  if (policy.decision === "warn") {
    return (
      <section role="alert" className="space-y-3 rounded-lg border border-warning/50 bg-warning-bg p-4">
        <div className="flex items-start gap-2.5">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-semibold">Please read before continuing</p>
            <ul className="list-disc space-y-1 pl-4">
              {(policy.notices?.length ? policy.notices : [policy.rationale ?? ""]).filter(Boolean).map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          </div>
        </div>
        {onAcknowledge ? (
          <Button variant="primary" size="sm" onClick={onAcknowledge} loading={acknowledging}>
            I understand — continue
          </Button>
        ) : null}
      </section>
    );
  }
  return null;
}
