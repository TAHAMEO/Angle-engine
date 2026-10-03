"use client";

import { KeyRound, Lock, ShieldCheck } from "lucide-react";

import { ExternalLink } from "@/components/security/external-link";
import { Badge, Card } from "@/components/ui/data";
import { LoadingBlock } from "@/components/ui/feedback";
import type { ConnectorOut } from "@/lib/api/types";
import { humanize } from "@/lib/format";

import { INPUT_TYPES } from "./labels";

const STATUS_TONE: Record<string, string> = {
  ready: "border-success/50 text-success",
  needs_key: "border-warning/60 text-warning",
  disabled: "border-border-strong text-muted",
};

export function ConnectorCatalog({ connectors, loading }: { connectors?: ConnectorOut[]; loading?: boolean }) {
  if (loading) return <LoadingBlock />;
  const groups = new Map<string, ConnectorOut[]>();
  for (const connector of connectors ?? []) {
    const list = groups.get(connector.category_label) ?? [];
    list.push(connector);
    groups.set(connector.category_label, list);
  }
  return (
    <div className="space-y-6">
      <p className="max-w-3xl text-sm text-muted">
        Connectors use official APIs or public pages that allow automated access. They never log in, solve CAPTCHAs, bypass paywalls or
        query people-search and breach sources.
      </p>
      {[...groups.entries()].map(([category, list]) => (
        <section key={category} aria-labelledby={`cat-${category}`} className="space-y-2">
          <h3 id={`cat-${category}`} className="text-sm font-semibold">
            {category}
          </h3>
          <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {list.map((connector) => (
              <li key={connector.id}>
                <Card className="h-full space-y-2 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <p className="font-medium">{connector.name}</p>
                    <Badge className={STATUS_TONE[connector.status] ?? ""}>{humanize(connector.status)}</Badge>
                  </div>
                  <p className="text-[13px] text-muted">{connector.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {connector.input_types.map((type) => (
                      <Badge key={type}>{INPUT_TYPES[type] ?? type}</Badge>
                    ))}
                    {connector.requires_key ? (
                      <Badge>
                        <KeyRound className="h-3 w-3" aria-hidden /> API key
                      </Badge>
                    ) : null}
                    {connector.allowed_in_restricted_mode ? (
                      <Badge>
                        <ShieldCheck className="h-3 w-3" aria-hidden /> Restricted mode
                      </Badge>
                    ) : (
                      <Badge className="text-muted">
                        <Lock className="h-3 w-3" aria-hidden /> Not in restricted mode
                      </Badge>
                    )}
                  </div>
                  {connector.reason ? <p className="text-xs text-warning">{connector.reason}</p> : null}
                  <p className="text-xs text-muted">
                    {connector.terms_note} <ExternalLink href={connector.docs_url}>Docs</ExternalLink>
                  </p>
                </Card>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
