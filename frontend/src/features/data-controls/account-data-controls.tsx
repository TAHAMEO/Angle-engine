"use client";

import { useQuery } from "@tanstack/react-query";
import { FileText, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { CATEGORY_LABELS } from "@/components/security/policy-panel";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader, Table, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { formatDateTime, humanize } from "@/lib/format";

const LEGAL = [
  { href: "/legal/privacy", label: "Privacy Policy" },
  { href: "/legal/terms", label: "Terms of Use" },
  { href: "/legal/acceptable-use", label: "Acceptable Use Policy" },
  { href: "/legal/responsible-use", label: "Responsible Use & Methodology" },
];

function Decisions() {
  const { data, error, isPending, refetch } = useQuery({
    queryKey: ["me", "policy-decisions", "all"],
    queryFn: () => unwrap(api.GET("/api/v1/me/policy-decisions")),
  });
  if (isPending) return <LoadingBlock />;
  if (error) return <QueryError error={error} retry={() => void refetch()} />;
  const notable = (data ?? []).filter((d) => d.decision !== "allow");
  if (!notable.length) return <EmptyState icon={ShieldCheck} title="No warnings, reviews or refusals" className="py-6" />;
  return (
    <Table caption="Acceptable-use decisions about your requests">
      <thead>
        <tr>
          <Th>When</Th>
          <Th>Decision</Th>
          <Th>Where</Th>
          <Th>Concern</Th>
          <Th>Explanation</Th>
        </tr>
      </thead>
      <tbody>
        {notable.map((d) => (
          <tr key={d.id}>
            <Td className="whitespace-nowrap">{formatDateTime(d.created_at)}</Td>
            <Td>
              <Badge className={d.decision === "refuse" ? "border-danger/50 text-danger" : d.decision === "review" ? "border-primary/50 text-primary" : "border-warning/50 text-warning"}>
                {humanize(d.decision)}
              </Badge>
            </Td>
            <Td>{humanize(d.surface)}</Td>
            <Td className="text-xs">{d.categories.map((c) => CATEGORY_LABELS[c] ?? humanize(c)).join(", ") || "—"}</Td>
            <Td className="max-w-md text-muted">{d.rationale}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function AccountDataControls() {
  return (
    <>
      <PageHeader
        title="Privacy & data controls"
        description="What Angel Engine keeps about you, the acceptable-use decisions about your requests, and the policies that apply."
      />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader title="What is stored about you" />
          <div className="space-y-3 p-4 text-sm">
            <ul className="list-disc space-y-1 pl-4">
              <li>Your account: email, display name, role, password hash, encrypted two-factor secret and hashed recovery codes.</li>
              <li>Sessions: browser family and timestamps (no IP addresses; a monthly-rotated pseudonym is used for security events).</li>
              <li>Your attestations and the policy versions you accepted.</li>
              <li>Audit-log entries of your actions (who, what, when — never evidence content).</li>
              <li>Acceptable-use decisions about your requests (the request text is encrypted and deleted after 90 days).</li>
            </ul>
            <div className="flex flex-wrap gap-2">
              <Button asChild variant="secondary" size="sm">
                <Link href="/settings/sessions">Manage sessions</Link>
              </Button>
              <Button asChild variant="secondary" size="sm">
                <Link href="/report-abuse">Make a data request</Link>
              </Button>
            </div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Policies" />
          <ul className="divide-y divide-border">
            {LEGAL.map((doc) => (
              <li key={doc.href}>
                <Link href={doc.href} className="flex items-center gap-2 px-4 py-3 text-sm hover:bg-surface-2">
                  <FileText className="h-4 w-4 text-muted" aria-hidden /> {doc.label}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader
            title="Acceptable-use decisions"
            description="Warnings, reviews and refusals of your requests. Repeated refusals are flagged for supervisor review."
          />
          <div className="p-4">
            <Decisions />
          </div>
        </Card>
      </div>
    </>
  );
}
