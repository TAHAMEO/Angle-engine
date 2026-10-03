"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ClipboardCheck, FilePlus2, FolderSearch, ShieldCheck, UserCog } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, Stat } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { InvestigationStatus, QueryError } from "@/features/common/states";
import { InvestigationTable } from "@/features/investigations/investigation-table";
import { useDashboard } from "@/features/investigations/overview";
import { api, unwrap } from "@/lib/api/client";
import type { User } from "@/lib/api/types";
import { useInvestigationDetail } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";
import { useSession } from "@/lib/session";

import { StatusBreakdown, WarningsList } from "./overview-widgets";

function ContinueCard({ id }: { id: string }) {
  const { data: inv } = useInvestigationDetail(id);
  const { data } = useDashboard(id);
  if (!inv) return null;
  return (
    <Card>
      <CardHeader
        title="Continue where you left off"
        description={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{inv.ref}</span> <InvestigationStatus status={inv.status} />
          </span>
        }
        action={
          <Button asChild size="sm" variant="primary">
            <Link href={`/investigations/${id}`}>
              Open <ArrowRight className="h-3.5 w-3.5" aria-hidden />
            </Link>
          </Button>
        }
      />
      <div className="space-y-4 p-4">
        <p className="font-medium">{inv.title}</p>
        {data ? (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Evidence" value={data.stats.evidence} />
              <Stat label="Sources" value={data.stats.sources} />
              <Stat label="Findings" value={data.stats.findings} />
              <Stat label="Images" value={data.stats.images} />
            </div>
            <WarningsList warnings={data.warnings} />
            <StatusBreakdown byStatus={data.stats.by_status} investigationId={id} />
          </>
        ) : null}
      </div>
    </Card>
  );
}

function SupervisorPanel() {
  const { data } = useQuery({ queryKey: ["reviews"], queryFn: () => unwrap(api.GET("/api/v1/reviews")) });
  return (
    <Card>
      <CardHeader title="Waiting for your review" description="Investigations of individuals and policy reviews need a supervisor who did not create them." />
      <div className="flex items-center justify-between gap-3 p-4">
        <p className="text-3xl font-semibold tabular">{data?.length ?? "—"}</p>
        <Button asChild variant="secondary" size="sm">
          <Link href="/reviews">
            <ClipboardCheck className="h-4 w-4" aria-hidden /> Open review queue
          </Link>
        </Button>
      </div>
    </Card>
  );
}

function GovernanceDashboard({ user }: { user: User }) {
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Administrators and auditors manage the platform and its audit trail. Investigation content is visible only to investigation members."
      />
      <div className="grid gap-4 md:grid-cols-2">
        {user.role === "admin" ? (
          <Card className="p-5">
            <UserCog className="mb-2 h-6 w-6 text-primary" aria-hidden />
            <h2 className="font-semibold">Administration</h2>
            <p className="mt-1 text-sm text-muted">Approve access requests, manage roles, connectors, retention, abuse reports and failed jobs.</p>
            <Button asChild variant="secondary" size="sm" className="mt-3">
              <Link href="/admin/users">Open administration</Link>
            </Button>
          </Card>
        ) : null}
        <Card className="p-5">
          <ShieldCheck className="mb-2 h-6 w-6 text-primary" aria-hidden />
          <h2 className="font-semibold">Audit log</h2>
          <p className="mt-1 text-sm text-muted">Review the tamper-evident activity record and verify its hash chain.</p>
          <Button asChild variant="secondary" size="sm" className="mt-3">
            <Link href="/admin/audit-log">Open audit log</Link>
          </Button>
        </Card>
      </div>
    </>
  );
}

export function WorkspaceDashboard() {
  const { data: session } = useSession();
  const user = session?.user as User | undefined;
  const contentRole = user && ["supervisor", "investigator", "viewer"].includes(user.role);
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.investigations({ limit: 8 }),
    queryFn: () => unwrap(api.GET("/api/v1/investigations", { params: { query: { limit: 8 } } })),
    enabled: Boolean(contentRole),
  });
  if (!user) return <LoadingBlock />;
  if (!contentRole) return <GovernanceDashboard user={user} />;
  const canCreate = user.role === "supervisor" || user.role === "investigator";
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Investigate public evidence, verify sources, protect privacy — and never turn an AI inference into an identity claim."
        actions={
          canCreate ? (
            <Button asChild variant="primary">
              <Link href="/investigations/new">
                <FilePlus2 className="h-4 w-4" aria-hidden /> New investigation
              </Link>
            </Button>
          ) : undefined
        }
      />
      <div className="space-y-6">
        {user.role === "supervisor" ? <SupervisorPanel /> : null}
        {user.last_active_investigation_id ? <ContinueCard id={user.last_active_investigation_id} /> : null}
        <section aria-labelledby="recent-heading" className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 id="recent-heading" className="text-base font-semibold">
              Recent investigations
            </h2>
            <Link href="/investigations" className="text-[13px] text-primary underline underline-offset-2 hover:decoration-2">
              Investigation history
            </Link>
          </div>
          {isPending ? (
            <LoadingBlock />
          ) : error ? (
            <QueryError error={error} retry={() => void refetch()} />
          ) : data?.length ? (
            <InvestigationTable items={data} caption="Recent investigations" />
          ) : (
            <EmptyState
              icon={FolderSearch}
              title="No investigations yet"
              action={
                canCreate ? (
                  <Button asChild variant="primary">
                    <Link href="/investigations/new">Start an investigation</Link>
                  </Button>
                ) : undefined
              }
            >
              Every investigation starts with a stated purpose and legal basis. Investigations of individual people need a supervisor&apos;s approval.
            </EmptyState>
          )}
        </section>
      </div>
    </>
  );
}
