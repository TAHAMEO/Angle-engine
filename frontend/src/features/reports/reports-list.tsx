"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FilePlus2, FileText, Lock } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Table, Td, Th } from "@/components/ui/data";
import { EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Checkbox, Field, Input, Select } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { PolicyRefusalError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import { formatDateTime } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { CONFIDENTIALITY, OPTIONAL_SECTIONS, SECTION_TITLES } from "./labels";

function NewReportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const router = useRouter();
  const client = useQueryClient();
  const [title, setTitle] = useState(`Investigation report ${inv.ref}`);
  const [confidentiality, setConfidentiality] = useState<(typeof CONFIDENTIALITY)[number]>("Confidential");
  const [sections, setSections] = useState<Set<string>>(new Set(Object.keys(SECTION_TITLES)));
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/reports", {
          params: { path: { investigation_id: inv.id } },
          body: { title: title.trim(), options: { confidentiality, sections: [...sections] } },
        }),
      ),
    onSuccess: (report) => {
      void client.invalidateQueries({ queryKey: qk.reports(inv.id) });
      onOpenChange(false);
      router.push(`${path(inv.id, "reports")}/${report.id}`);
    },
    onError: (e) => {
      if (e instanceof PolicyRefusalError) setPolicy(e.policy);
      else toast("The report was not created", { description: messageOf(e), tone: "danger" });
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="New report"
      description="Reports are built only from recorded evidence. Every factual statement cites its findings, evidence and sources."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={title.trim().length < 3} onClick={() => create.mutate()}>
            Build draft
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Title" required>
          {(props) => <Input {...props} value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} />}
        </Field>
        <Field label="Confidentiality marking">
          {(props) => (
            <Select {...props} value={confidentiality} onChange={(e) => setConfidentiality(e.target.value as (typeof CONFIDENTIALITY)[number])}>
              {CONFIDENTIALITY.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Optional sections</legend>
          <p className="text-[13px] text-muted">Overview, methodology, findings, contradictions, sources, limitations and privacy are always included.</p>
          {[...OPTIONAL_SECTIONS].map((key) => (
            <Checkbox
              key={key}
              label={SECTION_TITLES[key]}
              checked={sections.has(key)}
              onChange={(e) =>
                setSections((current) => {
                  const next = new Set(current);
                  if (e.target.checked) next.add(key);
                  else next.delete(key);
                  return next;
                })
              }
            />
          ))}
        </fieldset>
        {policy ? <PolicyDecisionPanel policy={policy} /> : null}
      </div>
    </Dialog>
  );
}

export function ReportsList() {
  const { investigation: inv, can } = useInvestigation();
  const [creating, setCreating] = useState(false);
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.reports(inv.id),
    queryFn: () => unwrap(api.GET("/api/v1/investigations/{investigation_id}/reports", { params: { path: { investigation_id: inv.id } } })),
  });
  return (
    <>
      <PageHeader
        title="Reports"
        description="Cited reports in HTML, Markdown, JSON or PDF. Finalized reports are locked, hashed and anchored in the audit log."
        actions={
          can("content:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <FilePlus2 className="h-4 w-4" aria-hidden /> New report
            </Button>
          ) : undefined
        }
      />
      {isPending ? (
        <LoadingBlock />
      ) : error ? (
        <QueryError error={error} retry={() => void refetch()} />
      ) : data?.length ? (
        <Table caption="Reports" className="rounded-lg border border-border">
          <thead>
            <tr>
              <Th>Title</Th>
              <Th>Status</Th>
              <Th>Generated</Th>
              <Th>Finalized</Th>
              <Th>SHA-256</Th>
            </tr>
          </thead>
          <tbody>
            {data.map((report) => (
              <tr key={report.id}>
                <Td>
                  <Link href={`${path(inv.id, "reports")}/${report.id}`} className="font-medium text-primary hover:underline">
                    {report.title}
                  </Link>
                </Td>
                <Td>
                  {report.status === "final" ? (
                    <Badge className="border-success/50 text-success">
                      <Lock className="h-3 w-3" aria-hidden /> Final
                    </Badge>
                  ) : (
                    <Badge>Draft</Badge>
                  )}
                </Td>
                <Td className="whitespace-nowrap">{formatDateTime(report.generated_at)}</Td>
                <Td className="whitespace-nowrap">{formatDateTime(report.finalized_at)}</Td>
                <Td className="font-mono text-xs">{report.final_sha256 ? `${report.final_sha256.slice(0, 16)}…` : "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <EmptyState icon={FileText} title="No reports yet">
          Build a draft at any time; it is rebuilt from current evidence until you finalize it.
        </EmptyState>
      )}
      {can("content:write") ? <NewReportDialog open={creating} onOpenChange={setCreating} /> : null}
    </>
  );
}
