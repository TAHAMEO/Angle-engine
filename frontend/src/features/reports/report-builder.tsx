"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileDown, Lock, Plus, RefreshCw, Save, ShieldCheck, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

import { SandboxedFrame } from "@/components/security/sandboxed-frame";
import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Badge, Card, CardHeader, DefinitionList, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock, Spinner } from "@/components/ui/feedback";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/form";
import { ConfirmDialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { withReauth } from "@/features/auth/reauth";
import { QueryError } from "@/features/common/states";
import { BACKGROUND, api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, PreconditionError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import type { ReportOut, S } from "@/lib/api/types";
import { downloadFile } from "@/lib/download";
import { bytes, formatDateTime, relative } from "@/lib/format";
import { path, useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { CONFIDENTIALITY, FORMATS, LINT_LABELS, OPTIONAL_SECTIONS, SECTION_TITLES } from "./labels";

type Custom = { title: string; paragraphs: { text: string; refs: string[] }[] };
const REF = /^[FES]-\d{1,9}$/i;

function parseRefs(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((r) => r.trim().toUpperCase())
    .filter(Boolean);
}

function OptionsEditor({ report, editable }: { report: ReportOut; editable: boolean }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const options = report.options as { confidentiality?: string; sections?: string[]; ai_interaction_id?: string | null };
  const [title, setTitle] = useState(report.title);
  const [confidentiality, setConfidentiality] = useState(options.confidentiality ?? "Confidential");
  const [sections, setSections] = useState<Set<string>>(new Set(options.sections ?? Object.keys(SECTION_TITLES)));
  const [aiId, setAiId] = useState(options.ai_interaction_id ?? "");
  const [custom, setCustom] = useState<Custom[]>((report.custom_sections as Custom[]) ?? []);
  const [refsText, setRefsText] = useState<string[][]>(() => custom.map((s) => s.paragraphs.map((p) => p.refs.join(", "))));
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const { data: narratives } = useQuery({
    queryKey: ["investigations", inv.id, "assistant", "summaries"],
    enabled: editable,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/assistant/requests", {
          params: { path: { investigation_id: inv.id }, query: { task: "summarize" } },
        }),
      ),
  });
  const badRefs = refsText.flat().flatMap(parseRefs).filter((r) => !REF.test(r));
  const save = useMutation({
    mutationFn: (acknowledge: boolean) =>
      unwrap(
        api.PATCH("/api/v1/investigations/{investigation_id}/reports/{report_id}", {
          params: { path: { investigation_id: inv.id, report_id: report.id }, header: { "if-match": `"${report.version}"` } },
          body: {
            title: title.trim(),
            acknowledge_policy_notices: acknowledge,
            options: {
              confidentiality: confidentiality as "Confidential" | "Internal" | "Restricted",
              sections: [...sections],
              ai_interaction_id: aiId || null,
            },
            custom_sections: custom.map((section, i) => ({
              title: section.title,
              paragraphs: section.paragraphs.map((p, j) => ({ text: p.text, refs: parseRefs(refsText[i]?.[j] ?? "") })),
            })),
          },
        }),
      ),
    onSuccess: (updated) => {
      setPolicy(null);
      client.setQueryData(qk.report(inv.id, report.id), updated);
      void client.invalidateQueries({ queryKey: qk.reports(inv.id) });
      toast("Draft rebuilt", { tone: "success" });
    },
    onError: (e) => {
      if (e instanceof PolicyRefusalError || e instanceof PolicyAcknowledgementError) setPolicy(e.policy);
      else if (e instanceof PreconditionError) {
        toast("The report changed elsewhere", { description: "Reloading the latest version.", tone: "danger" });
        void client.invalidateQueries({ queryKey: qk.report(inv.id, report.id) });
      } else toast("The draft was not saved", { description: messageOf(e), tone: "danger" });
    },
  });
  const updateParagraph = (i: number, j: number, text: string) =>
    setCustom((current) => current.map((s, si) => (si === i ? { ...s, paragraphs: s.paragraphs.map((p, pj) => (pj === j ? { ...p, text } : p)) } : s)));
  return (
    <form
      className="space-y-5"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate(false);
      }}
    >
      <fieldset disabled={!editable} className="space-y-4">
        <Field label="Title">{(props) => <Input {...props} value={title} onChange={(e) => setTitle(e.target.value)} />}</Field>
        <Field label="Confidentiality marking">
          {(props) => (
            <Select {...props} value={confidentiality} onChange={(e) => setConfidentiality(e.target.value)}>
              {CONFIDENTIALITY.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div className="space-y-2">
          <p className="text-sm font-medium">Sections</p>
          <ul className="grid gap-1.5 sm:grid-cols-2">
            {Object.entries(SECTION_TITLES).map(([key, label]) => (
              <li key={key}>
                <Checkbox
                  label={label}
                  checked={!OPTIONAL_SECTIONS.has(key) || sections.has(key)}
                  disabled={!OPTIONAL_SECTIONS.has(key)}
                  onChange={(e) =>
                    setSections((current) => {
                      const next = new Set(current);
                      if (e.target.checked) next.add(key);
                      else next.delete(key);
                      return next;
                    })
                  }
                />
              </li>
            ))}
          </ul>
        </div>
        <Field label="AI narrative (optional)" hint="A completed “Summarize” answer from the assistant. It is labelled as AI output and uncited sentences are marked.">
          {(props) => (
            <Select {...props} value={aiId} onChange={(e) => setAiId(e.target.value)}>
              <option value="">None</option>
              {(narratives ?? [])
                .filter((n) => n.status === "completed" && !n.expired)
                .map((n) => (
                  <option key={n.id} value={n.id}>
                    Summary from {formatDateTime(n.completed_at)} ({n.grounding_label ?? n.grounding})
                  </option>
                ))}
            </Select>
          )}
        </Field>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium">Analyst sections</p>
            {editable ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => {
                  setCustom((c) => [...c, { title: "", paragraphs: [{ text: "", refs: [] }] }]);
                  setRefsText((r) => [...r, [""]]);
                }}
              >
                <Plus className="h-3.5 w-3.5" aria-hidden /> Add section
              </Button>
            ) : null}
          </div>
          <p className="text-[13px] text-muted">
            Cite findings, evidence or sources by label (for example F-3, E-12, S-4). Paragraphs without citations are moved to “Unverified
            claims”.
          </p>
          {custom.map((section, i) => (
            <div key={i} className="space-y-2 rounded-md border border-border p-3">
              <div className="flex gap-2">
                <Input
                  aria-label={`Section ${i + 1} title`}
                  placeholder="Section title"
                  value={section.title}
                  onChange={(e) => setCustom((c) => c.map((s, si) => (si === i ? { ...s, title: e.target.value } : s)))}
                />
                {editable ? (
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    aria-label={`Remove section ${i + 1}`}
                    onClick={() => {
                      setCustom((c) => c.filter((_, si) => si !== i));
                      setRefsText((r) => r.filter((_, si) => si !== i));
                    }}
                  >
                    <Trash2 className="h-4 w-4" aria-hidden />
                  </Button>
                ) : null}
              </div>
              {section.paragraphs.map((p, j) => (
                <div key={j} className="space-y-1.5">
                  <Textarea aria-label={`Section ${i + 1} paragraph ${j + 1}`} rows={3} value={p.text} onChange={(e) => updateParagraph(i, j, e.target.value)} />
                  <Input
                    aria-label={`Citations for section ${i + 1} paragraph ${j + 1}`}
                    placeholder="Citations, e.g. F-3, E-12"
                    value={refsText[i]?.[j] ?? ""}
                    onChange={(e) => setRefsText((r) => r.map((row, ri) => (ri === i ? row.map((v, rj) => (rj === j ? e.target.value : v)) : row)))}
                    className="font-mono text-[13px]"
                  />
                </div>
              ))}
              {editable ? (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setCustom((c) => c.map((s, si) => (si === i ? { ...s, paragraphs: [...s.paragraphs, { text: "", refs: [] }] } : s)));
                    setRefsText((r) => r.map((row, ri) => (ri === i ? [...row, ""] : row)));
                  }}
                >
                  <Plus className="h-3.5 w-3.5" aria-hidden /> Paragraph
                </Button>
              ) : null}
            </div>
          ))}
          {badRefs.length ? <p className="text-[13px] text-danger">Not a valid citation: {badRefs.join(", ")}. Use F-n, E-n or S-n.</p> : null}
        </div>
      </fieldset>
      {policy ? (
        <PolicyDecisionPanel policy={policy} onAcknowledge={policy.decision === "warn" ? () => save.mutate(true) : undefined} acknowledging={save.isPending} />
      ) : null}
      {editable ? (
        <Button type="submit" variant="primary" loading={save.isPending} disabled={badRefs.length > 0 || title.trim().length < 3}>
          <Save className="h-4 w-4" aria-hidden /> Save and rebuild
        </Button>
      ) : null}
    </form>
  );
}

function Exports({ report }: { report: ReportOut }) {
  const { investigation: inv, can } = useInvestigation();
  const client = useQueryClient();
  const [format, setFormat] = useState<S<"ExportIn">["format"]>("pdf");
  const { data } = useQuery({
    queryKey: qk.exports(inv.id, report.id),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/reports/{report_id}/exports", {
          params: { path: { investigation_id: inv.id, report_id: report.id } },
          headers: BACKGROUND,
        }),
      ),
    refetchInterval: (query) => (query.state.data?.some((x) => x.status === "pending" || x.status === "running") ? 1500 : false),
  });
  const request = useMutation({
    mutationFn: () =>
      withReauth(() =>
        unwrap(
          api.POST("/api/v1/investigations/{investigation_id}/reports/{report_id}/exports", {
            params: { path: { investigation_id: inv.id, report_id: report.id } },
            body: { format },
          }),
        ),
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: qk.exports(inv.id, report.id) });
      toast("Export requested", { description: "It is rendered offline and kept for 24 hours." });
    },
    onError: (e) => toast("The export was not requested", { description: messageOf(e), tone: "danger" }),
  });
  if (!can("report:export")) return null;
  return (
    <Card>
      <CardHeader title="Exports" description="Exports are encrypted, expire after 24 hours and need a recent password confirmation." />
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Format</span>
            <Select value={format} onChange={(e) => setFormat(e.target.value as typeof format)} className="w-52">
              {FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </Select>
          </label>
          <Button variant="secondary" loading={request.isPending} onClick={() => request.mutate()}>
            <FileDown className="h-4 w-4" aria-hidden /> Export
          </Button>
        </div>
        {data?.length ? (
          <Table caption="Exports">
            <thead>
              <tr>
                <Th>Format</Th>
                <Th>Status</Th>
                <Th>Size</Th>
                <Th>Expires</Th>
                <Th><span className="sr-only">Download</span></Th>
              </tr>
            </thead>
            <tbody>
              {data.map((x) => (
                <tr key={x.id}>
                  <Td className="uppercase">{x.format}</Td>
                  <Td>
                    {x.status === "pending" || x.status === "running" ? <Spinner className="mr-1 h-3.5 w-3.5" label="Rendering" /> : null}
                    {x.status}
                  </Td>
                  <Td>{bytes(x.byte_size)}</Td>
                  <Td className="whitespace-nowrap">{relative(x.expires_at)}</Td>
                  <Td>
                    {x.status === "ready" ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          void downloadFile(
                            `/api/v1/investigations/${inv.id}/reports/${report.id}/exports/${x.id}/download`,
                            `${inv.ref}-report.${x.format === "markdown" ? "md" : x.format}`,
                          ).catch((e) => toast("Download failed", { description: messageOf(e), tone: "danger" }))
                        }
                      >
                        <Download className="h-3.5 w-3.5" aria-hidden /> Download
                      </Button>
                    ) : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : null}
      </div>
    </Card>
  );
}

export function ReportBuilder() {
  const { investigation: inv, can } = useInvestigation();
  const { reportId } = useParams<{ reportId: string }>();
  const router = useRouter();
  const client = useQueryClient();
  const [finalizing, setFinalizing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { data: report, error, isPending, refetch } = useQuery({
    queryKey: qk.report(inv.id, reportId),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/reports/{report_id}", { params: { path: { investigation_id: inv.id, report_id: reportId } } }),
      ),
  });
  const params = { path: { investigation_id: inv.id, report_id: reportId } };
  const refresh = useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/investigations/{investigation_id}/reports/{report_id}/refresh", { params })),
    onSuccess: (updated) => {
      client.setQueryData(qk.report(inv.id, reportId), updated);
      toast("Draft rebuilt from the latest evidence");
    },
    onError: (e) => toast("Could not rebuild", { description: messageOf(e), tone: "danger" }),
  });
  const finalize = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/reports/{report_id}/finalize", {
          params: { ...params, header: { "if-match": `"${report?.version ?? 0}"` } },
        }),
      ),
    onSuccess: (updated) => {
      setFinalizing(false);
      client.setQueryData(qk.report(inv.id, reportId), updated);
      void client.invalidateQueries({ queryKey: qk.reports(inv.id) });
      toast("Report finalized", { description: "It is now locked; its hash is recorded in the audit log.", tone: "success" });
    },
    onError: (e) => toast("The report was not finalized", { description: messageOf(e), tone: "danger" }),
  });
  const remove = useMutation({
    mutationFn: () => unwrap(api.DELETE("/api/v1/investigations/{investigation_id}/reports/{report_id}", { params })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: qk.reports(inv.id) });
      router.push(path(inv.id, "reports"));
    },
    onError: (e) => toast("Could not delete the draft", { description: messageOf(e), tone: "danger" }),
  });
  if (isPending) return <LoadingBlock />;
  if (error || !report) return <QueryError error={error} retry={() => void refetch()} />;
  const final = report.status === "final";
  const editable = !final && can("content:write");
  const lint = Object.entries(report.lint).filter(([, n]) => n > 0);
  return (
    <>
      <PageHeader
        eyebrow={
          <Link href={path(inv.id, "reports")} className="inline-flex items-center gap-1 hover:underline">
            <ArrowLeft className="h-3 w-3" aria-hidden /> Reports
          </Link>
        }
        title={report.title}
        description={
          final ? (
            <span className="inline-flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5" aria-hidden /> Final — locked on {formatDateTime(report.finalized_at)}
            </span>
          ) : (
            `Draft — rebuilt ${formatDateTime(report.generated_at)}`
          )
        }
        actions={
          editable ? (
            <>
              <Button variant="secondary" loading={refresh.isPending} onClick={() => refresh.mutate()}>
                <RefreshCw className="h-4 w-4" aria-hidden /> Rebuild
              </Button>
              <Button variant="ghost" onClick={() => setDeleting(true)}>
                <Trash2 className="h-4 w-4" aria-hidden /> Delete
              </Button>
              <Button variant="primary" onClick={() => setFinalizing(true)}>
                <ShieldCheck className="h-4 w-4" aria-hidden /> Finalize
              </Button>
            </>
          ) : undefined
        }
      />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="space-y-6">
          {lint.length ? (
            <Alert tone="warning" title="Citation check">
              <ul className="list-disc space-y-0.5 pl-4">
                {lint.map(([key, n]) => (
                  <li key={key}>
                    {n} {LINT_LABELS[key] ?? key}
                  </li>
                ))}
              </ul>
            </Alert>
          ) : (
            <Alert tone="success" title="Citation check passed">
              Every factual statement in this report cites recorded evidence.
            </Alert>
          )}
          {final ? (
            <Card>
              <CardHeader title="Integrity" />
              <div className="space-y-3 p-4">
                <DefinitionList
                  items={[
                    ["SHA-256", <span key="h" className="font-mono text-xs break-all">{report.final_sha256}</span>],
                    ["Audit log entry", report.audit_seq ? `#${report.audit_seq}` : "—"],
                    ["Finalized", formatDateTime(report.finalized_at)],
                    [
                      "Verification",
                      report.verified ? (
                        <Badge key="v" className="border-success/50 text-success">
                          Content matches its integrity code
                        </Badge>
                      ) : (
                        <Badge key="v" className="border-danger/50 text-danger">
                          Integrity check failed
                        </Badge>
                      ),
                    ],
                  ]}
                />
              </div>
            </Card>
          ) : null}
          <Card>
            <CardHeader title="Contents" />
            <div className="p-4">
              <OptionsEditor key={report.version} report={report} editable={editable} />
            </div>
          </Card>
          <Exports report={report} />
        </div>
        <Card className="min-w-0 overflow-hidden">
          <CardHeader title="Preview" description="Rendered by the server in an isolated frame: no scripts, no external requests." />
          <div className="p-3">
            {report.document ? (
              <SandboxedFrame
                key={report.version}
                src={`/api/v1/investigations/${inv.id}/reports/${report.id}/preview?v=${report.version}`}
                title={`Preview of ${report.title}`}
                className="h-[80vh] w-full rounded-md border border-border bg-white"
              />
            ) : (
              <EmptyState title="No preview yet" />
            )}
          </div>
        </Card>
      </div>
      <ConfirmDialog
        open={finalizing}
        onOpenChange={setFinalizing}
        title="Finalize this report?"
        tone="primary"
        description={
          <>
            <p>The report is rebuilt one last time, then locked: it can no longer be edited or deleted.</p>
            <p>Its SHA-256 hash and a keyed integrity code are recorded, and the hash is anchored in the audit log.</p>
            {lint.length ? <p className="text-warning">Some content was moved to “Unverified claims” by the citation check.</p> : null}
          </>
        }
        confirmLabel="Finalize"
        loading={finalize.isPending}
        onConfirm={() => finalize.mutate()}
      />
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title="Delete this draft?"
        confirmLabel="Delete"
        loading={remove.isPending}
        onConfirm={() => remove.mutate()}
      />
    </>
  );
}
