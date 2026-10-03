"use client";

import { useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, MapPin } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Badge, DefinitionList, Table, Td, Th } from "@/components/ui/data";
import { Alert, EmptyState } from "@/components/ui/feedback";
import { api, unwrap } from "@/lib/api/client";
import type { ImageDetail } from "@/lib/api/types";
import { bytes, formatDateTime, humanize, relative } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";

import { STAGE_LABELS } from "./status";

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
  score?: number | null;
}
export interface OcrLine {
  text: string;
  confidence: number;
  box: Box;
}
interface OcrData {
  text?: string;
  lines?: OcrLine[];
  mean_confidence?: number;
  languages?: string;
  redaction_counts?: Record<string, number>;
  flags?: string[];
}
interface MetadataData {
  availability?: string;
  fields?: Record<string, unknown>;
  redacted_fields?: string[];
  location?: { status: string; country_code?: string | null; country_name?: string | null; region_code?: string | null; region_name?: string | null; basis?: string } | null;
  capture_time?: string | null;
  indicators?: { code: string; message: string; caveat: string }[];
  redaction_counts?: Record<string, number>;
}

export const asOcr = (value: unknown) => (value ?? null) as OcrData | null;
export const asMetadata = (value: unknown) => (value ?? null) as MetadataData | null;

const STAGE_TONE: Record<string, string> = {
  ok: "text-success",
  skipped: "text-muted",
  failed: "text-danger",
  timeout: "text-danger",
  policy_blocked: "text-warning",
};

export function OverviewPanel({ image }: { image: ImageDetail }) {
  return (
    <div className="space-y-5">
      <DefinitionList
        items={[
          ["Label", <span key="l" className="font-mono">{image.label}</span>],
          ["File name", image.filename ?? "—"],
          ["Type", image.mime ?? "—"],
          ["Size", bytes(image.byte_size)],
          ["Dimensions", image.width && image.height ? `${image.width} × ${image.height} px` : "—"],
          ["Uploaded", formatDateTime(image.created_at)],
          ["Analysis", image.analysis_completed_at ? `Completed ${formatDateTime(image.analysis_completed_at)}` : image.status_label],
          [
            "Malware scan",
            image.scan.completed_at ? (
              <span key="s">
                {image.scan.engine ?? "Scanner"} · {formatDateTime(image.scan.completed_at)}
                {image.scan.degraded ? <span className="block text-xs text-warning">Basic built-in checks only (development scanner).</span> : null}
              </span>
            ) : (
              "Pending"
            ),
          ],
          [
            "Original file",
            image.original_purged_at
              ? `Deleted ${formatDateTime(image.original_purged_at)} (retention policy)`
              : image.original_purge_after
                ? `Kept until ${formatDateTime(image.original_purge_after)} (${relative(image.original_purge_after)})`
                : image.original_retained
                  ? "Kept (encrypted, never shown)"
                  : "—",
          ],
        ]}
      />
      {image.quarantine_reason ? (
        <Alert tone="danger" title="Quarantined">
          {image.quarantine_reason}
        </Alert>
      ) : null}
      <div>
        <h3 className="mb-2 text-sm font-semibold">Analysis stages</h3>
        {image.stages.length ? (
          <Table caption="Analysis stages">
            <thead>
              <tr>
                <Th>Stage</Th>
                <Th>Result</Th>
                <Th>Version</Th>
                <Th className="text-right">Time</Th>
              </tr>
            </thead>
            <tbody>
              {image.stages.map((stage) => (
                <tr key={stage.analyzer}>
                  <Td>{STAGE_LABELS[stage.analyzer] ?? humanize(stage.analyzer)}</Td>
                  <Td className={STAGE_TONE[stage.status] ?? ""}>
                    {humanize(stage.status)}
                    {stage.error_code ? <span className="block text-xs text-muted">{humanize(stage.error_code)}</span> : null}
                  </Td>
                  <Td className="font-mono text-xs">{stage.version}</Td>
                  <Td className="text-right tabular">{stage.duration_ms !== null ? `${stage.duration_ms} ms` : "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-sm text-muted">Analysis has not run yet.</p>
        )}
      </div>
    </div>
  );
}

export function TextPanel({ image }: { image: ImageDetail }) {
  const { investigation: inv } = useInvestigation();
  const [reveal, setReveal] = useState(false);
  const { data: revealed } = useQuery({
    queryKey: ["investigations", inv.id, "image", image.id, "revealed"],
    enabled: reveal,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/images/{image_id}", {
          params: { path: { investigation_id: inv.id, image_id: image.id }, query: { reveal_sensitive: true } },
        }),
      ),
    staleTime: 0,
    gcTime: 0,
  });
  const ocr = asOcr(reveal && revealed ? revealed.ocr : image.ocr);
  if (!ocr) return <EmptyState title="No text recognized" />;
  const redacted = Object.entries(ocr.redaction_counts ?? {}).filter(([, n]) => n > 0);
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Recognized with Tesseract ({ocr.languages ?? "eng"}), mean confidence {Math.round((ocr.mean_confidence ?? 0) * 100)}%. Sensitive
        values are redacted before storage; raw OCR output is never kept.
      </p>
      {redacted.length ? (
        <div className="flex flex-wrap gap-1.5">
          {redacted.map(([kind, count]) => (
            <Badge key={kind}>
              {humanize(kind)} redacted × {count}
            </Badge>
          ))}
        </div>
      ) : null}
      {image.ocr_hidden && !(reveal && revealed) ? (
        <Alert
          tone="warning"
          title="Hidden: possibly sensitive text"
          action={
            <Button size="sm" variant="secondary" onClick={() => setReveal(true)}>
              <Eye className="h-3.5 w-3.5" aria-hidden /> Show (audited)
            </Button>
          }
        >
          The text was flagged ({(ocr.flags ?? []).map(humanize).join(", ") || "sensitive"}) and is hidden by default. Showing it is recorded in
          the audit log.
        </Alert>
      ) : ocr.lines?.length ? (
        <>
          {reveal ? (
            <Button size="sm" variant="ghost" onClick={() => setReveal(false)}>
              <EyeOff className="h-3.5 w-3.5" aria-hidden /> Hide again
            </Button>
          ) : null}
          <Table caption="Recognized text lines">
            <thead>
              <tr>
                <Th>Text</Th>
                <Th className="text-right">Confidence</Th>
              </tr>
            </thead>
            <tbody>
              {ocr.lines.map((line, index) => (
                <tr key={index}>
                  <Td className="font-mono text-[13px] break-all">{line.text}</Td>
                  <Td className="text-right tabular">{Math.round(line.confidence * 100)}%</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </>
      ) : (
        <EmptyState title="No text recognized" />
      )}
    </div>
  );
}

export function MetadataPanel({ image }: { image: ImageDetail }) {
  const meta = asMetadata(image.metadata);
  if (!meta) return <EmptyState title="No metadata analysis yet" />;
  const fields = Object.entries(meta.fields ?? {}).filter(([, value]) => value !== null && value !== "");
  return (
    <div className="space-y-5">
      <Alert tone="info">Metadata is editable; its presence or absence proves nothing on its own.</Alert>
      <DefinitionList
        items={[
          ["Availability", humanize(meta.availability ?? image.metadata_availability ?? "none")],
          ["Capture time (as recorded)", meta.capture_time ?? "—"],
          [
            "Location",
            meta.location && meta.location.status !== "unresolved" ? (
              <span key="loc" className="inline-flex items-start gap-1.5">
                <MapPin className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" aria-hidden />
                <span>
                  GPS present, generalized to{" "}
                  {meta.location.region_name ? `${meta.location.region_name}, ` : ""}
                  {meta.location.country_name ?? meta.location.country_code}
                  <span className="block text-xs text-muted">Exact coordinates are never stored. {meta.location.basis}</span>
                </span>
              </span>
            ) : meta.location ? (
              "GPS present but outside known boundaries (not stored)"
            ) : (
              "No GPS data"
            ),
          ],
        ]}
      />
      {meta.indicators?.length ? (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Possible edit indicators</h3>
          <ul className="space-y-1.5">
            {meta.indicators.map((indicator) => (
              <li key={indicator.code} className="rounded-md border border-border px-3 py-2 text-sm">
                {indicator.message}
                <span className="block text-xs text-muted">{indicator.caveat}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {fields.length ? (
        <Table caption="Metadata fields kept">
          <thead>
            <tr>
              <Th>Field</Th>
              <Th>Value</Th>
            </tr>
          </thead>
          <tbody>
            {fields.map(([name, value]) => (
              <tr key={name}>
                <Td className="whitespace-nowrap text-muted">{humanize(name)}</Td>
                <Td className="font-mono text-[13px] break-all">{typeof value === "object" ? JSON.stringify(value) : String(value)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : null}
      {meta.redacted_fields?.length ? (
        <p className="text-sm text-muted">
          Removed for privacy (serial numbers, owner names, unique IDs — presence only):{" "}
          {meta.redacted_fields.map(humanize).join(", ")}.
        </p>
      ) : null}
    </div>
  );
}
