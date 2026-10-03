"use client";

import { useState } from "react";
import { Bar, BarChart, Brush, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Button } from "@/components/ui/button";
import { Table, Td, Th } from "@/components/ui/data";
import type { EventOut } from "@/lib/api/types";

export interface Bucket {
  key: string;
  count: number;
  contradicted: number;
}

/** Group events by year (long spans) or month (short spans). Deterministic and timezone-free (UTC). */
export function bucketize(events: EventOut[]): { buckets: Bucket[]; unit: "month" | "year" } {
  if (!events.length) return { buckets: [], unit: "month" };
  const times = events.map((e) => new Date(e.occurred_start).getTime());
  const span = Math.max(...times) - Math.min(...times);
  const unit = span > 1000 * 60 * 60 * 24 * 365 * 4 ? "year" : "month";
  const counts = new Map<string, Bucket>();
  for (const event of events) {
    const iso = new Date(event.occurred_start).toISOString();
    const key = unit === "year" ? iso.slice(0, 4) : iso.slice(0, 7);
    const bucket = counts.get(key) ?? { key, count: 0, contradicted: 0 };
    bucket.count += 1;
    if (event.verification_status === "contradicted") bucket.contradicted += 1;
    counts.set(key, bucket);
  }
  // Fill gaps so the axis is continuous.
  const keys = [...counts.keys()].sort();
  const filled: Bucket[] = [];
  const first = keys[0]!;
  const last = keys[keys.length - 1]!;
  if (unit === "year") {
    for (let y = Number(first); y <= Number(last); y += 1) filled.push(counts.get(String(y)) ?? { key: String(y), count: 0, contradicted: 0 });
  } else {
    let [y, m] = first.split("-").map(Number) as [number, number];
    const [ly, lm] = last.split("-").map(Number) as [number, number];
    while (y < ly || (y === ly && m <= lm)) {
      const key = `${y}-${String(m).padStart(2, "0")}`;
      filled.push(counts.get(key) ?? { key, count: 0, contradicted: 0 });
      m += 1;
      if (m > 12) {
        m = 1;
        y += 1;
      }
    }
  }
  return { buckets: filled, unit };
}

export function DensityChart({ events, onRange }: { events: EventOut[]; onRange: (from: string | null, to: string | null) => void }) {
  const { buckets, unit } = bucketize(events);
  const [table, setTable] = useState(false);
  if (buckets.length < 2) return null;
  const boundary = (key: string, end: boolean) =>
    unit === "year" ? `${key}-${end ? "12-31" : "01-01"}` : end ? new Date(Date.UTC(Number(key.slice(0, 4)), Number(key.slice(5, 7)), 0)).toISOString().slice(0, 10) : `${key}-01`;
  return (
    <figure className="space-y-2 rounded-lg border border-border bg-surface p-3">
      <figcaption className="flex items-center justify-between gap-2 text-sm">
        <span className="font-medium">Events per {unit}</span>
        <Button size="sm" variant="ghost" onClick={() => setTable(!table)} aria-pressed={table}>
          {table ? "Show chart" : "Show as table"}
        </Button>
      </figcaption>
      {table ? (
        <Table caption={`Events per ${unit}`}>
          <thead>
            <tr>
              <Th>{unit === "year" ? "Year" : "Month"}</Th>
              <Th className="text-right">Events</Th>
              <Th className="text-right">Contradicted</Th>
            </tr>
          </thead>
          <tbody>
            {buckets
              .filter((b) => b.count)
              .map((b) => (
                <tr key={b.key}>
                  <Td className="font-mono">{b.key}</Td>
                  <Td className="text-right tabular">{b.count}</Td>
                  <Td className="text-right tabular">{b.contradicted}</Td>
                </tr>
              ))}
          </tbody>
        </Table>
      ) : (
        <div className="h-44" aria-hidden>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={buckets} margin={{ top: 4, right: 8, bottom: 0, left: -24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="key" tick={{ fill: "var(--muted)", fontSize: 11 }} stroke="var(--border-strong)" />
              <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} stroke="var(--border-strong)" />
              <Tooltip
                cursor={{ fill: "var(--surface-3)" }}
                contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, color: "var(--foreground)", fontSize: 12 }}
              />
              <Bar dataKey="count" name="Events" fill="var(--primary)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
              <Bar dataKey="contradicted" name="Contradicted" fill="var(--st-contradicted)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
              <Brush
                dataKey="key"
                height={18}
                stroke="var(--primary)"
                fill="var(--surface)"
                travellerWidth={8}
                onChange={(range) => {
                  const start = buckets[range.startIndex ?? 0];
                  const end = buckets[range.endIndex ?? buckets.length - 1];
                  const whole = (range.startIndex ?? 0) === 0 && (range.endIndex ?? buckets.length - 1) === buckets.length - 1;
                  onRange(whole || !start ? null : boundary(start.key, false), whole || !end ? null : boundary(end.key, true));
                }}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      {!table ? <p className="text-xs text-muted">Drag the handles under the chart to narrow the list to a period.</p> : null}
    </figure>
  );
}
