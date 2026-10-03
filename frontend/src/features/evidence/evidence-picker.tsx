"use client";

import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/feedback";
import { Input, Select } from "@/components/ui/form";
import { api, unwrap } from "@/lib/api/client";
import { formatDate, humanize } from "@/lib/format";
import { useInvestigation } from "@/lib/investigation";

export interface PickedEvidence {
  evidence_id: string;
  label: string;
  stance: "supports" | "contradicts" | "context";
  directly_states: boolean;
}

/** Search evidence items (keyword over the encrypted blind index) and pick them with a stance. */
export function EvidencePicker({ value, onChange, exclude = [] }: { value: PickedEvidence[]; onChange: (value: PickedEvidence[]) => void; exclude?: string[] }) {
  const { investigation: inv } = useInvestigation();
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const { data, isFetching } = useQuery({
    queryKey: ["investigations", inv.id, "evidence-picker", q],
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/evidence", {
          params: { path: { investigation_id: inv.id }, query: { q: q || undefined, limit: 25 } },
        }),
      ),
  });
  const chosen = new Map(value.map((v) => [v.evidence_id, v]));
  const items = (data?.items ?? []).filter((item) => !exclude.includes(item.id));
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              setQ(draft.trim());
            }
          }}
          placeholder="Filter evidence by keyword"
          aria-label="Filter evidence by keyword"
        />
        <Button type="button" variant="secondary" onClick={() => setQ(draft.trim())} aria-label="Search evidence">
          <Search className="h-4 w-4" aria-hidden />
        </Button>
      </div>
      {isFetching ? <Spinner /> : null}
      <ul className="max-h-64 space-y-1.5 overflow-y-auto rounded-md border border-border p-1.5">
        {items.map((item) => {
          const picked = chosen.get(item.id);
          return (
            <li key={item.id} className="rounded p-1.5 text-sm hover:bg-surface-2">
              <div className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 accent-[var(--primary)]"
                  checked={Boolean(picked)}
                  aria-label={`Use ${item.label}`}
                  onChange={(event) =>
                    onChange(
                      event.target.checked
                        ? [...value, { evidence_id: item.id, label: item.label, stance: "supports", directly_states: false }]
                        : value.filter((v) => v.evidence_id !== item.id),
                    )
                  }
                />
                <div className="min-w-0 flex-1">
                  <p>
                    <span className="font-mono text-xs font-semibold">{item.label}</span>{" "}
                    <span className="text-xs text-muted">
                      {humanize(item.evidence_type)} · {item.source?.host ?? "image"} · {formatDate(item.captured_at)}
                    </span>
                  </p>
                  {item.excerpt ? <p className="line-clamp-2 text-[13px] text-muted">{item.excerpt}</p> : null}
                  {picked ? (
                    <div className="mt-1.5 flex flex-wrap items-center gap-3">
                      <Select
                        aria-label={`Stance of ${item.label}`}
                        className="h-8 w-36"
                        value={picked.stance}
                        onChange={(event) =>
                          onChange(value.map((v) => (v.evidence_id === item.id ? { ...v, stance: event.target.value as PickedEvidence["stance"] } : v)))
                        }
                      >
                        <option value="supports">Supports</option>
                        <option value="contradicts">Contradicts</option>
                        <option value="context">Context</option>
                      </Select>
                      <label className="flex items-center gap-1.5 text-xs">
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 accent-[var(--primary)]"
                          checked={picked.directly_states}
                          onChange={(event) =>
                            onChange(value.map((v) => (v.evidence_id === item.id ? { ...v, directly_states: event.target.checked } : v)))
                          }
                        />
                        States it directly
                      </label>
                    </div>
                  ) : null}
                </div>
              </div>
            </li>
          );
        })}
        {!isFetching && !items.length ? <li className="p-3 text-center text-sm text-muted">No evidence found.</li> : null}
      </ul>
    </div>
  );
}
