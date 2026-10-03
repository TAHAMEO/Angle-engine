"use client";

import { ChevronDown, Search, X } from "lucide-react";
import { useState } from "react";

import { PROVENANCE, STATUS } from "@/components/provenance/badges";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/form";
import { Popover } from "@/components/ui/menu";
import { CATEGORY_NAMES } from "@/lib/format";

import { activeFilterCount, type FindingFilters } from "./filters";
import { EVIDENCE_TYPES } from "./labels";

type ListKey = "status" | "provenance" | "category" | "confidence" | "source_category" | "evidence_type";

function MultiSelect({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: Record<string, string>;
  value: string[];
  onChange: (value: string[]) => void;
}) {
  return (
    <Popover
      className="w-64"
      trigger={
        <Button variant={value.length ? "outline" : "secondary"} size="sm" aria-label={`${label}${value.length ? `, ${value.length} selected` : ""}`}>
          {label}
          {value.length ? <span className="rounded bg-primary/20 px-1 text-[11px] text-primary">{value.length}</span> : null}
          <ChevronDown className="h-3.5 w-3.5 opacity-70" aria-hidden />
        </Button>
      }
    >
      <fieldset className="space-y-1.5">
        <legend className="mb-1 text-xs font-semibold text-muted uppercase">{label}</legend>
        {Object.entries(options).map(([key, text]) => (
          <label key={key} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4 accent-[var(--primary)]"
              checked={value.includes(key)}
              onChange={(event) => onChange(event.target.checked ? [...value, key] : value.filter((v) => v !== key))}
            />
            {text}
          </label>
        ))}
      </fieldset>
    </Popover>
  );
}

/** Text filters apply on Enter or blur, not on every keystroke. */
function CommitInput({
  value,
  onCommit,
  transform = (v) => v,
  ...props
}: Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string | undefined;
  onCommit: (value: string | undefined) => void;
  transform?: (value: string) => string;
}) {
  const [draft, setDraft] = useState(value ?? "");
  const commit = () => {
    const next = transform(draft.trim());
    if (next !== (value ?? "")) onCommit(next || undefined);
  };
  return (
    <Input
      {...props}
      value={draft}
      onChange={(event) => setDraft(event.target.value)}
      onBlur={commit}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
        }
      }}
    />
  );
}

const STATUS_OPTIONS = Object.fromEntries(Object.entries(STATUS).map(([k, v]) => [k, v.label]));
const PROVENANCE_OPTIONS = Object.fromEntries(Object.entries(PROVENANCE).map(([k, v]) => [k, v.label]));
const CONFIDENCE_OPTIONS = { high: "High", moderate: "Moderate", low: "Low", none: "Not applicable" };

export function FilterBar({
  filters,
  onChange,
  keyword,
  onKeyword,
}: {
  filters: FindingFilters;
  onChange: (filters: FindingFilters) => void;
  keyword: string;
  onKeyword: (keyword: string) => void;
}) {
  const [draft, setDraft] = useState(keyword);
  const [more, setMore] = useState(false);
  const set = <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => onChange({ ...filters, [key]: value });
  const setList = (key: ListKey) => (value: string[]) => set(key, value);
  const count = activeFilterCount(filters);
  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface p-3">
      <form
        role="search"
        className="flex flex-wrap gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          onKeyword(draft.trim());
        }}
      >
        <label className="sr-only" htmlFor="finding-keyword">
          Keyword
        </label>
        <Input
          id="finding-keyword"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Keyword (exact words, searched in encrypted form)"
          className="min-w-56 flex-1"
          autoComplete="off"
        />
        <Button type="submit" variant="secondary">
          <Search className="h-4 w-4" aria-hidden /> Search
        </Button>
        {keyword ? (
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setDraft("");
              onKeyword("");
            }}
          >
            Clear keyword
          </Button>
        ) : null}
      </form>
      <div className="flex flex-wrap items-center gap-2">
        <MultiSelect label="Verification" options={STATUS_OPTIONS} value={filters.status} onChange={setList("status")} />
        <MultiSelect label="Provenance" options={PROVENANCE_OPTIONS} value={filters.provenance} onChange={setList("provenance")} />
        <MultiSelect label="Category" options={CATEGORY_NAMES} value={filters.category} onChange={setList("category")} />
        <MultiSelect label="Confidence" options={CONFIDENCE_OPTIONS} value={filters.confidence} onChange={setList("confidence")} />
        <MultiSelect label="Evidence type" options={EVIDENCE_TYPES} value={filters.evidence_type} onChange={setList("evidence_type")} />
        <Button variant="ghost" size="sm" aria-expanded={more} onClick={() => setMore(!more)}>
          More filters <ChevronDown className={`h-3.5 w-3.5 transition-transform ${more ? "rotate-180" : ""}`} aria-hidden />
        </Button>
        {count ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              onChange({ status: [], provenance: [], category: [], confidence: [], source_category: [], evidence_type: [], sort: filters.sort })
            }
          >
            <X className="h-3.5 w-3.5" aria-hidden /> Clear {count} filter{count === 1 ? "" : "s"}
          </Button>
        ) : null}
        <label className="ml-auto flex items-center gap-2 text-sm">
          <span className="text-muted">Sort</span>
          <Select value={filters.sort ?? "updated"} onChange={(e) => set("sort", e.target.value as "updated" | "created")} className="h-8 w-48">
            <option value="updated">Last updated</option>
            <option value="created">Newest first</option>
          </Select>
        </label>
      </div>
      {more ? (
        <div className="grid gap-3 border-t border-border pt-3 sm:grid-cols-2 lg:grid-cols-4">
          <MultiSelect label="Source category" options={CATEGORY_NAMES} value={filters.source_category} onChange={setList("source_category")} />
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Domain</span>
            <CommitInput value={filters.domain} onCommit={(v) => set("domain", v)} transform={(v) => v.toLowerCase()} placeholder="example.org" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Connector</span>
            <CommitInput value={filters.connector} onCommit={(v) => set("connector", v)} placeholder="gdelt" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Importance</span>
            <Select value={filters.importance ?? ""} onChange={(e) => set("importance", (e.target.value || undefined) as FindingFilters["importance"])}>
              <option value="">Any</option>
              <option value="key">Key findings</option>
              <option value="normal">Normal</option>
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Captured from</span>
            <Input type="date" value={filters.captured_from ?? ""} onChange={(e) => set("captured_from", e.target.value || undefined)} />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Captured to</span>
            <Input type="date" value={filters.captured_to ?? ""} onChange={(e) => set("captured_to", e.target.value || undefined)} />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Published from</span>
            <Input type="date" value={filters.published_from ?? ""} onChange={(e) => set("published_from", e.target.value || undefined)} />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Published to</span>
            <Input type="date" value={filters.published_to ?? ""} onChange={(e) => set("published_to", e.target.value || undefined)} />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Country (ISO code)</span>
            <CommitInput value={filters.country} maxLength={2} onCommit={(v) => set("country", v)} transform={(v) => v.toUpperCase()} placeholder="GB" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Region (ISO 3166-2)</span>
            <CommitInput value={filters.region} maxLength={10} onCommit={(v) => set("region", v)} transform={(v) => v.toUpperCase()} placeholder="GB-ENG" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Contradictions</span>
            <Select value={filters.has_contradictions ?? ""} onChange={(e) => set("has_contradictions", (e.target.value || undefined) as FindingFilters["has_contradictions"])}>
              <option value="">Any</option>
              <option value="true">Has active contradictions</option>
              <option value="false">No contradictions</option>
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Retracted findings</span>
            <Select value={filters.include_retracted ?? ""} onChange={(e) => set("include_retracted", (e.target.value || undefined) as FindingFilters["include_retracted"])}>
              <option value="">Show</option>
              <option value="false">Hide</option>
            </Select>
          </label>
        </div>
      ) : null}
    </div>
  );
}
