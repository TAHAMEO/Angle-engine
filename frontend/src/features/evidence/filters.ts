import { z } from "@/lib/zod";

/**
 * Structured finding filters live in the URL (shareable, back-button friendly). The free-text keyword is deliberately
 * kept out of the URL so search terms never land in browser history or server logs.
 */
const list = z.array(z.string().max(64)).max(20).default([]);
const optional = z.string().max(253).optional();
const date = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .optional();

export const findingFiltersSchema = z.object({
  status: list,
  provenance: list,
  category: list,
  confidence: list,
  source_category: list,
  evidence_type: list,
  importance: z.enum(["key", "normal"]).optional(),
  domain: optional,
  connector: optional,
  country: z
    .string()
    .regex(/^[A-Z]{2}$/)
    .optional(),
  region: z.string().max(10).optional(),
  captured_from: date,
  captured_to: date,
  published_from: date,
  published_to: date,
  has_contradictions: z.enum(["true", "false"]).optional(),
  include_retracted: z.enum(["true", "false"]).optional(),
  sort: z.enum(["updated", "created"]).optional(),
});
export type FindingFilters = z.output<typeof findingFiltersSchema>;

const LIST_KEYS = ["status", "provenance", "category", "confidence", "source_category", "evidence_type"] as const;
const SCALAR_KEYS = [
  "importance",
  "domain",
  "connector",
  "country",
  "region",
  "captured_from",
  "captured_to",
  "published_from",
  "published_to",
  "has_contradictions",
  "include_retracted",
  "sort",
] as const;

export function parseFilters(params: URLSearchParams): FindingFilters {
  const raw: Record<string, unknown> = {};
  for (const key of LIST_KEYS) raw[key] = params.getAll(key).filter(Boolean);
  for (const key of SCALAR_KEYS) {
    const value = params.get(key);
    if (value) raw[key] = value;
  }
  const parsed = findingFiltersSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  // Drop only the invalid keys instead of all filters.
  const clean: Record<string, unknown> = { ...raw };
  for (const issue of parsed.error.issues) delete clean[String(issue.path[0])];
  return findingFiltersSchema.parse(clean);
}

/** Serialize filters, keeping unrelated params (drawers, tabs) intact. */
export function writeFilters(base: URLSearchParams, filters: FindingFilters): URLSearchParams {
  const next = new URLSearchParams(base);
  for (const key of [...LIST_KEYS, ...SCALAR_KEYS]) next.delete(key);
  next.delete("cursor");
  for (const key of LIST_KEYS) for (const value of filters[key]) next.append(key, value);
  for (const key of SCALAR_KEYS) {
    const value = filters[key];
    if (value) next.set(key, value);
  }
  return next;
}

export function activeFilterCount(filters: FindingFilters): number {
  return LIST_KEYS.reduce((n, key) => n + filters[key].length, 0) + SCALAR_KEYS.filter((key) => key !== "sort" && filters[key]).length;
}

/** API query parameters (dates become UTC day boundaries). */
export function toQuery(filters: FindingFilters, keyword: string) {
  const day = (value: string | undefined, end = false) => (value ? `${value}T${end ? "23:59:59" : "00:00:00"}Z` : undefined);
  const list = <T extends string>(values: string[]) => (values.length ? (values as T[]) : undefined);
  return {
    status: list<"confirmed_by_source" | "corroborated" | "unverified" | "contradicted" | "ai_hypothesis">(filters.status),
    provenance: list<"observed" | "source_reported" | "analyst_inference" | "ai_hypothesis">(filters.provenance),
    category: list(filters.category),
    confidence: list<"low" | "moderate" | "high" | "none">(filters.confidence),
    source_category: list(filters.source_category),
    evidence_type: list(filters.evidence_type),
    importance: filters.importance,
    domain: filters.domain,
    connector: filters.connector,
    country: filters.country,
    region: filters.region,
    captured_from: day(filters.captured_from),
    captured_to: day(filters.captured_to, true),
    published_from: day(filters.published_from),
    published_to: day(filters.published_to, true),
    has_contradictions: filters.has_contradictions ? filters.has_contradictions === "true" : undefined,
    include_retracted: filters.include_retracted ? filters.include_retracted === "true" : undefined,
    sort: filters.sort,
    q: keyword || undefined,
  };
}
