import { formatDistanceToNowStrict } from "date-fns";

/** All timestamps are shown in UTC with an explicit label: evidence work must not depend on local time zones. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().slice(0, 10);
}

/** A date at its recorded precision ("2016", "2016-03", "2016-03-02", or a timestamp). */
export function formatAtPrecision(value: string | null | undefined, precision?: string | null): string {
  if (!value) return "—";
  const iso = new Date(value).toISOString();
  switch (precision) {
    case "year":
      return iso.slice(0, 4);
    case "month":
      return iso.slice(0, 7);
    case "day":
      return iso.slice(0, 10);
    case "approximate":
      return `c. ${iso.slice(0, 10)}`;
    default:
      return `${iso.slice(0, 16).replace("T", " ")} UTC`;
  }
}

export function relative(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${formatDistanceToNowStrict(date)} ${date.getTime() > Date.now() ? "from now" : "ago"}`;
}

export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function humanize(value: string | null | undefined): string {
  if (!value) return "—";
  const text = value.replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const CATEGORY_NAMES: Record<string, string> = {
  websites: "Websites",
  news_articles: "News articles",
  public_social_media: "Public social media",
  public_profiles: "Public profiles",
  public_documents: "Public documents",
  public_company_information: "Public company information",
  public_government_information: "Public government information",
  public_directories: "Public directories",
  public_forums: "Public forums",
  public_image_sources: "Public image sources",
  search_engine_results: "Search engine results",
  image_analysis: "Image analysis",
  analysis: "Analysis",
};
