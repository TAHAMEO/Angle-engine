export const SECTION_TITLES: Record<string, string> = {
  overview: "Overview",
  methodology: "Methodology",
  evidence_summary: "Evidence summary",
  important_findings: "Important findings",
  contradictions: "Contradictions",
  unverified_claims: "Unverified claims",
  ai_hypotheses: "AI hypotheses",
  timeline: "Timeline",
  relationships: "Relationships",
  sources: "Sources",
  images: "Images",
  limitations: "Limitations",
  privacy: "Privacy considerations",
};

export const OPTIONAL_SECTIONS = new Set(["timeline", "relationships", "images", "ai_hypotheses", "unverified_claims"]);

export const CONFIDENTIALITY = ["Confidential", "Internal", "Restricted"] as const;

export const FORMATS = [
  { value: "pdf", label: "PDF" },
  { value: "html", label: "HTML (self-contained)" },
  { value: "markdown", label: "Markdown" },
  { value: "json", label: "JSON (structured)" },
] as const;

export const LINT_LABELS: Record<string, string> = {
  uncited_custom_paragraphs: "custom paragraph(s) without citations were moved to “Unverified claims”",
  moved_without_evidence: "finding(s) whose evidence was deleted were moved to “Unverified claims”",
  ai_uncited_segments: "AI narrative sentence(s) without citations are labelled as uncited AI commentary",
};
