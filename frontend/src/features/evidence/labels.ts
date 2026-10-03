export const EVIDENCE_TYPES: Record<string, string> = {
  text_excerpt: "Text excerpt",
  page_capture: "Page capture",
  document_excerpt: "Document excerpt",
  registry_record: "Registry record",
  search_result: "Search result",
  ocr_text: "Text in image (OCR)",
  image_clue: "Image clue",
  metadata: "Image metadata",
  image_match: "Image match",
};

export const STANCES: Record<string, { label: string; className: string }> = {
  supports: { label: "Supports", className: "border-st-confirmed/60 text-st-confirmed" },
  contradicts: { label: "Contradicts", className: "border-st-contradicted/60 text-st-contradicted" },
  context: { label: "Context", className: "border-border-strong text-muted" },
};

export const PRECONDITION_HINTS: Record<string, string> = {
  confirmed_by_source: "Needs at least one supporting source that states it directly, and no active contradiction.",
  corroborated: "Needs supporting evidence from at least two independent origins, and your attestation that they do not cite each other.",
  contradicted: "Needs at least one active contradicting source.",
  unverified: "Always available.",
  ai_hypothesis: "Only for findings that came from AI.",
};
