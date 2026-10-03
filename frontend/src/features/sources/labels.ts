export const INPUT_TYPES: Record<string, string> = {
  keyword: "Keyword",
  domain: "Domain",
  url: "Web address (URL)",
  username: "Public username",
  organization: "Organization name",
  place: "Public place",
};

export const ACCESS_STATUS: Record<string, { label: string; help: string }> = {
  captured: { label: "Captured", help: "A copy of the public page was captured." },
  reference_only: { label: "Reference only", help: "Recorded as a reference; content was not stored." },
  login_required: { label: "Login required", help: "Behind a login — never accessed. Review it manually if you are authorized." },
  robots_disallowed: { label: "Robots disallowed", help: "The site's robots.txt disallows automated access, so it was not fetched." },
  paywalled: { label: "Paywalled", help: "Behind a paywall — never bypassed." },
};

export const RUN_STATUS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Completed",
  partial: "Partly completed",
  failed: "Failed",
  cancelled: "Cancelled",
  pending_review: "Waiting for supervisor",
  refused: "Refused",
};

export const RUN_ACTIVE = new Set(["queued", "running"]);

export const RELIABILITY: Record<string, string> = {
  A: "A — completely reliable",
  B: "B — usually reliable",
  C: "C — fairly reliable",
  D: "D — not usually reliable",
  E: "E — unreliable",
  F: "F — reliability cannot be judged",
};
