export const PURPOSE_CATEGORIES: Record<string, string> = {
  journalism: "Journalism",
  fact_checking: "Fact-checking",
  due_diligence: "Due diligence",
  brand_protection: "Brand protection",
  cybersecurity: "Cybersecurity",
  academic_research: "Academic research",
  legal_proceedings: "Legal proceedings",
  law_enforcement: "Law enforcement (authorized)",
  misinformation_research: "Misinformation research",
  image_verification: "Image verification",
  other: "Other",
};

export const LAWFUL_BASES: Record<string, string> = {
  legitimate_interest: "Legitimate interest",
  public_interest_journalism: "Public-interest journalism",
  legal_obligation: "Legal obligation",
  law_enforcement_authorization: "Law-enforcement authorization",
  research_exemption: "Research exemption",
  contract: "Contract",
  consent: "Consent of the subject",
  other: "Other (explain in the purpose)",
};

export const SUBJECT_TYPES: Record<string, { label: string; help: string }> = {
  organization: { label: "Organization", help: "A company, NGO, agency or other organization." },
  website: { label: "Website or domain", help: "A site, domain or online service." },
  public_event: { label: "Public event", help: "An incident, event or news story." },
  public_figure_role: {
    label: "Public figure (public role only)",
    help: "A person only in their public role — e.g. statements made as an official. No private life.",
  },
  individual: {
    label: "Individual person",
    help: "Needs a stated lawful basis and a supervisor's approval, then runs in restricted mode.",
  },
  image_provenance: { label: "Image provenance", help: "Where an image came from and how it spread." },
  other: { label: "Other", help: "Anything else that is not about a private person." },
};

export const STATUS_FILTERS = [
  { value: "", label: "All statuses" },
  { value: "active", label: "Active" },
  { value: "draft", label: "Draft" },
  { value: "pending_review", label: "Pending review" },
  { value: "suspended", label: "Suspended" },
  { value: "closed", label: "Closed" },
  { value: "archived", label: "Archived" },
  { value: "refused", label: "Refused" },
];
