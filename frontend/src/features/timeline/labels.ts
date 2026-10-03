export const EVENT_KINDS: Record<string, { label: string; basis: string }> = {
  capture_time: { label: "Image capture time", basis: "From embedded image metadata — editable, so treat it as a claim." },
  publication: { label: "Publication", basis: "Publication date reported by the source." },
  first_archived: { label: "First archived", basis: "Earliest snapshot in a public web archive." },
  registration: { label: "Registration", basis: "Registry record (e.g. domain or company registration)." },
  corporate_event: { label: "Corporate event", basis: "Reported in a company or government record." },
  public_statement: { label: "Public statement", basis: "Date of a public statement reported by the source." },
  event: { label: "Event", basis: "Date reported by the cited sources." },
  manual: { label: "Recorded by an investigator", basis: "Entered by an investigator from the cited evidence." },
};

export const PRECISION_LABELS: Record<string, string> = {
  exact: "Exact",
  minute: "Minute",
  hour: "Hour",
  day: "Day",
  month: "Month",
  year: "Year",
  approximate: "Approximate",
};
