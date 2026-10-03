import type { components } from "./schema";

export type Schemas = components["schemas"];
export type S<K extends keyof Schemas> = Schemas[K];

export type Session = S<"SessionOut">;
export type User = S<"UserOut">;
export type InvestigationSummary = S<"InvestigationSummary">;
export type InvestigationDetail = S<"InvestigationDetail">;
export type FindingRow = S<"FindingRow">;
export type FindingDetail = S<"FindingDetail">;
export type EvidenceOut = S<"EvidenceOut">;
export type SourceOut = S<"SourceOut">;
export type EventOut = S<"EventOut">;
export type ImageOut = S<"ImageOut">;
export type ImageDetail = S<"ImageDetail">;
export type ClueOut = S<"ClueOut">;
export type RunOut = S<"RunOut">;
export type ConnectorOut = S<"ConnectorOut">;
export type InteractionOut = S<"InteractionOut">;
export type ProposalOut = S<"ProposalOut">;
export type ReportOut = S<"ReportOut">;
export type ReportSummary = S<"ReportSummary">;
export type ExportOut = S<"ExportOut">;
