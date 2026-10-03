"use client";

import { ProvenanceBadge, VerificationStatusBadge } from "@/components/provenance/badges";
import { Table, Td, Th } from "@/components/ui/data";

import { ENTITY_LABELS, REL_LABELS, type GraphData } from "./types";

/** Accessible equivalent of the graph canvas. */
export function RelationshipList({ graph, onSelect }: { graph: GraphData; onSelect: (id: string) => void }) {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  return (
    <Table caption="Relationships" className="rounded-lg border border-border">
      <thead>
        <tr>
          <Th>From</Th>
          <Th>Relationship</Th>
          <Th>To</Th>
          <Th>Status</Th>
          <Th>Provenance</Th>
          <Th>Supporting sources</Th>
        </tr>
      </thead>
      <tbody>
        {graph.edges.map((edge) => {
          const from = nodes.get(edge.from);
          const to = nodes.get(edge.to);
          return (
            <tr key={edge.id}>
              <Td>
                {from?.name ?? "?"}
                <span className="block text-xs text-muted">{from ? ENTITY_LABELS[from.type] : ""}</span>
              </Td>
              <Td>
                <button type="button" className="text-primary underline underline-offset-2 hover:decoration-2" onClick={() => onSelect(edge.id)}>
                  {REL_LABELS[edge.rel_type] ?? edge.rel_type}
                </button>
              </Td>
              <Td>
                {to?.name ?? "?"}
                <span className="block text-xs text-muted">{to ? ENTITY_LABELS[to.type] : ""}</span>
              </Td>
              <Td>
                <VerificationStatusBadge status={edge.verification_status} size="sm" />
              </Td>
              <Td>
                <ProvenanceBadge provenance={edge.provenance} size="sm" />
              </Td>
              <Td className="text-xs">
                {edge.evidence
                  .filter((s) => s.stance === "supports")
                  .map((s) => `${s.evidence_label}${s.source_label ? ` (${s.source_label})` : ""}`)
                  .join(", ") || "—"}
                {edge.contradicting_count ? <span className="block text-st-contradicted">{edge.contradicting_count} contradicting</span> : null}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
