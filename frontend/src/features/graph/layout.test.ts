import { describe, expect, it } from "vitest";

import { NODE_HEIGHT, NODE_WIDTH, layoutGraph } from "./layout";
import type { GraphEdge, GraphNode } from "./types";

const node = (id: string): GraphNode => ({ id, type: "organization", name: id, country: null, location_level: null });
const edge = (id: string, from: string, to: string): GraphEdge => ({
  id,
  from,
  to,
  rel_type: "mentions",
  provenance: "source_reported",
  verification_status: "unverified",
  confidence: null,
  supporting_count: 1,
  contradicting_count: 0,
  evidence: [],
});

describe("layoutGraph", () => {
  const nodes = ["a", "b", "c", "d"].map(node);
  const edges = [edge("e1", "a", "b"), edge("e2", "b", "c"), edge("e3", "a", "d")];

  it("is deterministic regardless of input order", () => {
    const first = layoutGraph(nodes, edges);
    const second = layoutGraph([...nodes].reverse(), [...edges].reverse());
    expect([...second.entries()].sort()).toEqual([...first.entries()].sort());
  });

  it("places nodes left to right without overlap and ignores dangling edges", () => {
    const positions = layoutGraph(nodes, [...edges, edge("e4", "a", "missing")]);
    expect(positions.size).toBe(4);
    expect(positions.get("b")!.x).toBeGreaterThan(positions.get("a")!.x);
    const boxes = [...positions.values()];
    for (const [i, p] of boxes.entries()) {
      for (const q of boxes.slice(i + 1)) {
        const overlap = Math.abs(p.x - q.x) < NODE_WIDTH && Math.abs(p.y - q.y) < NODE_HEIGHT;
        expect(overlap).toBe(false);
      }
    }
  });
});
