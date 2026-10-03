import dagre from "@dagrejs/dagre";

import type { GraphEdge, GraphNode } from "./types";

export const NODE_WIDTH = 208;
export const NODE_HEIGHT = 60;

/**
 * Deterministic left-to-right layout: inputs are sorted by id so the same graph always gets the same positions.
 * dagre returns node centres; React Flow wants top-left corners.
 */
export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], direction: "LR" | "TB" = "LR"): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: direction, nodesep: 28, ranksep: 90, marginx: 16, marginy: 16 });
  g.setDefaultEdgeLabel(() => ({}));
  const ids = new Set(nodes.map((n) => n.id));
  for (const node of [...nodes].sort((a, b) => a.id.localeCompare(b.id))) {
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (const edge of [...edges].sort((a, b) => a.id.localeCompare(b.id))) {
    if (ids.has(edge.from) && ids.has(edge.to)) g.setEdge(edge.from, edge.to, {}, edge.id);
  }
  dagre.layout(g);
  const positions = new Map<string, { x: number; y: number }>();
  for (const id of ids) {
    const point = g.node(id) as { x: number; y: number } | undefined;
    if (point) positions.set(id, { x: Math.round(point.x - NODE_WIDTH / 2), y: Math.round(point.y - NODE_HEIGHT / 2) });
  }
  return positions;
}
