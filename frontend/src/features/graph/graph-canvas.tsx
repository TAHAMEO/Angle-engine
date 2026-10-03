"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  getBezierPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  Building2,
  CalendarDays,
  FileText,
  Globe,
  Image as ImageIcon,
  Landmark,
  Link2,
  MapPin,
  Package,
  Tag,
  UserRound,
  AtSign,
  Server,
} from "lucide-react";
import { useMemo } from "react";

import { STATUS, type Status } from "@/components/provenance/badges";
import { cn } from "@/lib/utils";

import { NODE_HEIGHT, NODE_WIDTH, layoutGraph } from "./layout";
import { ENTITY_LABELS, REL_LABELS, type GraphData, type GraphEdge, type GraphNode } from "./types";

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  image: ImageIcon,
  username: AtSign,
  website: Globe,
  domain: Server,
  webpage: Link2,
  organization: Building2,
  event: CalendarDays,
  document: FileText,
  location: MapPin,
  brand: Tag,
  product: Package,
  landmark: Landmark,
  public_figure: UserRound,
};

/** Stroke pattern per status so the graph never relies on colour alone. */
export const EDGE_STYLE: Record<Status, { stroke: string; dash?: string; width: number }> = {
  confirmed_by_source: { stroke: "var(--st-confirmed)", width: 2.5 },
  corroborated: { stroke: "var(--st-corroborated)", width: 3.5 },
  unverified: { stroke: "var(--st-unverified)", dash: "6 4", width: 1.75 },
  contradicted: { stroke: "var(--st-contradicted)", dash: "2 4", width: 2.5 },
  ai_hypothesis: { stroke: "var(--st-ai)", dash: "10 4 2 4", width: 2 },
};

type EntityNode = Node<{ entity: GraphNode; highlighted: boolean }, "entity">;
type StatusEdgeType = Edge<{ edge: GraphEdge; highlighted: boolean }, "status">;

function EntityNodeView({ data, selected }: NodeProps<EntityNode>) {
  const Icon = ICONS[data.entity.type] ?? Tag;
  return (
    <div
      className={cn(
        "flex h-full w-full items-center gap-2 rounded-md border bg-surface px-2.5 text-left shadow-sm",
        selected ? "border-primary ring-2 ring-primary/40" : data.highlighted ? "border-warning" : "border-border-strong",
      )}
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT }}
    >
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-border-strong" />
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded bg-surface-3 text-muted">
        <Icon className="h-4 w-4" aria-hidden />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[13px] font-medium text-foreground" title={data.entity.name}>
          {data.entity.name}
        </span>
        <span className="block truncate text-[11px] text-muted">
          {ENTITY_LABELS[data.entity.type] ?? data.entity.type}
          {data.entity.country ? ` · ${data.entity.country}` : ""}
        </span>
      </span>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-border-strong" />
    </div>
  );
}

function StatusEdgeView({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, selected, markerEnd }: EdgeProps<StatusEdgeType>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const edge = data!.edge;
  const style = EDGE_STYLE[edge.verification_status as Status] ?? EDGE_STYLE.unverified;
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke: style.stroke,
          strokeWidth: selected || data!.highlighted ? style.width + 1.5 : style.width,
          strokeDasharray: style.dash,
        }}
      />
      <EdgeLabelRenderer>
        <div
          className={cn(
            "nodrag nopan pointer-events-auto absolute rounded border bg-surface px-1.5 py-0.5 text-[10px] leading-tight whitespace-nowrap text-foreground",
            selected ? "border-primary" : "border-border",
          )}
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
        >
          {REL_LABELS[edge.rel_type] ?? edge.rel_type}
          <span className="text-muted">
            {" "}
            · {edge.supporting_count} src{edge.contradicting_count ? ` · ${edge.contradicting_count} contra` : ""}
          </span>
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

const nodeTypes = { entity: EntityNodeView };
const edgeTypes = { status: StatusEdgeView };

export function GraphCanvas({
  graph,
  selection,
  onSelect,
  highlight,
}: {
  graph: GraphData;
  selection: { kind: "node" | "edge"; id: string } | null;
  onSelect: (selection: { kind: "node" | "edge"; id: string } | null) => void;
  highlight: Set<string>;
}) {
  const names = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n.name])), [graph.nodes]);
  const { nodes, edges } = useMemo(() => {
    const positions = layoutGraph(graph.nodes, graph.edges);
    const flowNodes: EntityNode[] = graph.nodes.map((entity) => ({
      id: entity.id,
      type: "entity",
      position: positions.get(entity.id) ?? { x: 0, y: 0 },
      data: { entity, highlighted: false },
      selected: selection?.kind === "node" && selection.id === entity.id,
      ariaLabel: `${ENTITY_LABELS[entity.type] ?? entity.type}: ${entity.name}`,
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    }));
    const flowEdges: StatusEdgeType[] = graph.edges.map((edge) => ({
      id: edge.id,
      source: edge.from,
      target: edge.to,
      type: "status",
      data: { edge, highlighted: highlight.has(edge.id) },
      selected: selection?.kind === "edge" && selection.id === edge.id,
      ariaLabel: `${names.get(edge.from) ?? "?"} ${REL_LABELS[edge.rel_type] ?? edge.rel_type} ${names.get(edge.to) ?? "?"}, ${
        STATUS[edge.verification_status as Status]?.label ?? edge.verification_status
      }, ${edge.supporting_count} supporting sources`,
      markerEnd: { type: "arrowclosed" as const, color: (EDGE_STYLE[edge.verification_status as Status] ?? EDGE_STYLE.unverified).stroke },
    }));
    return { nodes: flowNodes, edges: flowEdges };
  }, [graph, selection, highlight, names]);

  return (
    <div className="h-[65vh] min-h-96 overflow-hidden rounded-lg border border-border">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.08, maxZoom: 1.1 }}
        minZoom={0.2}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        onNodeClick={(_, node) => onSelect({ kind: "node", id: node.id })}
        onEdgeClick={(_, edge) => onSelect({ kind: "edge", id: edge.id })}
        onPaneClick={() => onSelect(null)}
        ariaLabelConfig={{ "node.a11yDescription.default": "Press Enter or Space to select this entity and show its details." }}
      >
        <Background gap={20} color="var(--border)" />
        <Controls showInteractive={false} />
        {graph.nodes.length > 40 ? (
          <MiniMap pannable zoomable nodeColor="var(--surface-3)" maskColor="color-mix(in srgb, var(--background) 70%, transparent)" />
        ) : null}
      </ReactFlow>
    </div>
  );
}

export function GraphLegend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs" aria-label="Edge legend">
      {(Object.keys(EDGE_STYLE) as Status[]).map((status) => {
        const style = EDGE_STYLE[status];
        return (
          <li key={status} className="flex items-center gap-1.5">
            <svg width="34" height="8" aria-hidden>
              <line x1="0" y1="4" x2="34" y2="4" stroke={style.stroke} strokeWidth={style.width} strokeDasharray={style.dash} />
            </svg>
            {STATUS[status].label}
          </li>
        );
      })}
      <li className="text-muted">Labels show the number of supporting (and contradicting) sources.</li>
    </ul>
  );
}
