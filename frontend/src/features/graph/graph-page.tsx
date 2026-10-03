"use client";

import { useQuery } from "@tanstack/react-query";
import { Network, Plus, Route } from "lucide-react";
import dynamic from "next/dynamic";
import { useMemo, useState } from "react";

import { STATUS } from "@/components/provenance/badges";
import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/data";
import { Alert, EmptyState, LoadingBlock } from "@/components/ui/feedback";
import { Select } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { QueryError } from "@/features/common/states";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { useInvestigation } from "@/lib/investigation";
import { qk } from "@/lib/query/keys";

import { AddEntityDialog, AddRelationshipDialog } from "./edit-dialogs";
import { GraphLegend } from "./graph-canvas";
import { GraphInspector } from "./inspector";
import { RelationshipList } from "./relationship-list";
import { ENTITY_LABELS, REL_LABELS, asGraph } from "./types";

// React Flow measures the DOM; render it on the client only.
const GraphCanvas = dynamic(() => import("./graph-canvas").then((m) => m.GraphCanvas), {
  ssr: false,
  loading: () => <LoadingBlock label="Drawing the graph" className="h-[65vh]" />,
});

type Selection = { kind: "node" | "edge"; id: string } | null;

export function GraphPage() {
  const { investigation: inv, can } = useInvestigation();
  const [view, setView] = useState<"graph" | "list">("graph");
  const [status, setStatus] = useState("");
  const [relType, setRelType] = useState("");
  const [entityType, setEntityType] = useState("");
  const [root, setRoot] = useState("");
  const [depth, setDepth] = useState(2);
  const [selection, setSelection] = useState<Selection>(null);
  const [highlight, setHighlight] = useState<Set<string>>(new Set());
  const [pathFrom, setPathFrom] = useState("");
  const [pathTo, setPathTo] = useState("");
  const [addEntity, setAddEntity] = useState(false);
  const [addRel, setAddRel] = useState(false);
  const filters = { status, relType, entityType, root, depth };
  const { data, error, isPending, refetch } = useQuery({
    queryKey: qk.graph(inv.id, filters),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/graph", {
          params: {
            path: { investigation_id: inv.id },
            query: {
              status: status ? [status as S<"VerificationStatus">] : undefined,
              rel_type: relType ? [relType as S<"RelationshipType">] : undefined,
              entity_type: entityType ? [entityType as S<"EntityType">] : undefined,
              root: root || undefined,
              depth,
            },
          },
        }),
      ),
  });
  const graph = useMemo(() => asGraph(data), [data]);
  const sortedNodes = useMemo(() => [...graph.nodes].sort((a, b) => a.name.localeCompare(b.name)), [graph.nodes]);

  const findPath = async () => {
    try {
      const result = await unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/graph/path", {
          params: { path: { investigation_id: inv.id }, query: { from: pathFrom, to: pathTo } },
        }),
      );
      if (!result.found) {
        setHighlight(new Set());
        toast("No connection found within four steps");
      } else {
        setHighlight(new Set(result.relationship_ids));
        toast(`Connected in ${result.relationship_ids.length} step${result.relationship_ids.length === 1 ? "" : "s"}`, {
          description: "The path is highlighted in the graph.",
        });
      }
    } catch (e) {
      toast("Could not find a path", { description: messageOf(e), tone: "danger" });
    }
  };

  return (
    <>
      <PageHeader
        title="Relationship graph"
        description="Entities and the evidence-backed relationships between them. Every edge cites at least one source; select it to see which."
        actions={
          can("content:write") ? (
            <>
              <Button variant="secondary" onClick={() => setAddEntity(true)}>
                <Plus className="h-4 w-4" aria-hidden /> Entity
              </Button>
              <Button variant="secondary" onClick={() => setAddRel(true)}>
                <Plus className="h-4 w-4" aria-hidden /> Relationship
              </Button>
            </>
          ) : undefined
        }
      />
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-2">
          <div className="inline-flex rounded-md border border-border p-0.5" role="group" aria-label="View">
            {(["graph", "list"] as const).map((v) => (
              <Button key={v} size="sm" variant={view === v ? "primary" : "ghost"} aria-pressed={view === v} onClick={() => setView(v)}>
                {v === "graph" ? "Graph" : "List"}
              </Button>
            ))}
          </div>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Status</span>
            <Select value={status} onChange={(e) => setStatus(e.target.value)} className="h-8 w-44">
              <option value="">All</option>
              {Object.entries(STATUS).map(([key, meta]) => (
                <option key={key} value={key}>
                  {meta.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Relationship</span>
            <Select value={relType} onChange={(e) => setRelType(e.target.value)} className="h-8 w-40">
              <option value="">All</option>
              {Object.entries(REL_LABELS).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Entity type</span>
            <Select value={entityType} onChange={(e) => setEntityType(e.target.value)} className="h-8 w-40">
              <option value="">All</option>
              {Object.entries(ENTITY_LABELS).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Focus on</span>
            <Select value={root} onChange={(e) => setRoot(e.target.value)} className="h-8 w-48">
              <option value="">Whole graph</option>
              {sortedNodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name}
                </option>
              ))}
            </Select>
          </label>
          {root ? (
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium">Depth</span>
              <Select value={depth} onChange={(e) => setDepth(Number(e.target.value))} className="h-8 w-20">
                {[1, 2, 3].map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </Select>
            </label>
          ) : null}
        </div>
        <GraphLegend />
        {isPending ? (
          <LoadingBlock />
        ) : error ? (
          <QueryError error={error} retry={() => void refetch()} />
        ) : !graph.nodes.length ? (
          <EmptyState icon={Network} title="No entities yet">
            Image analysis and collected sources create entities (websites, organizations, documents…) and relationships automatically.
          </EmptyState>
        ) : (
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
            <div className="min-w-0 space-y-3">
              {graph.truncated ? <Alert tone="info">The graph is large; only part of it is shown. Focus on an entity to explore.</Alert> : null}
              {view === "graph" ? (
                <GraphCanvas graph={graph} selection={selection} onSelect={setSelection} highlight={highlight} />
              ) : (
                <RelationshipList graph={graph} onSelect={(id) => setSelection({ kind: "edge", id })} />
              )}
            </div>
            <div className="space-y-4">
              <GraphInspector selection={selection} onClose={() => setSelection(null)} />
              <Card className="space-y-2 p-4">
                <h2 className="flex items-center gap-1.5 text-sm font-semibold">
                  <Route className="h-4 w-4" aria-hidden /> How are two entities connected?
                </h2>
                <Select aria-label="From entity" value={pathFrom} onChange={(e) => setPathFrom(e.target.value)} className="h-8">
                  <option value="">From…</option>
                  {sortedNodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </Select>
                <Select aria-label="To entity" value={pathTo} onChange={(e) => setPathTo(e.target.value)} className="h-8">
                  <option value="">To…</option>
                  {sortedNodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </Select>
                <div className="flex gap-2">
                  <Button size="sm" variant="secondary" disabled={!pathFrom || !pathTo || pathFrom === pathTo} onClick={() => void findPath()}>
                    Find path
                  </Button>
                  {highlight.size ? (
                    <Button size="sm" variant="ghost" onClick={() => setHighlight(new Set())}>
                      Clear
                    </Button>
                  ) : null}
                </div>
                <p className="text-xs text-muted">A path shows documented links between public entities — it is not evidence of anything by itself.</p>
              </Card>
            </div>
          </div>
        )}
      </div>
      {can("content:write") ? (
        <>
          <AddEntityDialog open={addEntity} onOpenChange={setAddEntity} />
          <AddRelationshipDialog open={addRel} onOpenChange={setAddRel} />
        </>
      ) : null}
    </>
  );
}
