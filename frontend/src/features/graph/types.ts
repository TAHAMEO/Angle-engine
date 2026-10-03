/** Shapes of GET {I}/graph (the OpenAPI schema types them as free-form objects). */
export interface GraphNode {
  id: string;
  type: string;
  name: string;
  country: string | null;
  location_level: string | null;
}

export interface EdgeSupport {
  stance: "supports" | "contradicts" | "context";
  evidence_id: string;
  evidence_label: string;
  source_id: string | null;
  source_label: string | null;
  host: string | null;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  rel_type: string;
  provenance: string;
  verification_status: string;
  confidence: string | null;
  supporting_count: number;
  contradicting_count: number;
  evidence: EdgeSupport[];
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export const REL_LABELS: Record<string, string> = {
  shows_text: "shows text",
  links_to: "links to",
  hosted_on: "hosted on",
  operated_by: "operated by",
  subsidiary_of: "subsidiary of",
  mentions: "mentions",
  published_by: "published by",
  participated_in: "participated in",
  located_in: "located in",
  same_image_as: "same image as",
  similar_image_to: "similar image to",
  documented_by: "documented by",
  registered_by: "registered by",
  depicts: "depicts",
};

export const ENTITY_LABELS: Record<string, string> = {
  image: "Image",
  username: "Username",
  website: "Website",
  domain: "Domain",
  webpage: "Web page",
  organization: "Organization",
  event: "Event",
  document: "Document",
  location: "Location",
  brand: "Brand",
  product: "Product",
  landmark: "Landmark",
  public_figure: "Public figure (role)",
};

export function asGraph(value: unknown): GraphData {
  const graph = (value ?? {}) as Partial<GraphData>;
  return { nodes: graph.nodes ?? [], edges: graph.edges ?? [], truncated: Boolean(graph.truncated) };
}
