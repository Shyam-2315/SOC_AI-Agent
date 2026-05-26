import { Fragment } from "react";
import type { IncidentAttackGraphResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

const COLUMN_ORDER = [
  "source_ip",
  "host",
  "endpoint",
  "user",
  "alert",
  "incident",
  "soar_action",
  "mitre_technique",
] as const;

const COLUMN_LABELS: Record<(typeof COLUMN_ORDER)[number], string> = {
  source_ip: "Source IPs",
  host: "Hosts",
  endpoint: "Endpoints",
  user: "Users",
  alert: "Alerts",
  incident: "Incident",
  soar_action: "SOAR",
  mitre_technique: "MITRE",
};

const NODE_STYLES: Record<string, string> = {
  source_ip: "border-red-500/40 bg-red-500/10 text-red-200",
  endpoint: "border-sky-500/40 bg-sky-500/10 text-sky-200",
  host: "border-sky-500/40 bg-sky-500/10 text-sky-200",
  user: "border-sky-500/30 bg-sky-500/10 text-sky-100",
  alert: "border-orange-500/40 bg-orange-500/10 text-orange-200",
  incident: "border-violet-500/40 bg-violet-500/10 text-violet-200",
  soar_action: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
  mitre_technique: "border-slate-500/40 bg-slate-500/10 text-slate-200",
};

type GraphNode = IncidentAttackGraphResponse["nodes"][number];
type GraphEdge = IncidentAttackGraphResponse["edges"][number];

export function AttackGraph({ graph }: { graph: IncidentAttackGraphResponse }) {
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const grouped = groupNodes(graph.nodes);
  const visibleColumns = COLUMN_ORDER.filter((column) => grouped[column].length > 0);

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto pb-2">
        <div
          className="grid min-w-[840px] gap-4"
          style={{
            gridTemplateColumns: `repeat(${Math.max(visibleColumns.length, 1)}, minmax(180px, 1fr))`,
          }}
        >
          {visibleColumns.map((column) => (
            <div key={column} className="space-y-3">
              <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {COLUMN_LABELS[column]}
              </div>
              <div className="space-y-3">
                {grouped[column].map((node) => (
                  <GraphNodeCard key={node.id} node={node} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background/40 p-4">
        <div className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
          Relationships
        </div>
        <div className="mt-3 space-y-2">
          {graph.edges.map((edge, index) => (
            <Fragment key={`${edge.source}:${edge.target}:${edge.label}:${index}`}>
              <GraphEdgeRow edge={edge} source={nodesById.get(edge.source)} target={nodesById.get(edge.target)} />
            </Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

function GraphNodeCard({ node }: { node: GraphNode }) {
  return (
    <div className={cn("rounded-xl border p-3 shadow-card", NODE_STYLES[node.type] ?? "border-border bg-card")}>
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-current/70">
        {node.type.replaceAll("_", " ")}
      </div>
      <div className="mt-2 break-words text-sm font-medium text-foreground">{node.label}</div>
      {node.severity && (
        <div className="mt-2 inline-flex rounded-full border border-current/20 px-2 py-0.5 text-[11px] uppercase tracking-[0.14em] text-current/80">
          {node.severity}
        </div>
      )}
    </div>
  );
}

function GraphEdgeRow({
  edge,
  source,
  target,
}: {
  edge: GraphEdge;
  source?: GraphNode;
  target?: GraphNode;
}) {
  return (
    <div className="grid gap-2 rounded-lg border border-border bg-card/60 px-3 py-2 md:grid-cols-[1fr_auto_1fr] md:items-center">
      <div className="min-w-0">
        <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
          {source?.type?.replaceAll("_", " ") ?? "source"}
        </div>
        <div className="truncate text-sm font-medium">{source?.label ?? edge.source}</div>
      </div>
      <div className="justify-self-start md:justify-self-center">
        <span className="inline-flex items-center rounded-full border border-primary/20 bg-primary/10 px-2 py-1 text-[11px] uppercase tracking-[0.16em] text-primary">
          {edge.label}
        </span>
      </div>
      <div className="min-w-0 md:text-right">
        <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
          {target?.type?.replaceAll("_", " ") ?? "target"}
        </div>
        <div className="truncate text-sm font-medium">{target?.label ?? edge.target}</div>
      </div>
    </div>
  );
}

function groupNodes(nodes: GraphNode[]) {
  const grouped = {
    source_ip: [] as GraphNode[],
    host: [] as GraphNode[],
    endpoint: [] as GraphNode[],
    user: [] as GraphNode[],
    alert: [] as GraphNode[],
    incident: [] as GraphNode[],
    soar_action: [] as GraphNode[],
    mitre_technique: [] as GraphNode[],
  };

  for (const node of nodes) {
    if (node.type in grouped) {
      grouped[node.type as keyof typeof grouped].push(node);
    }
  }

  for (const key of Object.keys(grouped) as Array<keyof typeof grouped>) {
    grouped[key].sort((left, right) => left.label.localeCompare(right.label));
  }

  return grouped;
}
