import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Btn } from "@/components/soc/Btn";
import { CopilotV2Panel } from "@/components/soc/AiCopilotPanels";
import { ClientDateTime } from "@/components/soc/ClientOnly";
import { PageHeader } from "@/components/soc/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import {
  backend,
  entityId,
  type AttackChainRecord,
  type AttackChainStatus,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend, severityOf, textOf } from "@/lib/presentation";
import { GitBranch, Network, RefreshCw, ShieldCheck, Sparkles } from "lucide-react";

export const Route = createFileRoute("/_app/attack-chains")({
  head: () => ({ meta: [{ title: "Attack Chains - SentinelAI" }] }),
  component: AttackChainsPage,
});

const STATUSES: AttackChainStatus[] = ["open", "investigating", "contained", "resolved"];

function AttackChainsPage() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [lookbackHours, setLookbackHours] = useState(24);
  const chains = useQuery({
    queryKey: ["attack-chains"],
    queryFn: () => backend.attackChains({ limit: 100 }),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });
  const generate = useMutation({
    mutationFn: () => backend.generateAttackChains(lookbackHours),
    onSuccess: (payload) => {
      queryClient.invalidateQueries({ queryKey: ["attack-chains"] });
      const first = payload.items[0];
      if (first) setSelectedId(entityId(first));
    },
  });
  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AttackChainStatus }) =>
      backend.updateAttackChainStatus(id, status),
    onSuccess: (chain) => {
      queryClient.invalidateQueries({ queryKey: ["attack-chains"] });
      setSelectedId(entityId(chain));
    },
  });

  const items = chains.data?.items ?? [];
  const selected = useMemo(() => {
    if (selectedId) {
      const match = items.find((item) => entityId(item) === selectedId);
      if (match) return match;
    }
    return items[0] ?? null;
  }, [items, selectedId]);
  const activeId = selected ? entityId(selected) : "";
  const story = useQuery({
    queryKey: ["attack-chain-story", activeId],
    queryFn: () => backend.attackChainStory(activeId),
    enabled: canQueryBackend() && !!activeId,
  });
  const graph = useQuery({
    queryKey: ["attack-chain-graph", activeId],
    queryFn: () => backend.attackChainGraph(activeId),
    enabled: canQueryBackend() && !!activeId,
  });
  const timeline = story.data?.timeline ?? selected?.timeline ?? [];
  const actions = story.data?.recommended_actions ?? selected?.recommended_actions ?? [];
  const summary = story.data?.ai_summary ?? selected?.ai_summary ?? "";

  if (chains.isLoading || chains.isPending) return <LoadingState label="Loading attack chains..." />;
  if (chains.error) {
    return (
      <ErrorState
        message={chains.error instanceof Error ? chains.error.message : "Could not load attack chains."}
      />
    );
  }

  return (
    <div className="space-y-6" data-testid="attack-chains-page">
      <PageHeader
        eyebrow="Threat Story"
        title="Attack Chains"
        description="Correlated alert chains with MITRE mapping, timeline, risk, and response priorities."
        actions={
          <>
            <select
              value={lookbackHours}
              onChange={(event) => setLookbackHours(Number(event.target.value))}
              className="h-8 rounded-md border border-border bg-background px-2 text-xs focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              aria-label="Lookback window"
            >
              <option value={6}>6h</option>
              <option value={24}>24h</option>
              <option value={72}>72h</option>
              <option value={168}>7d</option>
            </select>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => chains.refetch()}
              disabled={chains.isFetching}
            >
              <RefreshCw className={`h-4 w-4 ${chains.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Btn>
            <Btn
              variant="hero"
              size="sm"
              onClick={() => generate.mutate()}
              disabled={generate.isPending}
            >
              <Sparkles className="h-4 w-4" />
              Generate
            </Btn>
          </>
        }
      />

      {(generate.error || updateStatus.error) && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {(generate.error ?? updateStatus.error) instanceof Error
            ? (generate.error ?? updateStatus.error)?.message
            : "Attack chain operation failed."}
        </div>
      )}

      {items.length === 0 ? (
        <EmptyState
          title="No attack chains"
          description="Generate chains from recent alerts after collector or demo data is available."
        />
      ) : (
        <div className="grid gap-5 xl:grid-cols-[360px_minmax(0,1fr)]">
          <aside className="space-y-3">
            {items.map((chain) => {
              const id = entityId(chain);
              const active = id === activeId;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setSelectedId(id)}
                  className={`w-full rounded-lg border p-4 text-left transition ${
                    active
                      ? "border-primary bg-primary/10"
                      : "border-border bg-card hover:border-primary/40"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold">{chain.title}</div>
                      <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                        CHAIN-{id.slice(-8)}
                      </div>
                    </div>
                    <SeverityBadge severity={severityOf(chain.severity)} />
                  </div>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    <Metric label="Risk" value={`${chain.risk_score.toFixed(1)}/10`} />
                    <Metric label="Confidence" value={`${Math.round(chain.confidence_score * 100)}%`} />
                    <Metric label="Hosts" value={chain.affected_hosts.length} />
                    <Metric label="Users" value={chain.affected_users.length} />
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {chain.mitre_techniques.slice(0, 3).map((technique) => (
                      <span
                        key={technique.technique_id}
                        className="rounded-md border border-border bg-background px-2 py-0.5 font-mono text-[11px] text-muted-foreground"
                      >
                        {technique.technique_id}
                      </span>
                    ))}
                  </div>
                </button>
              );
            })}
          </aside>

          {selected ? (
            <section className="space-y-5">
              <div className="rounded-lg border border-border bg-card p-5 shadow-card">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={severityOf(selected.severity)} />
                      <StatusBadge status={selected.status} />
                    </div>
                    <h2 className="mt-3 text-xl font-semibold">{selected.title}</h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
                      {textOf(summary, "No threat story available.")}
                    </p>
                  </div>
                  <div className="min-w-48 rounded-md border border-border bg-background p-3">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>Risk score</span>
                      <span className="font-mono">{selected.risk_score.toFixed(1)}/10</span>
                    </div>
                    <div className="mt-2 h-2 rounded-full bg-muted">
                      <div
                        className="h-2 rounded-full bg-primary"
                        style={{ width: `${Math.min(selected.risk_score * 10, 100)}%` }}
                      />
                    </div>
                    <div className="mt-3 text-xs text-muted-foreground">
                      Updated <ClientDateTime value={selected.updated_at} />
                    </div>
                  </div>
                </div>

                <div className="mt-5 grid gap-3 md:grid-cols-4">
                  <Metric label="Alerts" value={selected.related_alert_ids.length} />
                  <Metric label="Incidents" value={selected.related_incident_ids.length} />
                  <Metric label="Source IPs" value={selected.source_ips.length} />
                  <Metric label="Destination IPs" value={selected.destination_ips.length} />
                </div>

                <div className="mt-5 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground">Status</span>
                  {STATUSES.map((status) => (
                    <button
                      key={status}
                      type="button"
                      onClick={() => updateStatus.mutate({ id: activeId, status })}
                      disabled={updateStatus.isPending || selected.status === status}
                      className={`rounded-md border px-2 py-1 text-[11px] capitalize transition disabled:opacity-50 ${
                        selected.status === status
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {status}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(320px,0.75fr)]">
                <TimelinePanel timeline={timeline} loading={story.isFetching} />
                <div className="space-y-5">
                  <CopilotV2Panel key={activeId} attackChainId={activeId} />
                  <ActionsPanel actions={actions} techniques={selected.mitre_techniques} />
                </div>
              </div>

              <GraphPanel graph={graph.data} loading={graph.isFetching} />
            </section>
          ) : null}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border bg-background px-3 py-2">
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-semibold">{value}</div>
    </div>
  );
}

function TimelinePanel({
  timeline,
  loading,
}: {
  timeline: NonNullable<AttackChainRecord["timeline"]>;
  loading: boolean;
}) {
  return (
    <div className="rounded-lg border border-border bg-card shadow-card">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3 text-sm font-semibold">
        <GitBranch className="h-4 w-4 text-primary" />
        Timeline
        {loading && <RefreshCw className="h-3 w-3 animate-spin text-muted-foreground" />}
      </div>
      <div className="divide-y divide-border/70">
        {timeline.length === 0 ? (
          <div className="p-5 text-sm text-muted-foreground">No timeline events.</div>
        ) : (
          timeline.map((item, index) => (
            <div key={`${item.alert_id ?? index}-${item.timestamp ?? "time"}`} className="p-5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-border bg-background px-2 py-0.5 text-[11px] font-medium">
                  {textOf(item.stage, "EXECUTION").replaceAll("_", " ")}
                </span>
                {item.severity ? <SeverityBadge severity={severityOf(item.severity)} /> : null}
                <span className="text-xs text-muted-foreground">
                  <ClientDateTime value={item.timestamp} />
                </span>
              </div>
              <div className="mt-2 text-sm font-semibold">
                {textOf(item.title ?? item.event_type, "Alert")}
              </div>
              <div className="mt-1 text-sm text-muted-foreground">{textOf(item.message, "")}</div>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                {item.host && <span className="rounded-md bg-background px-2 py-1">host {item.host}</span>}
                {item.user && <span className="rounded-md bg-background px-2 py-1">user {item.user}</span>}
                {item.source_ip && <span className="rounded-md bg-background px-2 py-1">src {item.source_ip}</span>}
                {item.destination_ip && <span className="rounded-md bg-background px-2 py-1">dst {item.destination_ip}</span>}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function ActionsPanel({
  actions,
  techniques,
}: {
  actions: string[];
  techniques: AttackChainRecord["mitre_techniques"];
}) {
  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-card shadow-card">
        <div className="flex items-center gap-2 border-b border-border px-5 py-3 text-sm font-semibold">
          <ShieldCheck className="h-4 w-4 text-primary" />
          Recommended Actions
        </div>
        <div className="space-y-3 p-5">
          {actions.length === 0 ? (
            <div className="text-sm text-muted-foreground">No recommended actions.</div>
          ) : (
            actions.map((action) => (
              <div key={action} className="rounded-md border border-border bg-background p-3 text-sm">
                {action}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card shadow-card">
        <div className="border-b border-border px-5 py-3 text-sm font-semibold">MITRE Techniques</div>
        <div className="space-y-3 p-5">
          {techniques.length === 0 ? (
            <div className="text-sm text-muted-foreground">No MITRE mappings.</div>
          ) : (
            techniques.map((technique) => (
              <div key={technique.technique_id} className="rounded-md border border-border bg-background p-3">
                <div className="font-mono text-xs text-primary">{technique.technique_id}</div>
                <div className="mt-1 text-sm font-semibold">{technique.technique_name}</div>
                <div className="mt-1 text-xs text-muted-foreground">{technique.tactic}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function GraphPanel({
  graph,
  loading,
}: {
  graph: Awaited<ReturnType<typeof backend.attackChainGraph>> | undefined;
  loading: boolean;
}) {
  return (
    <div className="rounded-lg border border-border bg-card shadow-card">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3 text-sm font-semibold">
        <Network className="h-4 w-4 text-primary" />
        Graph
        {loading && <RefreshCw className="h-3 w-3 animate-spin text-muted-foreground" />}
      </div>
      <div className="grid gap-4 p-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {(graph?.nodes ?? []).map((node) => (
            <div key={node.id} className="rounded-md border border-border bg-background p-3">
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
                {node.type.replaceAll("_", " ")}
              </div>
              <div className="mt-1 break-words text-sm font-semibold">{node.label}</div>
            </div>
          ))}
          {!loading && (graph?.nodes ?? []).length === 0 ? (
            <div className="text-sm text-muted-foreground">No graph nodes.</div>
          ) : null}
        </div>
        <div className="space-y-2">
          {(graph?.edges ?? []).slice(0, 24).map((edge) => (
            <div key={edge.id} className="rounded-md border border-border bg-background p-2 text-xs">
              <div className="font-medium capitalize">{edge.label}</div>
              <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
                {edge.source} {"->"} {edge.target}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
