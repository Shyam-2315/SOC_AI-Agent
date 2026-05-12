import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Bell, AlertOctagon, Zap, Radio, Activity, ShieldCheck, ArrowRight } from "lucide-react";
import { StatCard } from "@/components/soc/StatCard";
import { PageHeader } from "@/components/soc/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import { Btn } from "@/components/soc/Btn";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type AlertRecord, type IncidentRecord } from "@/lib/api";
import { canQueryBackend, dateTimeOf, severityOf, textOf, timeOf } from "@/lib/presentation";

export const Route = createFileRoute("/_app/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — SentinelAI" }] }),
  component: Dashboard,
});

function tacticCounts(alerts: AlertRecord[]) {
  const counts = new Map<string, number>();
  for (const alert of alerts) {
    const tactic = textOf(alert.mitre_tactic, "Unknown");
    counts.set(tactic, (counts.get(tactic) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

function campaignLabel(campaign: unknown, index: number): string {
  if (campaign && typeof campaign === "object") {
    const fields = campaign as Record<string, unknown>;
    return textOf(fields.name ?? fields.campaign ?? fields.id, `Campaign ${index + 1}`);
  }
  return `Campaign ${index + 1}`;
}

function Dashboard() {
  const enabled = canQueryBackend();
  const alerts = useQuery({
    queryKey: ["dashboard", "alerts"],
    queryFn: () => backend.alerts({ limit: 100 }),
    enabled,
  });
  const incidents = useQuery({
    queryKey: ["dashboard", "incidents"],
    queryFn: () => backend.incidents({ limit: 100 }),
    enabled,
  });
  const actions = useQuery({
    queryKey: ["dashboard", "soar-actions"],
    queryFn: () => backend.soarActions({ limit: 100 }),
    enabled,
  });
  const collectors = useQuery({
    queryKey: ["dashboard", "collectors"],
    queryFn: () => backend.collectors({ limit: 100 }),
    enabled,
  });
  const stats = useQuery({
    queryKey: ["dashboard", "threat-statistics"],
    queryFn: backend.threatStatistics,
    enabled,
  });
  const campaigns = useQuery({
    queryKey: ["dashboard", "campaigns"],
    queryFn: () => backend.threatCampaigns({ limit: 100 }),
    enabled,
  });

  const queries = [alerts, incidents, actions, collectors, stats, campaigns];
  if (queries.some((q) => q.isLoading || q.isPending))
    return <LoadingState label="Loading SOC overview…" />;
  const error = queries.find((q) => q.error)?.error;
  if (error)
    return (
      <ErrorState
        message={error instanceof Error ? error.message : "Could not load dashboard data."}
      />
    );

  const alertItems = alerts.data?.items ?? [];
  const incidentItems = incidents.data?.items ?? [];
  const actionItems = actions.data?.items ?? [];
  const collectorItems = collectors.data?.items ?? [];
  const openIncidents = incidentItems.filter(
    (i) => !["closed", "resolved"].includes(String(i.status ?? "").toLowerCase()),
  );
  const activeCollectors = collectorItems.filter((c) => c.status === "active");
  const tactics = tacticCounts(alertItems);
  const maxTacticCount = Math.max(1, ...tactics.map((t) => t.count));

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="SOC Overview"
        description="Live posture across detections, incidents and automated response."
        actions={
          <Link to="/hunting">
            <Btn variant="outline" size="sm">
              Start hunt <ArrowRight className="h-4 w-4" />
            </Btn>
          </Link>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Total alerts"
          value={(stats.data?.total_alerts ?? alertItems.length).toLocaleString()}
          hint="organization"
          icon={<Bell className="h-4 w-4" />}
          accent="primary"
        />
        <StatCard
          label="Critical"
          value={
            stats.data?.critical_alerts ??
            alertItems.filter((a) => severityOf(a.severity) === "critical").length
          }
          hint="needs review"
          icon={<ShieldCheck className="h-4 w-4" />}
          accent="critical"
        />
        <StatCard
          label="Open incidents"
          value={openIncidents.length}
          hint="active"
          icon={<AlertOctagon className="h-4 w-4" />}
          accent="warning"
        />
        <StatCard
          label="SOAR actions"
          value={actionItems.length}
          hint="recent"
          icon={<Zap className="h-4 w-4" />}
          accent="info"
        />
        <StatCard
          label="Collectors"
          value={`${activeCollectors.length}/${collectorItems.length}`}
          hint="active"
          icon={<Radio className="h-4 w-4" />}
          accent="success"
        />
        <StatCard
          label="Realtime"
          value="Open"
          hint="feed page"
          icon={<Activity className="h-4 w-4" />}
          accent="success"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 rounded-xl border border-border bg-card shadow-card">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="text-sm font-semibold">Recent alerts</div>
            <Link to="/alerts" className="text-xs text-primary hover:underline">
              View all →
            </Link>
          </div>
          <ul className="divide-y divide-border">
            {alertItems.length === 0 ? (
              <li className="p-5">
                <EmptyState
                  title="No alerts yet"
                  description="Create a collector and ingest a log to populate real tenant alerts."
                />
              </li>
            ) : (
              alertItems.slice(0, 6).map((alert) => (
                <li
                  key={entityId(alert)}
                  className="flex items-center gap-3 px-5 py-3 hover:bg-accent/40"
                >
                  <SeverityBadge severity={severityOf(alert.severity)} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">
                      {textOf(alert.message, textOf(alert.event_type, "Alert"))}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {textOf(alert.mitre_tactic)} · {textOf(alert.mitre_technique)} ·{" "}
                      {textOf(alert.ip_address)}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">{timeOf(alert.timestamp)}</div>
                </li>
              ))
            )}
          </ul>
        </div>

        <div className="rounded-xl border border-border bg-card shadow-card">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="text-sm font-semibold">Open incidents</div>
            <Link to="/incidents" className="text-xs text-primary hover:underline">
              View all →
            </Link>
          </div>
          <ul className="divide-y divide-border">
            {openIncidents.length === 0 ? (
              <li className="p-5">
                <EmptyState
                  title="No open incidents"
                  description="Incidents will appear here after alerts are promoted or created."
                />
              </li>
            ) : (
              openIncidents.slice(0, 5).map((incident: IncidentRecord) => (
                <li key={entityId(incident)} className="px-5 py-3 hover:bg-accent/40">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm font-medium truncate">
                      {textOf(incident.title, "Incident")}
                    </div>
                    <SeverityBadge severity={severityOf(incident.severity)} />
                  </div>
                  <div className="mt-1 flex items-center justify-between text-xs text-muted-foreground">
                    <span>{textOf(incident.assigned_to, "Unassigned")}</span>
                    <StatusBadge status={textOf(incident.status, "open")} />
                  </div>
                </li>
              ))
            )}
          </ul>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 rounded-xl border border-border bg-card p-5 shadow-card">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-semibold">MITRE ATT&CK tactics</div>
            <span className="text-xs text-muted-foreground">{alertItems.length} detections</span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {tactics.length === 0 ? (
              <div className="col-span-full">
                <EmptyState
                  title="No MITRE tactics"
                  description="Tactic counts are derived from real backend alerts."
                />
              </div>
            ) : (
              tactics.map((t) => (
                <div key={t.name} className="rounded-lg border border-border bg-background/50 p-3">
                  <div className="text-xs text-muted-foreground">{t.name}</div>
                  <div className="mt-1 flex items-end justify-between">
                    <div className="text-xl font-semibold tabular-nums">{t.count}</div>
                    <div className="h-1.5 w-16 overflow-hidden rounded bg-border">
                      <div
                        className="h-full bg-gradient-primary"
                        style={{ width: `${(t.count / maxTacticCount) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card shadow-card">
          <div className="border-b border-border px-5 py-3 text-sm font-semibold">
            Threat campaigns
          </div>
          <ul className="divide-y divide-border">
            {(campaigns.data?.detected_campaigns ?? []).slice(0, 5).map((campaign, index) => (
              <li key={index} className="px-5 py-3">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium">{campaignLabel(campaign, index)}</div>
                    <div className="text-xs text-muted-foreground">
                      Detected from correlated backend alerts
                    </div>
                  </div>
                  <SeverityBadge severity="high" />
                </div>
              </li>
            ))}
            {(campaigns.data?.detected_campaigns ?? []).length === 0 && (
              <li className="px-5 py-6 text-sm text-muted-foreground">
                No correlated campaigns detected.
              </li>
            )}
          </ul>
        </div>
      </div>
    </div>
  );
}
