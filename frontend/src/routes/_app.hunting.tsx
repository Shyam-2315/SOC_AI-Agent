import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { Crosshair, Play, Search } from "lucide-react";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, type ThreatTimelineRecord } from "@/lib/api";
import { canQueryBackend, dateTimeOf, severityOf, textOf } from "@/lib/presentation";

export const Route = createFileRoute("/_app/hunting")({
  head: () => ({ meta: [{ title: "Threat Hunting — SentinelAI" }] }),
  component: HuntingPage,
});

const PRESETS = [
  { name: "Lateral movement (SMB)", q: "event.proto:smb AND event.action:auth_failure" },
  {
    name: "Suspicious PowerShell",
    q: "process.name:powershell.exe AND process.cmd:*-EncodedCommand*",
  },
  { name: "TOR exits", q: "dest.ip in tor_exit_nodes" },
];

function HuntingPage() {
  const [q, setQ] = useState(PRESETS[0].q);
  const [ran, setRan] = useState(false);
  const enabled = canQueryBackend() && ran;
  const timeline = useQuery({
    queryKey: ["threat-hunting", "timeline", q],
    queryFn: () => backend.threatTimeline({ limit: 100 }),
    enabled,
  });
  const campaigns = useQuery({
    queryKey: ["threat-hunting", "campaigns", q],
    queryFn: () => backend.threatCampaigns({ limit: 100 }),
    enabled,
  });
  const stats = useQuery({
    queryKey: ["threat-hunting", "statistics", q],
    queryFn: backend.threatStatistics,
    enabled,
  });

  const error = [timeline, campaigns, stats].find((query) => query.error)?.error;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Investigation"
        title="Threat Hunting"
        description="Pivot across telemetry using backend attack timeline, campaign correlation and threat statistics."
      />

      <div className="rounded-xl border border-border bg-card p-4 shadow-card">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <textarea
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setRan(false);
            }}
            rows={3}
            className="w-full resize-none rounded-md border border-border bg-background px-9 py-2.5 font-mono text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Btn variant="hero" size="sm" onClick={() => setRan(true)}>
            <Play className="h-3.5 w-3.5" /> Run hunt
          </Btn>
          <span className="text-xs text-muted-foreground">Presets:</span>
          {PRESETS.map((preset) => (
            <button
              key={preset.name}
              onClick={() => {
                setQ(preset.q);
                setRan(false);
              }}
              className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground"
            >
              {preset.name}
            </button>
          ))}
        </div>
      </div>

      {!ran ? (
        <EmptyState
          icon={<Crosshair className="h-5 w-5" />}
          title="No hunt run yet"
          description="Choose a preset or write a query, then click Run hunt. The backend currently returns organization-wide timeline and campaign correlation."
        />
      ) : error ? (
        <ErrorState
          message={error instanceof Error ? error.message : "Could not run threat hunt."}
        />
      ) : timeline.isLoading || campaigns.isLoading || stats.isLoading ? (
        <LoadingState label="Running threat hunt…" />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
          <div className="overflow-hidden rounded-xl border border-border bg-card shadow-card">
            <div className="border-b border-border px-5 py-3 text-sm font-semibold">
              Timeline results · {timeline.data?.items.length ?? 0}
            </div>
            <ul className="divide-y divide-border">
              {(timeline.data?.items ?? []).length === 0 ? (
                <li className="p-5">
                  <EmptyState
                    title="No hunt results"
                    description="The backend returned no matching organization timeline events."
                  />
                </li>
              ) : (
                (timeline.data?.items ?? []).map((result: ThreatTimelineRecord, index) => (
                  <li
                    key={`${result.timestamp}-${index}`}
                    className="flex items-center gap-3 px-5 py-3 hover:bg-accent/40"
                  >
                    <SeverityBadge severity={severityOf(result.severity)} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">
                        {textOf(result.event_type, "event")}
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {textOf(result.source)} · {textOf(result.ip_address)}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {dateTimeOf(result.timestamp)}
                    </div>
                  </li>
                ))
              )}
            </ul>
          </div>
          <div className="space-y-4">
            <div className="rounded-xl border border-border bg-card p-4 shadow-card">
              <div className="text-sm font-semibold">Statistics</div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                <Metric label="Alerts" value={stats.data?.total_alerts ?? 0} />
                <Metric label="Critical" value={stats.data?.critical_alerts ?? 0} />
                <Metric label="Malware" value={stats.data?.malware_alerts ?? 0} />
                <Metric label="Ransomware" value={stats.data?.ransomware_alerts ?? 0} />
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4 shadow-card">
              <div className="text-sm font-semibold">Campaigns</div>
              <div className="mt-2 text-2xl font-semibold">
                {campaigns.data?.detected_campaigns.length ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">
                Correlated from current backend alerts.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background/50 p-3">
      <div className="text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}
