import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { RefreshCw, Bug, AlertTriangle, ShieldAlert, Skull, Crosshair } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JsonViewer } from "@/components/JsonViewer";
import { api, ENDPOINTS } from "@/lib/api";

export const Route = createFileRoute("/_app/hunting")({
  component: HuntingPage,
});

function Stat({ label, value, icon: Icon, tone = "primary" }: any) {
  const tones: Record<string, string> = {
    primary: "text-primary bg-primary/10",
    warning: "text-[var(--color-warning)] bg-[var(--color-warning)]/10",
    destructive: "text-destructive bg-destructive/10",
    info: "text-[var(--color-info)] bg-[var(--color-info)]/10",
  };
  return (
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="mt-1 text-2xl font-semibold">{value ?? "—"}</div>
        </div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-md ${tones[tone]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </CardContent>
    </Card>
  );
}

function HuntingPage() {
  const [stats, setStats] = useState<any>(null);
  const [campaigns, setCampaigns] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const safe = async <T,>(p: Promise<T>) => p.catch(() => null);
    const [s, c, t] = await Promise.all([
      safe(api<any>(ENDPOINTS.huntingStats)),
      safe(api<any>(ENDPOINTS.huntingCampaigns)),
      safe(api<any>(ENDPOINTS.huntingTimeline)),
    ]);
    setStats(s);
    setCampaigns(c);
    setTimeline(
      Array.isArray(t) ? t : (t as any)?.items || (t as any)?.events || (t as any)?.timeline || [],
    );
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  const total = stats?.total_alerts ?? stats?.total ?? null;
  const critical = stats?.critical_alerts ?? stats?.critical ?? null;
  const malware = stats?.malware_alerts ?? stats?.malware_count ?? stats?.malware ?? null;
  const ransomware =
    stats?.ransomware_alerts ?? stats?.ransomware_count ?? stats?.ransomware ?? null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Threat Hunting</h1>
          <p className="text-sm text-muted-foreground">
            Statistics, campaigns, and attack timeline.
          </p>
        </div>
        <Button onClick={load} variant="outline" size="sm" className="gap-2">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Stat label="Total alerts" value={total} icon={AlertTriangle} tone="info" />
        <Stat label="Critical" value={critical} icon={ShieldAlert} tone="destructive" />
        <Stat label="Malware" value={malware} icon={Bug} tone="warning" />
        <Stat label="Ransomware" value={ransomware} icon={Skull} tone="destructive" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-primary" /> Campaigns
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-xs text-muted-foreground">Loading…</div>
            ) : (
              <JsonViewer data={campaigns} />
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Stats payload</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-xs text-muted-foreground">Loading…</div>
            ) : (
              <JsonViewer data={stats} />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Attack Timeline</CardTitle>
        </CardHeader>
        <CardContent>
          {loading && <div className="text-xs text-muted-foreground">Loading…</div>}
          {!loading && timeline.length === 0 && (
            <div className="text-xs text-muted-foreground">No timeline events.</div>
          )}
          {!loading && timeline.length > 0 && (
            <ol className="relative ml-3 border-l border-border space-y-4">
              {timeline.map((ev, i) => (
                <li key={i} className="ml-4">
                  <div className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full bg-primary border-2 border-background" />
                  <div className="text-[11px] font-mono text-muted-foreground">
                    {ev.timestamp || ev.created_at || ev.time || `step ${i + 1}`}
                  </div>
                  <div className="text-sm font-medium">
                    {ev.title || ev.event_type || ev.action || ev.label || "Event"}
                  </div>
                  {ev.description && (
                    <div className="text-xs text-muted-foreground">{ev.description}</div>
                  )}
                  {(ev.mitre_tactic || ev.mitre_technique) && (
                    <div className="mt-1 flex flex-wrap gap-1 text-[10px] font-mono">
                      {ev.mitre_tactic && (
                        <span className="rounded bg-secondary px-1.5 py-0.5">
                          {ev.mitre_tactic}
                        </span>
                      )}
                      {ev.mitre_technique && (
                        <span className="rounded bg-secondary px-1.5 py-0.5">
                          {ev.mitre_technique}
                        </span>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
