import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Activity, Server, Box, RefreshCw, Bell, AlertTriangle, Zap, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { JsonViewer } from "@/components/JsonViewer";
import { api, ENDPOINTS } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";

export const Route = createFileRoute("/_app/dashboard")({
  component: DashboardPage,
});

function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  tone = "primary",
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  hint?: string;
  tone?: "primary" | "warning" | "destructive" | "info";
}) {
  const tones = {
    primary: "text-primary bg-primary/10",
    warning: "text-[var(--color-warning)] bg-[var(--color-warning)]/10",
    destructive: "text-destructive bg-destructive/10",
    info: "text-[var(--color-info)] bg-[var(--color-info)]/10",
  } as const;
  return (
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="mt-1 text-2xl font-semibold">{value}</div>
          {hint && <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div>}
        </div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-md ${tones[tone]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </CardContent>
    </Card>
  );
}

function DashboardPage() {
  const [root, setRoot] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [alertsCount, setAlertsCount] = useState<number | null>(null);
  const [incidentsCount, setIncidentsCount] = useState<number | null>(null);
  const [actionsCount, setActionsCount] = useState<number | null>(null);
  const [blockedCount, setBlockedCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const safe = async <T,>(p: Promise<T>) => p.catch(() => null);
    const [r, h, a, i, ac, bi] = await Promise.all([
      safe(api(ENDPOINTS.root, { auth: false })),
      safe(api(ENDPOINTS.health, { auth: false })),
      safe(api<any>(ENDPOINTS.alerts)),
      safe(api<any>(ENDPOINTS.incidents)),
      safe(api<any>(ENDPOINTS.soarActions)),
      safe(api<any>(ENDPOINTS.soarBlockedIps)),
    ]);
    setRoot(r);
    setHealth(h);
    const count = (x: any) =>
      Array.isArray(x) ? x.length : (x?.total ?? x?.items?.length ?? null);
    setAlertsCount(count(a));
    setIncidentsCount(count(i));
    setActionsCount(count(ac));
    setBlockedCount(Array.isArray(bi?.blocked_ips) ? bi.blocked_ips.length : count(bi));
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  const appName = root?.message || root?.app || root?.name || root?.service || "AI SOC Platform";
  const version = root?.version || health?.version || "—";
  const env = root?.environment || health?.environment || "—";
  const status = health?.status || (health ? "ok" : "unknown");

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">Operational overview of the SOC backend.</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-2">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Backend" value={status} icon={Server} hint={appName} tone="info" />
        <StatCard label="Version" value={version} icon={Box} hint={`env: ${env}`} />
        <StatCard label="Open Alerts" value={alertsCount ?? "—"} icon={Bell} tone="warning" />
        <StatCard
          label="Incidents"
          value={incidentsCount ?? "—"}
          icon={AlertTriangle}
          tone="destructive"
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <StatCard label="SOAR Actions" value={actionsCount ?? "—"} icon={Zap} tone="primary" />
        <StatCard label="Blocked IPs" value={blockedCount ?? "—"} icon={Shield} tone="info" />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" /> GET /
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-32 w-full" /> : <JsonViewer data={root} />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" /> GET /health
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-32 w-full" /> : <JsonViewer data={health} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
