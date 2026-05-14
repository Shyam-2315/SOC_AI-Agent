import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import { EmptyState } from "@/components/soc/States";
import { Btn } from "@/components/soc/Btn";
import { ClientTime } from "@/components/soc/ClientOnly";
import { useMounted } from "@/hooks/use-mounted";
import {
  backend,
  entityId,
  getWebsocketStatus,
  onWebsocketStatusChange,
  type AlertRecord,
  type SoarActionRecord,
} from "@/lib/api";
import {
  alertFromRealtimeEvent,
  onRealtimeEvent,
  soarActionFromRealtimeEvent,
} from "@/lib/live-data";
import { canQueryBackend, severityOf, textOf } from "@/lib/presentation";
import { Activity, RefreshCw, Zap } from "lucide-react";

export const Route = createFileRoute("/_app/realtime")({
  head: () => ({ meta: [{ title: "Realtime — SentinelAI" }] }),
  component: RealtimePage,
});

function uniqueById<T extends { id?: unknown; _id?: unknown }>(items: T[]): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const id = entityId(item);
    if (!id) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function RealtimePage() {
  const mounted = useMounted();
  const [websocketStatus, setLocalWebsocketStatus] = useState("not connected");
  const [liveAlerts, setLiveAlerts] = useState<AlertRecord[]>([]);
  const [liveActions, setLiveActions] = useState<SoarActionRecord[]>([]);
  const alertHistory = useQuery({
    queryKey: ["realtime", "alerts"],
    queryFn: () => backend.alerts({ limit: 8 }),
    enabled: canQueryBackend(),
  });
  const actionHistory = useQuery({
    queryKey: ["realtime", "actions"],
    queryFn: () => backend.soarActions({ limit: 8 }),
    enabled: canQueryBackend(),
  });

  useEffect(() => {
    setLocalWebsocketStatus(getWebsocketStatus());
    const removeStatus = onWebsocketStatusChange(() =>
      setLocalWebsocketStatus(getWebsocketStatus()),
    );
    const removeEvent = onRealtimeEvent((event) => {
      if (event.event_type === "soc.alert.created") {
        setLiveAlerts((items) => [alertFromRealtimeEvent(event), ...items].slice(0, 12));
      }
      if (event.event_type === "soc.response_action.created") {
        setLiveActions((items) => [soarActionFromRealtimeEvent(event), ...items].slice(0, 12));
      }
    });

    return () => {
      removeStatus();
      removeEvent();
    };
  }, []);

  const alerts = uniqueById([...liveAlerts, ...(alertHistory.data?.items ?? [])]).slice(0, 12);
  const actions = uniqueById([...liveActions, ...(actionHistory.data?.items ?? [])]).slice(0, 12);
  const connected = mounted && websocketStatus === "connected";
  const isRefreshing = alertHistory.isFetching || actionHistory.isFetching;
  const refreshHistory = () => {
    alertHistory.refetch();
    actionHistory.refetch();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="Realtime Feed"
        description="Live websocket stream of detections and response actions."
        actions={
          <>
            <Btn variant="outline" size="sm" onClick={refreshHistory} disabled={isRefreshing}>
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
              Refresh
            </Btn>
            <div
              className={`flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs capitalize ${connected ? "border-success/30 bg-success/10 text-success" : "border-border bg-card text-muted-foreground"}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-success animate-pulse" : "bg-muted-foreground"}`}
              />
              WebSocket: {websocketStatus}
            </div>
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Stream title="Alert stream" icon={<Activity className="h-4 w-4 text-primary" />}>
          {alerts.length === 0 ? (
            <li className="p-5">
              <EmptyState
                title="No alert events"
                description="Live alerts will appear when the backend publishes tenant events."
              />
            </li>
          ) : (
            alerts.map((alert, index) => (
              <li
                key={entityId(alert) || index}
                className="flex items-center gap-3 px-5 py-3 hover:bg-accent/40 animate-in fade-in slide-in-from-top-1"
              >
                <SeverityBadge severity={severityOf(alert.severity)} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">
                    {textOf(alert.message, textOf(alert.event_type, "Alert"))}
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {textOf(alert.ip_address)} · {textOf(alert.mitre_technique)}
                  </div>
                </div>
                <div className="text-xs text-muted-foreground">
                  <ClientTime value={alert.timestamp} />
                </div>
              </li>
            ))
          )}
        </Stream>
        <Stream title="SOAR action stream" icon={<Zap className="h-4 w-4 text-primary" />}>
          {actions.length === 0 ? (
            <li className="p-5">
              <EmptyState
                title="No response events"
                description="Live SOAR actions will appear when the backend publishes them."
              />
            </li>
          ) : (
            actions.map((action, index) => (
              <li
                key={entityId(action) || index}
                className="flex items-center gap-3 px-5 py-3 hover:bg-accent/40 animate-in fade-in slide-in-from-top-1"
              >
                <StatusBadge status={textOf(action.status, "simulated")} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">
                    {action.automated_actions?.[0] ?? "Response action"}
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {textOf(action.ip_address)} · {textOf(action.event_type)}
                  </div>
                </div>
                <div className="text-xs text-muted-foreground">
                  <ClientTime value={action.timestamp} />
                </div>
              </li>
            ))
          )}
        </Stream>
      </div>
    </div>
  );
}

function Stream({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card shadow-card">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3">
        {icon}
        <div className="text-sm font-semibold">{title}</div>
      </div>
      <ul className="scrollbar-thin max-h-[60vh] divide-y divide-border overflow-y-auto">
        {children}
      </ul>
    </div>
  );
}
