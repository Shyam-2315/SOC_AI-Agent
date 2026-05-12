import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import { EmptyState } from "@/components/soc/States";
import {
  backend,
  entityId,
  setWebsocketStatus,
  wsUrl,
  type AlertRecord,
  type SoarActionRecord,
} from "@/lib/api";
import { canQueryBackend, severityOf, textOf, timeOf } from "@/lib/presentation";
import { Activity, Zap } from "lucide-react";

export const Route = createFileRoute("/_app/realtime")({
  head: () => ({ meta: [{ title: "Realtime — SentinelAI" }] }),
  component: RealtimePage,
});

type RealtimeEvent = {
  event_id?: string;
  event_type?: string;
  occurred_at?: string;
  payload?: Record<string, unknown>;
};

function alertFromEvent(event: RealtimeEvent): AlertRecord {
  const payload = event.payload ?? {};
  return {
    id: textOf(event.event_id, crypto.randomUUID()),
    severity: textOf(payload.severity, "info"),
    message: textOf(payload.message, textOf(payload.event_type, "Alert")),
    event_type: textOf(payload.event_type, "alert"),
    ip_address: textOf(payload.ip_address, "Unknown"),
    mitre_technique: textOf(payload.mitre_technique, "Unknown"),
    timestamp: event.occurred_at ?? new Date().toISOString(),
  };
}

function actionFromEvent(event: RealtimeEvent): SoarActionRecord {
  const payload = event.payload ?? {};
  return {
    id: textOf(event.event_id, crypto.randomUUID()),
    status: textOf(payload.status, "simulated"),
    event_type: textOf(payload.event_type, "response"),
    ip_address: textOf(payload.ip_address, "Unknown"),
    automated_actions: Array.isArray(payload.automated_actions)
      ? payload.automated_actions.map(String)
      : ["Response action"],
    timestamp: event.occurred_at ?? new Date().toISOString(),
  };
}

function RealtimePage() {
  const [enabled, setEnabled] = useState(true);
  const [connected, setConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<AlertRecord[]>([]);
  const [liveActions, setLiveActions] = useState<SoarActionRecord[]>([]);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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
    if (!enabled || !canQueryBackend()) {
      socketRef.current?.close();
      setConnected(false);
      setWebsocketStatus(enabled ? "missing auth" : "disabled");
      return;
    }

    let closedByEffect = false;
    setWebsocketStatus("connecting");
    const socket = new WebSocket(wsUrl("/ws/alerts"));
    socketRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      setConnectionError(null);
      setWebsocketStatus("connected");
      socket.send(
        JSON.stringify({
          action: "subscribe",
          replace: true,
          event_types: [
            "soc.alert.created",
            "soc.incident.created",
            "soc.response_action.created",
            "system.connected",
          ],
        }),
      );
    };
    socket.onmessage = (message) => {
      let event: RealtimeEvent;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      if (event.event_type === "soc.alert.created" || event.event_type === "soc.incident.created") {
        setLiveAlerts((items) => [alertFromEvent(event), ...items].slice(0, 12));
      }
      if (event.event_type === "soc.response_action.created") {
        setLiveActions((items) => [actionFromEvent(event), ...items].slice(0, 12));
      }
    };
    socket.onerror = () => {
      setConnectionError("WebSocket connection failed.");
      setWebsocketStatus("error");
    };
    socket.onclose = () => {
      setConnected(false);
      if (!closedByEffect && enabled) {
        setWebsocketStatus("reconnecting");
        reconnectTimerRef.current = setTimeout(() => {
          setReconnectAttempt((value) => value + 1);
        }, 2500);
      } else {
        setWebsocketStatus("disconnected");
      }
    };

    return () => {
      closedByEffect = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      socket.close();
    };
  }, [enabled, reconnectAttempt]);

  const alerts = [...liveAlerts, ...(alertHistory.data?.items ?? [])].slice(0, 12);
  const actions = [...liveActions, ...(actionHistory.data?.items ?? [])].slice(0, 12);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="Realtime Feed"
        description={connectionError ?? "Live websocket stream of detections and response actions."}
        actions={
          <button
            onClick={() => setEnabled((value) => !value)}
            className={`flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs ${connected ? "border-success/30 bg-success/10 text-success" : "border-border bg-card text-muted-foreground"}`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-success animate-pulse" : "bg-muted-foreground"}`}
            />
            {connected ? "Connected" : enabled ? "Connecting" : "Disconnected"}
          </button>
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
                <div className="text-xs text-muted-foreground">{timeOf(alert.timestamp)}</div>
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
                <div className="text-xs text-muted-foreground">{timeOf(action.timestamp)}</div>
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
