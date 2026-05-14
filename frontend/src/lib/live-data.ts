import type { QueryClient } from "@tanstack/react-query";
import {
  entityId,
  type AlertRecord,
  type IncidentRecord,
  type Paginated,
  type SoarActionRecord,
} from "@/lib/api";
import { textOf } from "@/lib/presentation";

export const POLL_INTERVALS = {
  dashboard: 10_000,
  alerts: 5_000,
  incidents: 10_000,
  logs: 5_000,
  collectors: 15_000,
};

export type RealtimeEvent = {
  event_id?: string;
  event_type?: string;
  occurred_at?: string;
  payload?: Record<string, unknown>;
};

const LIVE_EVENT = "soc-live-event";

type LiveEventDetail = {
  event: RealtimeEvent;
};

function fallbackId(event: RealtimeEvent) {
  if (event.event_id) return event.event_id;
  return [
    event.event_type ?? "realtime-event",
    event.occurred_at ?? "unknown-time",
    JSON.stringify(event.payload ?? {}),
  ].join(":");
}

export function alertFromRealtimeEvent(event: RealtimeEvent): AlertRecord {
  const payload = event.payload ?? {};
  return {
    id: textOf(payload.alert_id, fallbackId(event)),
    source: textOf(payload.source, "realtime"),
    event_type: textOf(payload.event_type, "alert"),
    severity: textOf(payload.severity, "info"),
    message: textOf(payload.message, textOf(payload.event_type, "Alert")),
    ip_address: textOf(payload.ip_address),
    status: textOf(payload.status, "open"),
    threat_score: typeof payload.threat_score === "number" ? payload.threat_score : undefined,
    threat_label: typeof payload.threat_label === "string" ? payload.threat_label : undefined,
    mitre_tactic: textOf(payload.mitre_tactic),
    mitre_technique: textOf(payload.mitre_technique),
    mitre_tactic_id: typeof payload.mitre_tactic_id === "string" ? payload.mitre_tactic_id : null,
    mitre_tactic_name:
      typeof payload.mitre_tactic_name === "string" ? payload.mitre_tactic_name : null,
    mitre_technique_id:
      typeof payload.mitre_technique_id === "string" ? payload.mitre_technique_id : null,
    mitre_technique_name:
      typeof payload.mitre_technique_name === "string" ? payload.mitre_technique_name : null,
    correlation_id: typeof payload.correlation_id === "string" ? payload.correlation_id : null,
    matched_rule_id: typeof payload.matched_rule_id === "string" ? payload.matched_rule_id : null,
    matched_rule_name:
      typeof payload.matched_rule_name === "string" ? payload.matched_rule_name : null,
    timestamp: textOf(payload.timestamp, event.occurred_at ?? ""),
  };
}

export function incidentFromRealtimeEvent(event: RealtimeEvent): IncidentRecord {
  const payload = event.payload ?? {};
  return {
    id: textOf(payload.incident_id, fallbackId(event)),
    alert_id: typeof payload.alert_id === "string" ? payload.alert_id : undefined,
    title: textOf(payload.title, "Incident"),
    severity: textOf(payload.severity, "info"),
    status: textOf(payload.status, "open"),
    assigned_to_email:
      typeof payload.assigned_to_email === "string" ? payload.assigned_to_email : undefined,
    assigned_to: null,
    timestamp: textOf(payload.timestamp, event.occurred_at ?? ""),
  };
}

export function soarActionFromRealtimeEvent(event: RealtimeEvent): SoarActionRecord {
  const payload = event.payload ?? {};
  return {
    id: textOf(payload.response_action_id, fallbackId(event)),
    alert_id: typeof payload.alert_id === "string" ? payload.alert_id : undefined,
    event_type: textOf(payload.event_type, "response"),
    severity: textOf(payload.severity, "info"),
    ip_address: textOf(payload.ip_address),
    automated_actions: Array.isArray(payload.automated_actions)
      ? payload.automated_actions.map(String)
      : ["Response action"],
    blocked_ips: Array.isArray(payload.blocked_ips) ? payload.blocked_ips.map(String) : [],
    status: textOf(payload.status, "simulated"),
    timestamp: textOf(payload.timestamp, event.occurred_at ?? ""),
  };
}

function upsertPaginatedItem<T extends { id?: unknown; _id?: unknown }>(
  current: Paginated<T> | undefined,
  item: T,
): Paginated<T> | undefined {
  if (!current) return current;
  const id = entityId(item);
  const existing = current.items.filter((cached) => entityId(cached) !== id);
  const limit = current.limit || current.items.length || 100;
  return {
    ...current,
    total: existing.length === current.items.length ? current.total + 1 : current.total,
    items: [item, ...existing].slice(0, limit),
  };
}

function updatePaginatedQueries<T extends { id?: unknown; _id?: unknown }>(
  queryClient: QueryClient,
  queryKeys: unknown[][],
  item: T,
) {
  for (const queryKey of queryKeys) {
    queryClient.setQueriesData<Paginated<T>>({ queryKey }, (current) =>
      upsertPaginatedItem(current, item),
    );
  }
}

export function invalidateLiveData(queryClient: QueryClient) {
  queryClient.invalidateQueries({ queryKey: ["logs"] });
  queryClient.invalidateQueries({ queryKey: ["alerts"] });
  queryClient.invalidateQueries({ queryKey: ["incidents"] });
  queryClient.invalidateQueries({ queryKey: ["soar-actions"] });
  queryClient.invalidateQueries({ queryKey: ["blocked-ips"] });
  queryClient.invalidateQueries({ queryKey: ["collectors"] });
  queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  queryClient.invalidateQueries({ queryKey: ["realtime"] });
  queryClient.invalidateQueries({ queryKey: ["threat-hunting"] });
}

export function applyRealtimeEventToCache(queryClient: QueryClient, event: RealtimeEvent) {
  if (event.event_type === "soc.alert.created") {
    const alert = alertFromRealtimeEvent(event);
    updatePaginatedQueries(
      queryClient,
      [["alerts"], ["dashboard", "alerts"], ["realtime", "alerts"]],
      alert,
    );
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    queryClient.invalidateQueries({ queryKey: ["threat-hunting"] });
    return;
  }

  if (event.event_type === "soc.incident.created") {
    const incident = incidentFromRealtimeEvent(event);
    updatePaginatedQueries(queryClient, [["incidents"], ["dashboard", "incidents"]], incident);
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    return;
  }

  if (
    event.event_type === "incident.updated" ||
    event.event_type === "correlation.created" ||
    event.event_type === "correlation.updated" ||
    event.event_type === "timeline.updated"
  ) {
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    queryClient.invalidateQueries({ queryKey: ["threat-hunting"] });
    return;
  }

  if (event.event_type === "soc.response_action.created") {
    const action = soarActionFromRealtimeEvent(event);
    updatePaginatedQueries(
      queryClient,
      [["soar-actions"], ["dashboard", "soar-actions"], ["realtime", "actions"]],
      action,
    );
    queryClient.invalidateQueries({ queryKey: ["blocked-ips"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  }
}

export function emitRealtimeEvent(event: RealtimeEvent) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent<LiveEventDetail>(LIVE_EVENT, { detail: { event } }));
}

export function onRealtimeEvent(listener: (event: RealtimeEvent) => void): () => void {
  if (typeof window === "undefined") return () => undefined;
  const handler = (raw: Event) => {
    const event = raw as CustomEvent<LiveEventDetail>;
    listener(event.detail.event);
  };
  window.addEventListener(LIVE_EVENT, handler);
  return () => window.removeEventListener(LIVE_EVENT, handler);
}
