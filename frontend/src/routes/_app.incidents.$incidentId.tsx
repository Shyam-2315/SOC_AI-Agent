import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { ClientDateTime } from "@/components/soc/ClientOnly";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import {
  ApiError,
  backend,
  entityId,
  incidentRecordId,
  type AlertRecord,
  type IncidentRecord,
  type MitreMapping,
  type SoarActionRecord,
  type ThreatTimelineRecord,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend, severityOf, shortId, textOf } from "@/lib/presentation";
import {
  Activity,
  ArrowLeft,
  ClipboardList,
  Network,
  RefreshCw,
  Save,
  ShieldCheck,
} from "lucide-react";

export const Route = createFileRoute("/_app/incidents/$incidentId")({
  head: () => ({ meta: [{ title: "Incident Investigation - SentinelAI" }] }),
  component: IncidentInvestigationPage,
});

const STATUSES = ["new", "investigating", "contained", "resolved", "false_positive"];

function IncidentInvestigationPage() {
  const { incidentId } = Route.useParams();
  const queryClient = useQueryClient();
  const incident = useQuery({
    queryKey: ["incidents", incidentId],
    queryFn: () => backend.incident(incidentId),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });
  const timeline = useQuery({
    queryKey: ["threat-hunting", "timeline", incidentId],
    queryFn: () => backend.incidentTimeline(incidentId),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });
  const soar = useQuery({
    queryKey: ["soar", "actions", incidentId],
    queryFn: () => backend.soarActions({ incident_id: incidentId, limit: 100 }),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });
  const [notes, setNotes] = useState<string | null>(null);
  const [assignee, setAssignee] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (payload: {
      status?: string;
      assigned_to_email?: string | null;
      investigation_notes?: string | null;
    }) => backend.updateIncident(incidentId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["threat-hunting", "timeline", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["soar", "actions", incidentId] });
    },
  });

  if (incident.isLoading || incident.isPending) return <LoadingState label="Loading incident..." />;
  if (incident.error) {
    const isMissing = incident.error instanceof ApiError && incident.error.status === 404;
    return (
      <IncidentLoadError
        title={isMissing ? "Incident not found" : "Incident could not be loaded"}
        message={
          isMissing
            ? "The selected incident does not exist or is no longer available."
            : errorMessage(incident.error, "The incident API request failed.")
        }
        onRetry={isMissing ? undefined : () => incident.refetch()}
      />
    );
  }

  if (!incident.data) {
    return (
      <IncidentLoadError
        title="Incident not found"
        message="The selected incident does not exist or is no longer available."
      />
    );
  }

  const item = incident.data as IncidentRecord;
  const relatedAlerts = item.related_alerts ?? [];
  const mitreMappings = incidentMitreMappings(item);
  const correlation = timeline.data?.correlation ?? item.correlation ?? null;
  const correlationId = textValue(item.correlation_id ?? correlation?.correlation_id);
  const correlationScore = item.correlation_score ?? correlation?.correlation_score;
  const attackStage = textValue(item.attack_stage ?? correlation?.attack_stage);
  const timelineEvents =
    timeline.data?.events && timeline.data.events.length > 0
      ? timeline.data.events
      : (item.timeline_events ?? []);
  const soarActionsFromDetail = item.soar_actions ?? [];
  const soarActions =
    soarActionsFromDetail.length > 0 ? soarActionsFromDetail : (soar.data?.items ?? []);
  const incidentHosts = item.related_hosts ?? [];
  const incidentIps = item.related_ips ?? [];
  const relatedHosts =
    incidentHosts.length > 0 ? incidentHosts : (timeline.data?.correlated_hosts ?? []);
  const relatedIps = incidentIps.length > 0 ? incidentIps : (timeline.data?.correlated_ips ?? []);
  const summary = textValue(timeline.data?.summary ?? item.investigation_summary);
  const currentNotes = notes ?? textOf(item.investigation_notes ?? item.notes, "");
  const currentAssignee = assignee ?? textOf(item.assigned_to_email ?? item.assigned_to, "");

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Investigation"
        title={textOf(item.title, "Incident investigation")}
        description={
          <span className="flex flex-col gap-1">
            <span className="font-mono text-xs">{shortIncidentId(item)}</span>
            <span>
              Assigned analyst: {currentAssignee || "Unassigned"} · Opened{" "}
              <ClientDateTime value={item.timestamp} />
            </span>
          </span>
        }
        actions={
          <>
            <Link to="/incidents">
              <Btn variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4" /> Incidents
              </Btn>
            </Link>
            <Link to="/threat-hunting/timeline/$incidentId" params={{ incidentId }}>
              <Btn variant="outline" size="sm">
                Timeline
              </Btn>
            </Link>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => {
                incident.refetch();
                timeline.refetch();
                soar.refetch();
              }}
              disabled={incident.isFetching || timeline.isFetching || soar.isFetching}
            >
              <RefreshCw
                className={`h-4 w-4 ${
                  incident.isFetching || timeline.isFetching || soar.isFetching
                    ? "animate-spin"
                    : ""
                }`}
              />
              Refresh
            </Btn>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        <section className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-5 shadow-card">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={severityOf(item.severity)} />
              <StatusBadge status={textOf(item.status, "new")} />
              <span className="rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 text-xs text-primary">
                {attackStage || "No data yet"}
              </span>
              {correlationScore !== undefined && correlationScore !== null && (
                <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                  Score {correlationScore}
                </span>
              )}
              <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                Analyst {currentAssignee || "Unassigned"}
              </span>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <Metric label="Related alerts" value={relatedAlerts.length} />
              <Metric label="Hosts" value={relatedHosts.length} />
              <Metric label="SOAR actions" value={soarActions.length} />
            </div>
          </div>

          <SectionCard
            title="MITRE ATT&CK"
            icon={<ShieldCheck className="h-4 w-4" />}
            empty={mitreMappings.length === 0}
            emptyDescription="No MITRE tactic or technique has been attached to this incident yet."
          >
            <div className="grid gap-3 md:grid-cols-2">
              {mitreMappings.map((mapping, index) => (
                <MitreCard key={mitreKey(mapping, index)} mapping={mapping} />
              ))}
            </div>
          </SectionCard>

          <SectionCard
            title="Investigation summary"
            icon={<ClipboardList className="h-4 w-4" />}
            empty={!summary}
            emptyDescription="No generated summary is available yet."
          >
            <p className="text-sm leading-6 text-muted-foreground">{summary}</p>
          </SectionCard>

          <SectionCard
            title="Correlation details"
            icon={<Network className="h-4 w-4" />}
            empty={!correlationId && correlationScore == null && !attackStage}
            emptyDescription="No correlation data has been produced for this incident yet."
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <DetailField label="Correlation ID" value={correlationId || "No data yet"} mono />
              <DetailField
                label="Correlation score"
                value={
                  correlationScore === undefined || correlationScore === null
                    ? "No data yet"
                    : String(correlationScore)
                }
              />
              <DetailField label="Attack stage" value={attackStage || "No data yet"} />
              <DetailField
                label="Related alert IDs"
                value={(correlation?.related_alert_ids ?? item.related_alert_ids ?? []).join(", ")}
                fallback="No data yet"
                mono
              />
            </div>
          </SectionCard>

          <SectionCard
            title="Related alerts"
            empty={relatedAlerts.length === 0}
            emptyDescription="No alerts are currently linked to this incident."
          >
            <RelatedAlertsTable alerts={relatedAlerts} />
          </SectionCard>

          <SectionCard
            title="Attack timeline"
            icon={<Activity className="h-4 w-4" />}
            isLoading={(timeline.isLoading || timeline.isPending) && timelineEvents.length === 0}
            error={
              timeline.error && timelineEvents.length === 0
                ? errorMessage(timeline.error, "Timeline could not be loaded.")
                : null
            }
            onRetry={() => timeline.refetch()}
            empty={timelineEvents.length === 0}
            emptyDescription="Timeline events appear after alerts are correlated with this incident."
          >
            <TimelineList events={timelineEvents} />
          </SectionCard>

          <SectionCard
            title="SOAR actions"
            isLoading={soar.isLoading && soarActionsFromDetail.length === 0}
            error={
              soar.error && soarActions.length === 0
                ? errorMessage(soar.error, "SOAR actions could not be loaded.")
                : null
            }
            onRetry={() => soar.refetch()}
            empty={soarActions.length === 0}
            emptyDescription="No automated response actions have been recorded for this incident yet."
          >
            <SoarActionsList actions={soarActions} />
          </SectionCard>
        </section>

        <aside className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-4 shadow-card">
            <div className="text-sm font-semibold">Analyst notes and status</div>
            <label className="mt-3 block text-xs text-muted-foreground">Status</label>
            <div className="mt-2 flex flex-wrap gap-2">
              {STATUSES.map((status) => (
                <button
                  key={status}
                  onClick={() => save.mutate({ status })}
                  className={`rounded-md border px-2 py-1 text-xs capitalize ${
                    textOf(item.status).toLowerCase() === status
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {status.replace("_", " ")}
                </button>
              ))}
            </div>
            <label className="mt-4 block text-xs text-muted-foreground">Assigned email</label>
            <input
              value={currentAssignee}
              onChange={(event) => setAssignee(event.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            <label className="mt-4 block text-xs text-muted-foreground">Notes</label>
            <textarea
              value={currentNotes}
              onChange={(event) => setNotes(event.target.value)}
              rows={6}
              className="mt-1 w-full resize-none rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            {save.error && (
              <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                {errorMessage(save.error, "Incident update failed.")}
              </div>
            )}
            <Btn
              className="mt-3 w-full"
              size="sm"
              variant="hero"
              onClick={() =>
                save.mutate({
                  assigned_to_email: currentAssignee || null,
                  investigation_notes: currentNotes || null,
                })
              }
              disabled={save.isPending}
            >
              <Save className="h-4 w-4" /> Save
            </Btn>
          </div>

          <SectionCard
            title="Related hosts and IPs"
            empty={relatedHosts.length === 0 && relatedIps.length === 0}
            emptyDescription="No host or IP enrichment has been attached yet."
          >
            <div className="space-y-3">
              <PanelList title="Hosts" items={relatedHosts} />
              <PanelList title="IPs" items={relatedIps} mono />
            </div>
          </SectionCard>
        </aside>
      </div>
    </div>
  );
}

function IncidentLoadError({
  title,
  message,
  onRetry,
}: {
  title: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="space-y-4">
      <Link to="/incidents">
        <Btn variant="outline" size="sm">
          <ArrowLeft className="h-4 w-4" /> Incidents
        </Btn>
      </Link>
      <ErrorState
        title={title}
        message={message}
        onRetry={onRetry}
        action={
          <div className="flex flex-wrap justify-center gap-2">
            {onRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="rounded-md border border-border bg-card px-3 py-1.5 text-xs text-foreground transition hover:border-primary/40"
              >
                Retry
              </button>
            )}
            <Link
              to="/incidents"
              className="rounded-md border border-border bg-card px-3 py-1.5 text-xs text-foreground transition hover:border-primary/40"
            >
              Back to incidents
            </Link>
          </div>
        }
      />
    </div>
  );
}

function SectionCard({
  title,
  children,
  icon,
  isLoading = false,
  error,
  onRetry,
  empty = false,
  emptyTitle = "No data yet",
  emptyDescription,
}: {
  title: string;
  children: ReactNode;
  icon?: ReactNode;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  empty?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card shadow-card">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3 text-sm font-semibold">
        {icon && <span className="text-primary">{icon}</span>}
        {title}
      </div>
      <div className="p-5">
        {isLoading ? (
          <LoadingState label={`Loading ${title.toLowerCase()}...`} />
        ) : error ? (
          <ErrorState message={error} onRetry={onRetry} />
        ) : empty ? (
          <EmptyState title={emptyTitle} description={emptyDescription} />
        ) : (
          children
        )}
      </div>
    </div>
  );
}

function TimelineList({ events }: { events: ThreatTimelineRecord[] }) {
  return (
    <ol className="divide-y divide-border overflow-hidden rounded-lg border border-border">
      {events.map((event, index) => (
        <li
          key={`${event.alert_id ?? event.timestamp}-${index}`}
          className="grid gap-3 bg-background/40 px-4 py-4 sm:grid-cols-[160px_1fr]"
        >
          <div className="text-xs text-muted-foreground">
            <ClientDateTime value={event.timestamp} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={severityOf(event.severity)} />
              <span className="text-sm font-medium">{textOf(event.event_type, "event")}</span>
              <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                {textOf(event.attack_stage, "No data yet")}
              </span>
            </div>
            <div className="mt-1 text-sm text-muted-foreground">
              {textOf(event.message, "No message available.")}
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[11px]">
              <span className="rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary">
                {textOf(event.mitre?.tactic_id, textOf(event.mitre?.tactic_name, "No data yet"))}
              </span>
              <span className="rounded border border-border px-2 py-0.5 text-muted-foreground">
                {textOf(
                  event.mitre?.technique_id,
                  textOf(event.mitre?.technique_name, "No data yet"),
                )}
              </span>
              <span className="rounded border border-border px-2 py-0.5 text-muted-foreground">
                {textOf(event.host ?? event.source, "Unknown host")} ·{" "}
                {textOf(event.ip_address, "Unknown IP")}
              </span>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

function RelatedAlertsTable({ alerts }: { alerts: AlertRecord[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="min-w-full divide-y divide-border text-sm">
        <thead className="bg-background/70 text-left text-xs uppercase text-muted-foreground">
          <tr>
            <th className="px-4 py-3 font-medium">Alert</th>
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">MITRE</th>
            <th className="px-4 py-3 font-medium">Host/IP</th>
            <th className="px-4 py-3 font-medium">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {alerts.map((alert) => (
            <tr key={entityId(alert)} className="bg-background/40">
              <td className="max-w-md px-4 py-3">
                <div className="font-medium">{textOf(alert.message, textOf(alert.event_type))}</div>
                <div className="mt-1 font-mono text-xs text-muted-foreground">
                  {shortId(alert, "ALT-")}
                </div>
              </td>
              <td className="px-4 py-3">
                <SeverityBadge severity={severityOf(alert.severity)} />
              </td>
              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                <div>
                  {textOf(alert.mitre_tactic_id, textOf(alert.mitre_tactic_name, "No data yet"))}
                </div>
                <div>
                  {textOf(
                    alert.mitre_technique_id,
                    textOf(alert.mitre_technique_name, "No data yet"),
                  )}
                </div>
              </td>
              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                <div>{textOf(alert.hostname ?? alert.host ?? alert.source, "Unknown host")}</div>
                <div>{textOf(alert.ip_address, "Unknown IP")}</div>
              </td>
              <td className="px-4 py-3 text-xs text-muted-foreground">
                <ClientDateTime value={alert.timestamp} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SoarActionsList({ actions }: { actions: SoarActionRecord[] }) {
  return (
    <div className="space-y-3">
      {actions.map((action) => (
        <div
          key={entityId(action)}
          className="rounded-lg border border-border bg-background/50 p-4"
        >
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={severityOf(action.severity)} />
            <span className="text-sm font-medium">{textOf(action.event_type, "response")}</span>
            <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
              {textOf(action.status, "simulated")}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              <ClientDateTime value={action.timestamp} />
            </span>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <ActionList title="Automated actions" items={action.automated_actions ?? []} />
            <ActionList title="Blocked IPs" items={action.blocked_ips ?? []} mono />
          </div>
        </div>
      ))}
    </div>
  );
}

function ActionList({
  title,
  items,
  mono = false,
}: {
  title: string;
  items: string[];
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <div className={`mt-2 space-y-1.5 text-xs ${mono ? "font-mono" : ""}`}>
        {items.length === 0 ? (
          <div className="text-muted-foreground">No data yet</div>
        ) : (
          items.map((item) => (
            <div key={item} className="rounded-md border border-border bg-card px-2 py-1.5">
              {item}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function MitreCard({ mapping }: { mapping: MitreMapping }) {
  return (
    <div className="rounded-lg border border-border bg-background/50 p-4">
      <div className="text-xs uppercase text-muted-foreground">Tactic</div>
      <div className="mt-1 font-mono text-sm font-semibold">
        {textOf(mapping.tactic_id, "No data yet")}
      </div>
      <div className="mt-1 text-sm text-muted-foreground">
        {textOf(mapping.tactic_name, "No data yet")}
      </div>
      <div className="mt-4 text-xs uppercase text-muted-foreground">Technique</div>
      <div className="mt-1 font-mono text-sm font-semibold">
        {textOf(mapping.technique_id, "No data yet")}
      </div>
      <div className="mt-1 text-sm text-muted-foreground">
        {textOf(mapping.technique_name, "No data yet")}
      </div>
    </div>
  );
}

function DetailField({
  label,
  value,
  fallback = "Unknown",
  mono = false,
}: {
  label: string;
  value: string;
  fallback?: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border border-border bg-background/50 p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`mt-1 break-words text-sm ${mono ? "font-mono" : ""}`}>
        {value || fallback}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background/50 p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function PanelList({
  title,
  items,
  mono = false,
}: {
  title: string;
  items: string[];
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <div className={`mt-2 space-y-2 text-xs ${mono ? "font-mono" : ""}`}>
        {items.length === 0 ? (
          <div className="text-muted-foreground">No data yet</div>
        ) : (
          items.map((item) => (
            <div
              key={item}
              className="rounded-md border border-border bg-background/50 px-2 py-1.5 text-muted-foreground"
            >
              {item}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function incidentMitreMappings(item: IncidentRecord): MitreMapping[] {
  const mappings = [...(item.mitre_mappings ?? [])];
  if (
    mappings.length === 0 &&
    (item.mitre_tactic_id ||
      item.mitre_tactic_name ||
      item.mitre_technique_id ||
      item.mitre_technique_name)
  ) {
    mappings.push({
      tactic_id: item.mitre_tactic_id,
      tactic_name: item.mitre_tactic_name,
      technique_id: item.mitre_technique_id,
      technique_name: item.mitre_technique_name,
    });
  }
  return mappings.filter(
    (mapping) =>
      mapping.tactic_id ||
      mapping.tactic_name ||
      mapping.technique_id ||
      mapping.technique_name ||
      mapping.subtechnique_id ||
      mapping.subtechnique_name,
  );
}

function shortIncidentId(incident: IncidentRecord): string {
  const id = incidentRecordId(incident);
  return id ? `INC-${id.slice(-8)}` : shortId(incident, "INC-");
}

function mitreKey(mapping: MitreMapping, index: number): string {
  return [
    mapping.tactic_id,
    mapping.tactic_name,
    mapping.technique_id,
    mapping.technique_name,
    index,
  ]
    .map((value) => textValue(value))
    .join(":");
}

function textValue(value: unknown): string {
  return value === null || value === undefined || value === "" ? "" : String(value);
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
