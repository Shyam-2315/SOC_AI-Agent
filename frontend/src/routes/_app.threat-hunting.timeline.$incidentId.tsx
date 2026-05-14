import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { backend, type ThreatTimelineRecord } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend, dateTimeOf, severityOf, textOf } from "@/lib/presentation";
import { ArrowLeft, RefreshCw } from "lucide-react";

export const Route = createFileRoute("/_app/threat-hunting/timeline/$incidentId")({
  head: () => ({ meta: [{ title: "Attack Timeline — SentinelAI" }] }),
  component: IncidentTimelinePage,
});

function IncidentTimelinePage() {
  const { incidentId } = Route.useParams();
  const timeline = useQuery({
    queryKey: ["threat-hunting", "timeline", incidentId],
    queryFn: () => backend.incidentTimeline(incidentId),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });

  if (timeline.isLoading || timeline.isPending)
    return <LoadingState label="Loading attack timeline…" />;
  if (timeline.error)
    return (
      <ErrorState
        message={
          timeline.error instanceof Error ? timeline.error.message : "Could not load timeline."
        }
      />
    );

  const events = timeline.data?.events ?? [];
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Threat hunting"
        title="Attack Timeline"
        description={textOf(timeline.data?.summary, "Chronological correlated alert activity.")}
        actions={
          <>
            <Link to="/incidents/$incidentId" params={{ incidentId }}>
              <Btn variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4" /> Investigation
              </Btn>
            </Link>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => timeline.refetch()}
              disabled={timeline.isFetching}
            >
              <RefreshCw className={`h-4 w-4 ${timeline.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Btn>
          </>
        }
      />
      <div className="rounded-xl border border-border bg-card shadow-card">
        {events.length === 0 ? (
          <div className="p-5">
            <EmptyState
              title="No timeline events"
              description="Correlated alerts for this incident will appear here."
            />
          </div>
        ) : (
          <ol className="divide-y divide-border">
            {events.map((event, index) => (
              <TimelineEvent key={`${event.alert_id ?? event.timestamp}-${index}`} event={event} />
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}

function TimelineEvent({ event }: { event: ThreatTimelineRecord }) {
  return (
    <li className="grid gap-3 px-5 py-4 md:grid-cols-[180px_1fr]">
      <div className="text-xs text-muted-foreground">{dateTimeOf(event.timestamp)}</div>
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={severityOf(event.severity)} />
          <span className="text-sm font-semibold">{textOf(event.event_type, "Event")}</span>
          <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
            {textOf(event.attack_stage, "Stage")}
          </span>
        </div>
        <div className="mt-1 text-sm text-muted-foreground">{textOf(event.message)}</div>
        <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[11px]">
          <span className="rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary">
            {textOf(event.mitre?.tactic_id, textOf(event.mitre?.tactic_name, "TA"))}
          </span>
          <span className="rounded border border-border px-2 py-0.5 text-muted-foreground">
            {textOf(event.mitre?.technique_id, textOf(event.mitre?.technique_name, "Technique"))}
          </span>
          <span className="rounded border border-border px-2 py-0.5 text-muted-foreground">
            {textOf(event.host ?? event.source)} · {textOf(event.ip_address)}
          </span>
        </div>
      </div>
    </li>
  );
}
