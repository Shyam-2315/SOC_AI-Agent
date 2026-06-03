import { createFileRoute, Outlet, useMatchRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { SeverityBadge, StatusBadge } from "@/components/soc/SeverityBadge";
import { Btn } from "@/components/soc/Btn";
import { ClientDateTime } from "@/components/soc/ClientOnly";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, incidentRecordId, type IncidentRecord } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend, severityOf, textOf } from "@/lib/presentation";
import { RefreshCw } from "lucide-react";

export const Route = createFileRoute("/_app/incidents")({
  head: () => ({ meta: [{ title: "Incidents — SentinelAI" }] }),
  component: IncidentsPage,
});

const STATUSES = ["new", "investigating", "contained", "resolved", "false_positive"] as const;
type Status = (typeof STATUSES)[number];

function IncidentsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const matchRoute = useMatchRoute();
  const [filter, setFilter] = useState<Status | "all">("all");
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [draft, setDraft] = useState({
    title: "",
    description: "Created from the SOC console.",
    severity: "medium",
    assigned_to_email: "",
  });
  const [incidentActionError, setIncidentActionError] = useState<string | null>(null);
  const incidents = useQuery({
    queryKey: ["incidents"],
    queryFn: () => backend.incidents({ limit: 100 }),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.incidents,
  });
  const updateIncident = useMutation({
    mutationFn: ({ id, status }: { id: string; status: Status }) =>
      backend.updateIncident(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "incidents"] });
    },
  });
  const createIncident = useMutation({
    mutationFn: () =>
      backend.createIncident({
        title: draft.title.trim(),
        description: draft.description.trim(),
        severity: draft.severity,
        assigned_to_email: draft.assigned_to_email.trim() || null,
      }),
    onSuccess: () => {
      setShowCreateForm(false);
      setDraft({
        title: "",
        description: "Created from the SOC console.",
        severity: "medium",
        assigned_to_email: "",
      });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "incidents"] });
    },
  });

  if (matchRoute({ to: "/incidents/$incidentId" })) {
    return <Outlet />;
  }

  if (incidents.isLoading || incidents.isPending)
    return <LoadingState label="Loading incidents…" />;
  if (incidents.error)
    return (
      <ErrorState
        message={
          incidents.error instanceof Error ? incidents.error.message : "Could not load incidents."
        }
      />
    );

  const items = incidents.data?.items ?? [];
  const visible =
    filter === "all" ? items : items.filter((i) => String(i.status ?? "").toLowerCase() === filter);
  const mutationError = updateIncident.error ?? createIncident.error;
  const operationError =
    incidentActionError ??
    (mutationError
      ? mutationError instanceof Error
        ? mutationError.message
        : "Incident operation failed."
      : null);

  function update(incident: IncidentRecord, status: Status) {
    const id = incidentRecordId(incident);
    if (!id) {
      const message =
        "Cannot update incident status because the backend record has no incident ID.";
      setIncidentActionError(message);
      return;
    }
    setIncidentActionError(null);
    updateIncident.mutate({ id, status });
  }

  function investigate(incident: IncidentRecord) {
    const id = incidentRecordId(incident);
    if (!id) {
      const message = "Cannot investigate incident because the backend record has no incident ID.";
      setIncidentActionError(message);
      return;
    }
    setIncidentActionError(null);
    void navigate({
      to: "/incidents/$incidentId",
      params: { incidentId: id },
    });
  }

  return (
    <div className="space-y-6" data-testid="incidents-page">
      <PageHeader
        eyebrow="Operations"
        title="Incidents"
        description="Investigations linking related alerts, owners and response actions."
        actions={
          <>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => incidents.refetch()}
              disabled={incidents.isFetching}
            >
              <RefreshCw className={`h-4 w-4 ${incidents.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Btn>
            <Btn
              variant="hero"
              size="sm"
              onClick={() => setShowCreateForm((value) => !value)}
              data-testid="toggle-incident-form"
            >
              + New incident
            </Btn>
          </>
        }
      />
      {showCreateForm ? (
        <div className="rounded-xl border border-border bg-card p-4 shadow-card">
          <div className="mb-3 text-sm font-semibold">Create incident</div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block md:col-span-2">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Title</span>
              <input
                value={draft.title}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, title: event.target.value }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Incident title"
                placeholder="Credential access investigation"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Severity
              </span>
              <select
                value={draft.severity}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, severity: event.target.value }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Incident severity"
              >
                {["critical", "high", "medium", "low"].map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Assigned analyst email
              </span>
              <input
                value={draft.assigned_to_email}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, assigned_to_email: event.target.value }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Assigned analyst email"
                placeholder="analyst@example.com"
              />
            </label>
            <label className="block md:col-span-2">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Description
              </span>
              <textarea
                value={draft.description}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, description: event.target.value }))
                }
                rows={3}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Incident description"
              />
            </label>
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <Btn variant="ghost" size="sm" onClick={() => setShowCreateForm(false)}>
              Cancel
            </Btn>
            <Btn
              variant="hero"
              size="sm"
              onClick={() => createIncident.mutate()}
              disabled={!draft.title.trim() || !draft.description.trim() || createIncident.isPending}
            >
              Create incident
            </Btn>
          </div>
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {(["all", ...STATUSES] as const).map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded-md border px-3 py-1.5 text-xs capitalize transition ${
              filter === s
                ? "border-primary bg-primary/10 text-primary"
                : "border-border bg-card text-muted-foreground hover:text-foreground"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {operationError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {operationError}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {visible.length === 0 ? (
          <div className="md:col-span-2 xl:col-span-3">
            <EmptyState
              title="No incidents"
              description="Create an incident manually or ingest matching logs to generate alert-driven incidents."
            />
          </div>
        ) : (
          visible.map((incident: IncidentRecord, index) => {
            const id = incidentRecordId(incident);
            return (
              <div
                key={
                  id ||
                  `${incident.title ?? "incident"}-${incident.timestamp ?? "unknown"}-${index}`
                }
                className="flex flex-col rounded-xl border border-border bg-card p-5 shadow-card transition hover:border-primary/40"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-xs font-mono text-muted-foreground">
                      {shortIncidentId(incident)}
                    </div>
                    <div className="mt-1 text-base font-semibold">
                      {textOf(incident.title, "Incident")}
                    </div>
                  </div>
                  <SeverityBadge severity={severityOf(incident.severity)} />
                </div>
                <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-muted-foreground">Status</div>
                    <div className="mt-1">
                      <StatusBadge status={textOf(incident.status, "open")} />
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Analyst</div>
                    <div className="mt-1 font-medium">
                      {textOf(incident.assigned_to, "Unassigned")}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Linked alert</div>
                    <div className="mt-1 font-mono text-primary">
                      {textOf(incident.alert_id, "None")}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Stage</div>
                    <div className="mt-1 font-medium">
                      {textOf(incident.attack_stage, "Triage")}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Updated</div>
                    <div className="mt-1">
                      <ClientDateTime value={incident.updated_at ?? incident.timestamp} />
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border pt-3">
                  <Btn size="sm" variant="outline" onClick={() => investigate(incident)}>
                    Investigate
                  </Btn>
                  <span className="text-xs text-muted-foreground">Set status:</span>
                  {STATUSES.map((s) => (
                    <button
                      key={s}
                      onClick={() => update(incident, s)}
                      className={`rounded-md border px-2 py-1 text-[11px] capitalize transition ${
                        String(incident.status ?? "").toLowerCase() === s
                          ? "border-primary bg-primary/10 text-primary"
                          : "border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function shortIncidentId(incident: IncidentRecord): string {
  const id = incidentRecordId(incident);
  return id ? `INC-${id.slice(-8)}` : "unknown";
}
