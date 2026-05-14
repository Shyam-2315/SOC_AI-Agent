import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/soc/PageHeader";
import { DataTable, type Column } from "@/components/soc/DataTable";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { Btn } from "@/components/soc/Btn";
import { ClientDateTime, ClientTime } from "@/components/soc/ClientOnly";
import { ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type AlertRecord } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend, downloadJson, severityOf, textOf } from "@/lib/presentation";
import { Download, RefreshCw } from "lucide-react";

export const Route = createFileRoute("/_app/alerts")({
  head: () => ({ meta: [{ title: "Alerts — SentinelAI" }] }),
  component: AlertsPage,
});

type AlertRow = AlertRecord & {
  id: string;
  title: string;
  ip: string;
  rule: string;
};

function toRow(alert: AlertRecord): AlertRow {
  return {
    ...alert,
    id: entityId(alert),
    title: textOf(alert.message, textOf(alert.event_type, "Alert")),
    ip: textOf(alert.ip_address),
    rule: textOf(alert.matched_rule_name, "Classifier"),
  };
}

function AlertsPage() {
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: () => backend.alerts({ limit: 100 }),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.alerts,
  });

  if (alerts.isLoading || alerts.isPending) return <LoadingState label="Loading alerts…" />;
  if (alerts.error)
    return (
      <ErrorState
        message={alerts.error instanceof Error ? alerts.error.message : "Could not load alerts."}
      />
    );

  const rows = (alerts.data?.items ?? []).map(toRow);
  const cols: Column<AlertRow>[] = [
    {
      key: "sev",
      header: "Severity",
      render: (r) => <SeverityBadge severity={severityOf(r.severity)} />,
    },
    {
      key: "title",
      header: "Alert",
      render: (r) => <span className="font-medium">{r.title}</span>,
    },
    {
      key: "mitre",
      header: "MITRE",
      render: (r) => (
        <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
          <span className="rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary">
            {textOf(r.mitre_tactic_id, textOf(r.mitre_tactic_name ?? r.mitre_tactic, "TA"))}
          </span>
          <span className="rounded-md border border-border px-2 py-0.5 text-muted-foreground">
            {textOf(
              r.mitre_technique_id,
              textOf(r.mitre_technique_name ?? r.mitre_technique, "Technique"),
            )}
          </span>
        </div>
      ),
    },
    {
      key: "ip",
      header: "Source IP",
      render: (r) => <span className="font-mono text-xs">{r.ip}</span>,
    },
    {
      key: "src",
      header: "Source",
      render: (r) => <span className="text-muted-foreground">{textOf(r.source)}</span>,
    },
    {
      key: "rule",
      header: "Rule",
      render: (r) => <span className="font-mono text-xs text-primary">{r.rule}</span>,
    },
    {
      key: "ts",
      header: "Timestamp",
      render: (r) => (
        <span className="text-xs text-muted-foreground">
          <ClientDateTime value={r.timestamp} />
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations"
        title="Alerts"
        description={
          <span className="flex flex-col gap-1">
            <span>All detections across collectors and detection rules.</span>
            <span>
              Last updated: <ClientTime value={alerts.dataUpdatedAt} />
            </span>
          </span>
        }
        actions={
          <>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => alerts.refetch()}
              disabled={alerts.isFetching}
            >
              <RefreshCw className={`h-4 w-4 ${alerts.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Btn>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => downloadJson("alerts.json", rows)}
              disabled={rows.length === 0}
            >
              <Download className="h-4 w-4" /> Export
            </Btn>
          </>
        }
      />
      <DataTable
        rows={rows}
        columns={cols}
        searchPlaceholder="Search alerts, IPs, rules…"
        searchKeys={["title", "ip", "source", "rule"]}
        emptyTitle="No alerts"
      />
    </div>
  );
}
