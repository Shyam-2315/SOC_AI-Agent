import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, demoCollectorToken, entityId, isDemoMode, type LogRecord } from "@/lib/api";
import { canQueryBackend, dateTimeOf, textOf } from "@/lib/presentation";
import { Database, UploadCloud, Check } from "lucide-react";

export const Route = createFileRoute("/_app/ingest")({
  head: () => ({ meta: [{ title: "Log Ingestion — SentinelAI" }] }),
  component: IngestPage,
});

const SOURCES = [
  { name: "Syslog (UDP/514)", desc: "Generic UNIX/network device logs" },
  { name: "AWS CloudTrail", desc: "Multi-account audit events via S3 to SQS" },
  { name: "Microsoft 365", desc: "Audit log via Graph API" },
  { name: "Kubernetes", desc: "Cluster audit and pod logs via Fluent Bit" },
  { name: "Suricata", desc: "EVE JSON via Filebeat" },
];

const DEFAULT_LOG = {
  source: "frontend-test",
  event_type: "ssh_attack",
  severity: "high",
  message: "failed login from frontend ingestion test",
  ip_address: "203.0.113.50",
};

function IngestPage() {
  const [json, setJson] = useState(JSON.stringify(DEFAULT_LOG, null, 2));
  const [collectorToken, setCollectorToken] = useState(isDemoMode() ? demoCollectorToken() : "");
  const [sent, setSent] = useState(false);
  const logs = useQuery({
    queryKey: ["logs"],
    queryFn: () => backend.logs({ limit: 10 }),
    enabled: canQueryBackend(),
  });
  const ingest = useMutation({
    mutationFn: (log: LogRecord) => backend.ingestCollectorBatch(collectorToken, [log]),
    onSuccess: () => {
      setSent(true);
      setTimeout(() => setSent(false), 2000);
      logs.refetch();
    },
  });

  function send() {
    try {
      const parsed = JSON.parse(json);
      ingest.mutate(parsed);
    } catch {
      window.alert("Invalid JSON");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Detection"
        title="Log Ingestion"
        description="Connected sources and ad-hoc collector-token log push for testing detections."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 grid gap-3">
          {SOURCES.map((source) => (
            <div
              key={source.name}
              className="flex items-center gap-4 rounded-xl border border-border bg-card p-4 shadow-card"
            >
              <div className="grid h-10 w-10 place-items-center rounded-lg bg-primary/10 text-primary">
                <Database className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="font-medium">{source.name}</div>
                <div className="text-xs text-muted-foreground">{source.desc}</div>
              </div>
              <span className="rounded-full border border-border bg-background/50 px-2 py-0.5 text-[11px] text-muted-foreground">
                Template
              </span>
            </div>
          ))}

          <div className="overflow-hidden rounded-xl border border-border bg-card shadow-card">
            <div className="border-b border-border px-5 py-3 text-sm font-semibold">
              Recent backend logs
            </div>
            {logs.isLoading ? (
              <div className="p-4">
                <LoadingState label="Loading logs…" />
              </div>
            ) : logs.error ? (
              <div className="p-4">
                <ErrorState
                  message={
                    logs.error instanceof Error ? logs.error.message : "Could not load logs."
                  }
                />
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {(logs.data?.items ?? []).length === 0 ? (
                  <li className="p-5">
                    <EmptyState
                      title="No logs ingested"
                      description="Create a collector, copy its one-time token, then send a test event."
                    />
                  </li>
                ) : (
                  (logs.data?.items ?? []).map((log) => (
                    <li key={entityId(log)} className="px-5 py-3 text-sm">
                      <div className="font-medium">
                        {textOf(log.message, textOf(log.event_type, "Log event"))}
                      </div>
                      <div className="mt-1 font-mono text-xs text-muted-foreground">
                        {textOf(log.source)} · {textOf(log.ip_address)} ·{" "}
                        {dateTimeOf(log.timestamp)}
                      </div>
                    </li>
                  ))
                )}
              </ul>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-4 shadow-card">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <UploadCloud className="h-4 w-4 text-primary" /> Send test event
          </div>
          <label className="mb-2 block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">
              X-Collector-Token
            </span>
            <input
              value={collectorToken}
              onChange={(e) => setCollectorToken(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </label>
          <textarea
            value={json}
            onChange={(e) => setJson(e.target.value)}
            rows={10}
            className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
          {ingest.error && (
            <div className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {ingest.error instanceof Error ? ingest.error.message : "Ingestion failed."}
            </div>
          )}
          <Btn
            variant="hero"
            size="sm"
            className="mt-2 w-full"
            onClick={send}
            disabled={!collectorToken.trim() || ingest.isPending}
          >
            {sent ? (
              <>
                <Check className="h-4 w-4" /> Sent to /collector/ingest
              </>
            ) : (
              <>Send to /collector/ingest</>
            )}
          </Btn>
        </div>
      </div>
    </div>
  );
}
