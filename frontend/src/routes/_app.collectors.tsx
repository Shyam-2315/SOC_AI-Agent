import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { StatusBadge } from "@/components/soc/SeverityBadge";
import { ClientDateTime } from "@/components/soc/ClientOnly";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type CollectorRecord } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/live-data";
import { canQueryBackend } from "@/lib/presentation";
import { Copy, Check, Plus, Trash2 } from "lucide-react";

export const Route = createFileRoute("/_app/collectors")({
  head: () => ({ meta: [{ title: "Collectors — SentinelAI" }] }),
  component: CollectorsPage,
});

const COLLECTOR_TYPES: CollectorRecord["type"][] = [
  "linux",
  "windows",
  "syslog",
  "firewall",
  "cloud",
  "custom",
];

function CollectorsPage() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [type, setType] = useState<CollectorRecord["type"]>("linux");
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const collectors = useQuery({
    queryKey: ["collectors"],
    queryFn: () => backend.collectors({ limit: 100 }),
    enabled: canQueryBackend(),
    refetchInterval: POLL_INTERVALS.collectors,
  });
  const createCollector = useMutation({
    mutationFn: () => backend.createCollector({ name: name.trim(), type }),
    onSuccess: (result) => {
      setToken({ name: result.collector.name, token: result.api_key });
      setName("");
      queryClient.invalidateQueries({ queryKey: ["collectors"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "collectors"] });
    },
  });
  const updateCollector = useMutation({
    mutationFn: (collector: CollectorRecord) =>
      backend.updateCollector(entityId(collector), {
        status: collector.status === "active" ? "disabled" : "active",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["collectors"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "collectors"] });
    },
  });
  const deleteCollector = useMutation({
    mutationFn: backend.deleteCollector,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["collectors"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "collectors"] });
    },
  });

  if (collectors.isLoading || collectors.isPending)
    return <LoadingState label="Loading collectors…" />;
  if (collectors.error)
    return (
      <ErrorState
        message={
          collectors.error instanceof Error
            ? collectors.error.message
            : "Could not load collectors."
        }
      />
    );

  function create() {
    if (!name.trim()) return;
    createCollector.mutate();
  }

  function copy() {
    if (!token) return;
    navigator.clipboard.writeText(token.token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const mutationError = createCollector.error ?? updateCollector.error ?? deleteCollector.error;
  const collectorItems = collectors.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Detection"
        title="Collectors"
        description="Telemetry sources feeding the detection engine."
      />

      <div className="rounded-xl border border-border bg-card p-4 shadow-card">
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Collector name (e.g. edge-fw-02)"
            className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value as CollectorRecord["type"])}
            className="rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {COLLECTOR_TYPES.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
          <Btn variant="hero" onClick={create} disabled={!name.trim() || createCollector.isPending}>
            <Plus className="h-4 w-4" /> Create collector
          </Btn>
        </div>
        {token && (
          <div className="mt-3 rounded-md border border-warning/30 bg-warning/10 p-3 text-sm">
            <div className="text-xs font-semibold uppercase tracking-wider text-warning">
              One-time token for "{token.name}"
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              Copy this now. The backend stores only the token hash.
            </div>
            <div className="mt-2 flex items-center gap-2">
              <code className="flex-1 truncate rounded bg-background px-3 py-2 font-mono text-xs">
                {token.token}
              </code>
              <Btn size="sm" variant="outline" onClick={copy}>
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" /> Copy
                  </>
                )}
              </Btn>
            </div>
          </div>
        )}
        {mutationError && (
          <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {mutationError instanceof Error ? mutationError.message : "Collector operation failed."}
          </div>
        )}
      </div>

      <div className="grid gap-3">
        {collectorItems.length === 0 ? (
          <EmptyState
            title="No collectors"
            description="Create a collector to generate a one-time ingestion token for this tenant."
          />
        ) : (
          collectorItems.map((collector) => (
            <div
              key={entityId(collector)}
              className="flex items-center gap-4 rounded-xl border border-border bg-card p-4 shadow-card"
            >
              <div>
                <div className="font-medium">{collector.name}</div>
                <div className="text-xs text-muted-foreground">
                  {collector.type} · last seen <ClientDateTime value={collector.last_seen_at} />
                </div>
              </div>
              <div className="ml-auto flex items-center gap-3">
                <StatusBadge status={collector.status} />
                <button
                  onClick={() => updateCollector.mutate(collector)}
                  className={`relative h-6 w-11 rounded-full border ${collector.status === "active" ? "border-primary bg-primary/30" : "border-border bg-muted"}`}
                >
                  <span
                    className={`absolute top-0.5 h-4 w-4 rounded-full bg-foreground transition ${collector.status === "active" ? "left-6" : "left-0.5"}`}
                  />
                </button>
                <Btn
                  size="sm"
                  variant="ghost"
                  onClick={() => deleteCollector.mutate(entityId(collector))}
                  className="text-destructive hover:bg-destructive/10"
                >
                  <Trash2 className="h-4 w-4" />
                </Btn>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
