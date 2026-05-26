import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import {
  backend,
  type SecurityBlockedIpRecord,
  type SecurityDetectionRecord,
} from "@/lib/api";
import { canQueryBackend, severityOf, textOf, timeOf } from "@/lib/presentation";
import { ShieldAlert, Ban, ShieldCheck, RefreshCw } from "lucide-react";

export const Route = createFileRoute("/_app/security")({
  head: () => ({ meta: [{ title: "Traffic Security — SentinelAI" }] }),
  component: SecurityPage,
});

function SecurityPage() {
  const queryClient = useQueryClient();
  const summary = useQuery({
    queryKey: ["security", "traffic-summary"],
    queryFn: backend.securityTrafficSummary,
    enabled: canQueryBackend(),
    refetchInterval: 5000,
  });
  const blockedIps = useQuery({
    queryKey: ["security", "blocked-ips"],
    queryFn: backend.securityBlockedIps,
    enabled: canQueryBackend(),
    refetchInterval: 5000,
  });
  const blockIp = useMutation({
    mutationFn: backend.securityBlockIp,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["security"] });
      await queryClient.invalidateQueries({ queryKey: ["soar-actions"] });
    },
  });
  const unblockIp = useMutation({
    mutationFn: backend.securityUnblockIp,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["security"] });
      await queryClient.invalidateQueries({ queryKey: ["soar-actions"] });
    },
  });

  if (summary.isLoading || summary.isPending || blockedIps.isLoading || blockedIps.isPending) {
    return <LoadingState label="Loading traffic security data…" />;
  }
  if (summary.error || blockedIps.error) {
    const error = summary.error ?? blockedIps.error;
    return (
      <ErrorState
        message={error instanceof Error ? error.message : "Traffic security data could not be loaded."}
      />
    );
  }

  const blockError = blockIp.error ?? unblockIp.error;
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Protection"
        title="DoS / DDoS Security"
        description={`Auto-block is ${summary.data?.auto_block_enabled ? "enabled" : "disabled"} for single-IP DoS thresholds.`}
        actions={
          <>
            <Btn
              variant="outline"
              size="sm"
              onClick={() => {
                void summary.refetch();
                void blockedIps.refetch();
              }}
              disabled={summary.isFetching || blockedIps.isFetching}
            >
              <RefreshCw
                className={`h-4 w-4 ${summary.isFetching || blockedIps.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Btn>
            <Btn
              variant="hero"
              size="sm"
              onClick={() => {
                const ip = window.prompt("IP address to block");
                if (!ip?.trim()) return;
                blockIp.mutate({
                  ip: ip.trim(),
                  reason: "Manual analyst block from Traffic Security page",
                  duration_minutes: 15,
                });
              }}
            >
              <Ban className="h-4 w-4" />
              Block IP
            </Btn>
          </>
        }
      />

      {blockError ? (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {blockError instanceof Error ? blockError.message : "Blocklist operation failed."}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Requests / min" value={String(summary.data?.requests_per_minute ?? 0)} />
        <MetricCard
          label="Possible DoS"
          value={String(summary.data?.possible_dos_detections.length ?? 0)}
        />
        <MetricCard
          label="Possible DDoS"
          value={String(summary.data?.possible_ddos_detections.length ?? 0)}
        />
        <MetricCard
          label="Blocked IPs"
          value={String(blockedIps.data?.items.length ?? 0)}
          tone={blockedIps.data?.items.length ? "danger" : "default"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <KeyValueList
          title="Top source IPs"
          empty="No traffic has been recorded yet."
          items={summary.data?.top_source_ips ?? []}
        />
        <KeyValueList
          title="Targeted endpoints"
          empty="No endpoints are being tracked yet."
          items={summary.data?.targeted_endpoints ?? []}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <DetectionList
          title="Possible DoS detections"
          items={summary.data?.possible_dos_detections ?? []}
          onBlock={(ip) =>
            blockIp.mutate({
              ip,
              reason: "Manual block after DoS detection review",
              duration_minutes: 15,
            })
          }
        />
        <DetectionList
          title="Possible DDoS detections"
          items={summary.data?.possible_ddos_detections ?? []}
          onBlock={(ip) =>
            blockIp.mutate({
              ip,
              reason: "Manual block after DDoS detection review",
              duration_minutes: 15,
            })
          }
        />
      </div>

      <BlockedIpsCard
        items={blockedIps.data?.items ?? []}
        onUnblock={(ip) => unblockIp.mutate({ ip })}
      />
    </div>
  );
}

function MetricCard({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string;
  tone?: "default" | "danger";
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5 shadow-card">
      <div className="text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={tone === "danger" ? "mt-2 text-3xl font-semibold text-destructive" : "mt-2 text-3xl font-semibold"}>
        {value}
      </div>
    </div>
  );
}

function KeyValueList({
  title,
  empty,
  items,
}: {
  title: string;
  empty: string;
  items: { value: string; count: number }[];
}) {
  return (
    <div className="rounded-xl border border-border bg-card shadow-card">
      <div className="border-b border-border px-5 py-3 text-sm font-semibold">{title}</div>
      {(items ?? []).length === 0 ? (
        <div className="p-5">
          <EmptyState title="No data" description={empty} />
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li key={item.value} className="flex items-center justify-between px-5 py-3">
              <span className="font-mono text-sm">{item.value}</span>
              <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">
                {item.count}/min
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DetectionList({
  title,
  items,
  onBlock,
}: {
  title: string;
  items: SecurityDetectionRecord[];
  onBlock: (ip: string) => void;
}) {
  return (
    <div className="rounded-xl border border-border bg-card shadow-card">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="text-sm font-semibold">{title}</div>
        <ShieldAlert className="h-4 w-4 text-primary" />
      </div>
      {items.length === 0 ? (
        <div className="p-5">
          <EmptyState
            title="No detections"
            description="When traffic crosses the configured thresholds, detections will appear here."
          />
        </div>
      ) : (
        <div className="divide-y divide-border">
          {items.map((item) => (
            <div key={textOf(item.id, `${item.source_ip}-${item.created_at}`)} className="space-y-3 px-5 py-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium">{textOf(item.title, "Traffic detection")}</div>
                  <div className="mt-1 text-sm text-muted-foreground">
                    {textOf(item.reason)} on <span className="font-mono">{textOf(item.target_path)}</span>
                  </div>
                </div>
                <SeverityBadge severity={severityOf(item.severity)} />
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span className="rounded-full border border-border px-2 py-1 font-mono">
                  IP {textOf(item.source_ip)}
                </span>
                <span className="rounded-full border border-border px-2 py-1">
                  Requests {item.evidence?.request_count ?? 0}
                </span>
                <span className="rounded-full border border-border px-2 py-1">
                  Errors {item.evidence?.error_count ?? 0}
                </span>
                <span className="rounded-full border border-border px-2 py-1">
                  Unique IPs {item.evidence?.unique_ip_count ?? 0}
                </span>
                <span className="rounded-full border border-border px-2 py-1">
                  {timeOf(item.created_at)}
                </span>
              </div>
              <div className="flex gap-2">
                <Btn size="sm" variant="outline" onClick={() => onBlock(textOf(item.source_ip))}>
                  <Ban className="h-3.5 w-3.5" />
                  Block IP
                </Btn>
                <span className="self-center text-xs text-muted-foreground">
                  Auto-block {item.auto_block ? "enabled" : "disabled"}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlockedIpsCard({
  items,
  onUnblock,
}: {
  items: SecurityBlockedIpRecord[];
  onUnblock: (ip: string) => void;
}) {
  return (
    <div className="rounded-xl border border-border bg-card shadow-card">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="text-sm font-semibold">Blocked IPs</div>
        <ShieldCheck className="h-4 w-4 text-primary" />
      </div>
      {items.length === 0 ? (
        <div className="p-5">
          <EmptyState
            title="No blocked IPs"
            description="Internal application-level blocks will be listed here."
          />
        </div>
      ) : (
        <div className="divide-y divide-border">
          {items.map((item) => (
            <div key={item.ip_address} className="flex items-center justify-between gap-3 px-5 py-4">
              <div>
                <div className="font-mono text-sm">{item.ip_address}</div>
                <div className="mt-1 text-xs text-muted-foreground">
                  {textOf(item.reason, "Blocked")} · expires {timeOf(item.expires_at)}
                </div>
              </div>
              <Btn size="sm" variant="outline" onClick={() => onUnblock(item.ip_address)}>
                Unblock
              </Btn>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
