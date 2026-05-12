import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { StatusBadge } from "@/components/soc/SeverityBadge";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type SoarActionRecord } from "@/lib/api";
import { canQueryBackend, timeOf, textOf } from "@/lib/presentation";
import { Ban, Play } from "lucide-react";

export const Route = createFileRoute("/_app/soar")({
  head: () => ({ meta: [{ title: "SOAR — SentinelAI" }] }),
  component: SoarPage,
});

const PLAYBOOK_EVENTS = ["ssh_attack", "malware", "ransomware", "network_activity"];

function actionName(action: SoarActionRecord): string {
  return action.automated_actions?.[0] ?? textOf(action.event_type, "Response action");
}

function SoarPage() {
  const actions = useQuery({
    queryKey: ["soar-actions"],
    queryFn: () => backend.soarActions({ limit: 100 }),
    enabled: canQueryBackend(),
  });
  const blockedIps = useQuery({
    queryKey: ["blocked-ips"],
    queryFn: backend.blockedIps,
    enabled: canQueryBackend(),
  });
  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => Promise.all(PLAYBOOK_EVENTS.map((event) => backend.playbook(event))),
    enabled: canQueryBackend(),
  });

  const queries = [actions, blockedIps, playbooks];
  if (queries.some((q) => q.isLoading || q.isPending))
    return <LoadingState label="Loading SOAR data…" />;
  const error = queries.find((q) => q.error)?.error;
  if (error)
    return (
      <ErrorState message={error instanceof Error ? error.message : "Could not load SOAR data."} />
    );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Response"
        title="SOAR Actions"
        description="Automated and analyst-driven response across the estate."
        actions={
          <Btn variant="hero" size="sm" disabled title="No manual run endpoint is available yet">
            <Play className="h-4 w-4" /> Run playbook
          </Btn>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 overflow-hidden rounded-xl border border-border bg-card shadow-card">
          <div className="border-b border-border px-5 py-3 text-sm font-semibold">
            Recent actions
          </div>
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-background/30 text-left text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-3 font-medium">Action</th>
                  <th className="px-4 py-3 font-medium">Target</th>
                  <th className="px-4 py-3 font-medium">Event</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {(actions.data?.items ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-5">
                      <EmptyState
                        title="No SOAR actions"
                        description="Response actions will appear after matching backend alerts are processed."
                      />
                    </td>
                  </tr>
                ) : (
                  (actions.data?.items ?? []).map((action) => (
                    <tr
                      key={entityId(action)}
                      className="border-t border-border/60 hover:bg-accent/40"
                    >
                      <td className="px-4 py-3 font-medium">{actionName(action)}</td>
                      <td className="px-4 py-3 font-mono text-xs">{textOf(action.ip_address)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-primary">
                        {textOf(action.event_type)}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={textOf(action.status, "simulated")} />
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {timeOf(action.timestamp)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card shadow-card">
          <div className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="text-sm font-semibold">Blocked IPs</div>
            <span className="text-xs text-muted-foreground">
              {blockedIps.data?.blocked_ips.length ?? 0}
            </span>
          </div>
          <ul className="divide-y divide-border">
            {(blockedIps.data?.blocked_ips ?? []).length === 0 ? (
              <li className="p-5">
                <EmptyState
                  title="No blocked IPs"
                  description="Backend response output will be listed here."
                />
              </li>
            ) : (
              (blockedIps.data?.blocked_ips ?? []).map((ip) => (
                <li key={ip} className="flex items-center justify-between px-5 py-3">
                  <div className="flex items-center gap-2">
                    <Ban className="h-4 w-4 text-destructive" />
                    <span className="font-mono text-sm">{ip}</span>
                  </div>
                  <span className="text-xs text-muted-foreground">Backend</span>
                </li>
              ))
            )}
          </ul>
        </div>
      </div>

      <div>
        <div className="mb-3 text-sm font-semibold">Playbooks</div>
        <div className="grid gap-4 md:grid-cols-3">
          {(playbooks.data ?? []).map((playbook) => (
            <div
              key={playbook.event_type}
              className="rounded-xl border border-border bg-card p-5 shadow-card transition hover:border-primary/40"
            >
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold">
                  {playbook.event_type.replaceAll("_", " ")}
                </div>
                <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-muted-foreground">
                  {playbook.playbook.length} steps
                </span>
              </div>
              <div className="mt-1 font-mono text-xs text-muted-foreground">
                {playbook.event_type}
              </div>
              <p className="mt-3 text-sm text-muted-foreground">{playbook.playbook.join(" · ")}</p>
              <div className="mt-4 flex gap-2">
                <Btn
                  size="sm"
                  variant="primary"
                  disabled
                  title="No manual run endpoint is available yet"
                >
                  <Play className="h-3.5 w-3.5" /> Run
                </Btn>
                <Btn size="sm" variant="outline">
                  View
                </Btn>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
