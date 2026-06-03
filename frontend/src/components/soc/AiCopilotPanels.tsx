import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { AlertTriangle, Bot, CheckCircle2, Shield } from "lucide-react";
import {
  backend,
  type AiAlertTriage,
  type AiFalsePositiveScore,
  type AiIncidentSummary,
  type AiRecommendedActionsResponse,
} from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { LoadingState } from "./States";

export function AlertAiPanel({ alertId }: { alertId: string }) {
  const triage = useQuery({
    queryKey: ["ai", "alert", alertId, "triage"],
    queryFn: () => backend.aiAlertTriage(alertId),
    enabled: canQueryBackend() && !!alertId,
  });
  const falsePositive = useQuery({
    queryKey: ["ai", "alert", alertId, "false-positive"],
    queryFn: () => backend.aiAlertFalsePositiveScore(alertId),
    enabled: canQueryBackend() && !!alertId,
  });

  if (triage.isLoading || falsePositive.isLoading) {
    return <LoadingState label="Loading AI triage..." />;
  }

  if (triage.error || falsePositive.error) {
    return (
      <AiShell title="AI alert triage" icon={<Bot className="h-4 w-4" />}>
        <p className="text-sm text-muted-foreground">AI triage is unavailable for this alert.</p>
      </AiShell>
    );
  }

  return (
    <AiShell title="AI alert triage" icon={<Bot className="h-4 w-4" />}>
      {triage.data ? <AlertTriageContent triage={triage.data} /> : null}
      {falsePositive.data ? <FalsePositiveContent score={falsePositive.data} /> : null}
    </AiShell>
  );
}

export function IncidentAiPanel({ incidentId }: { incidentId: string }) {
  const summary = useQuery({
    queryKey: ["ai", "incident", incidentId, "summary"],
    queryFn: () => backend.aiIncidentSummary(incidentId),
    enabled: canQueryBackend() && !!incidentId,
  });
  const actions = useQuery({
    queryKey: ["ai", "incident", incidentId, "recommended-actions"],
    queryFn: () => backend.aiIncidentRecommendedActions(incidentId),
    enabled: canQueryBackend() && !!incidentId,
  });

  if (summary.isLoading || actions.isLoading) {
    return <LoadingState label="Loading AI incident summary..." />;
  }

  if (summary.error || actions.error) {
    return (
      <AiShell title="AI incident summary" icon={<Shield className="h-4 w-4" />}>
        <p className="text-sm text-muted-foreground">AI incident summary is unavailable.</p>
      </AiShell>
    );
  }

  return (
    <AiShell title="AI incident summary" icon={<Shield className="h-4 w-4" />}>
      {summary.data ? <IncidentSummaryContent summary={summary.data} /> : null}
      {actions.data ? <RecommendedActionsContent actions={actions.data} /> : null}
    </AiShell>
  );
}

function AlertTriageContent({ triage }: { triage: AiAlertTriage }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-3">
        <AiMetric label="Risk" value={`${triage.risk_score}`} />
        <AiMetric label="Priority" value={triage.priority} />
        <AiMetric label="Action" value={triage.recommended_action.replaceAll("_", " ")} />
      </div>
      <AiList title="Reasoning" items={triage.reasoning} />
      {triage.mapped_mitre_techniques.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {triage.mapped_mitre_techniques.map((mapping, index) => (
            <span key={`${mapping.technique_id}-${index}`} className="rounded-md border border-border px-2 py-1 font-mono text-xs">
              {textOf(mapping.technique_id, textOf(mapping.technique_name, "MITRE"))}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function FalsePositiveContent({ score }: { score: AiFalsePositiveScore }) {
  return (
    <div className="mt-4 border-t border-border pt-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <AiMetric label="FP score" value={`${score.false_positive_score}`} />
        <AiMetric label="Confidence" value={score.confidence} />
        <AiMetric label="Status" value={score.suggested_status.replaceAll("_", " ")} />
      </div>
      <AiList title="False-positive factors" items={score.reasons} />
    </div>
  );
}

function IncidentSummaryContent({ summary }: { summary: AiIncidentSummary }) {
  return (
    <div className="space-y-3">
      <p className="text-sm leading-6 text-muted-foreground">{summary.executive_summary}</p>
      <div className="rounded-md border border-border bg-background/50 p-3 text-sm">
        <div className="text-xs uppercase text-muted-foreground">Root cause guess</div>
        <div className="mt-1">{summary.root_cause_guess}</div>
      </div>
      <AiList title="Analyst next steps" items={summary.analyst_next_steps} />
    </div>
  );
}

function RecommendedActionsContent({ actions }: { actions: AiRecommendedActionsResponse }) {
  return (
    <div className="mt-4 border-t border-border pt-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
        <CheckCircle2 className="h-4 w-4 text-primary" />
        Recommended actions
      </div>
      <div className="flex flex-wrap gap-2">
        {actions.recommended_actions.map((action) => (
          <span key={action} className="rounded-md border border-primary/30 bg-primary/10 px-2 py-1 text-xs text-primary">
            {action.replaceAll("_", " ")}
          </span>
        ))}
      </div>
      <AiList title="Why" items={actions.reasons} />
    </div>
  );
}

function AiShell({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-card p-5 shadow-card" data-testid="ai-summary-panel">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold">
        {icon}
        {title}
      </div>
      {children}
    </section>
  );
}

function AiMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-background/50 px-3 py-2">
      <div className="text-[11px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-semibold capitalize">{value}</div>
    </div>
  );
}

function AiList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="mt-3">
      <div className="mb-1 flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground">
        <AlertTriangle className="h-3.5 w-3.5" />
        {title}
      </div>
      <ul className="space-y-1 text-sm text-muted-foreground">
        {items.map((item, index) => (
          <li key={`${item}-${index}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
