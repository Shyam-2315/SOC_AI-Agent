import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { AlertTriangle, Bot, CheckCircle2, FileText, Send, Shield, Sparkles } from "lucide-react";
import {
  backend,
  type AiAlertTriage,
  type AiFalsePositiveScore,
  type AiIncidentSummary,
  type AiRecommendedActionsResponse,
  type CopilotV2AnswerResponse,
  type CopilotV2ReportResponse,
} from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { Btn } from "./Btn";
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

const INCIDENT_PROMPTS = [
  "Why is this incident critical?",
  "What happened?",
  "Which MITRE techniques are involved?",
  "What should I investigate next?",
  "What SOAR action should I take?",
  "Generate executive summary",
  "Generate technical summary",
];

const ATTACK_CHAIN_PROMPTS = [
  "Why is this attack chain critical?",
  "What happened?",
  "Which MITRE techniques are involved?",
  "What should I investigate next?",
  "What SOAR action should I take?",
];

export function CopilotV2Panel({
  incidentId,
  attackChainId,
}: {
  incidentId?: string;
  attackChainId?: string;
}) {
  const [question, setQuestion] = useState(
    incidentId ? INCIDENT_PROMPTS[0] : ATTACK_CHAIN_PROMPTS[0],
  );
  const [answer, setAnswer] = useState<CopilotV2AnswerResponse | null>(null);
  const [report, setReport] = useState<CopilotV2ReportResponse | null>(null);
  const contextId = incidentId ?? attackChainId ?? "";
  const prompts = incidentId ? INCIDENT_PROMPTS : ATTACK_CHAIN_PROMPTS;
  const summary = useQuery({
    queryKey: ["copilot-v2", "summary", incidentId ? "incident" : "attack-chain", contextId],
    queryFn: () =>
      incidentId
        ? backend.copilotV2IncidentSummary(incidentId)
        : backend.copilotV2AttackChainSummary(attackChainId ?? ""),
    enabled: canQueryBackend() && !!contextId,
  });
  const ask = useMutation({
    mutationFn: (prompt: string) =>
      backend.copilotV2Ask({
        question: prompt,
        incident_id: incidentId,
        attack_chain_id: attackChainId,
      }),
    onSuccess: (payload) => {
      setAnswer(payload);
      setReport(null);
    },
  });
  const executiveReport = useMutation({
    mutationFn: () => backend.copilotV2IncidentExecutiveReport(incidentId ?? ""),
    onSuccess: (payload) => setReport(payload),
  });
  const technicalReport = useMutation({
    mutationFn: () => backend.copilotV2IncidentTechnicalReport(incidentId ?? ""),
    onSuccess: (payload) => setReport(payload),
  });
  const chainActions = useMutation({
    mutationFn: () => backend.copilotV2AttackChainRecommendedActions(attackChainId ?? ""),
    onSuccess: (payload) => {
      setAnswer(payload);
      setReport(null);
    },
  });

  function submit(prompt = question) {
    const trimmed = prompt.trim();
    if (!trimmed || ask.isPending) return;
    setQuestion(trimmed);
    ask.mutate(trimmed);
  }

  const activeAnswer = answer;
  const busy =
    ask.isPending ||
    executiveReport.isPending ||
    technicalReport.isPending ||
    chainActions.isPending;
  const error = ask.error ?? executiveReport.error ?? technicalReport.error ?? chainActions.error;

  return (
    <AiShell title="SOC Analyst Copilot v2" icon={<Sparkles className="h-4 w-4" />}>
      {summary.isLoading ? (
        <LoadingState label="Loading Copilot context..." />
      ) : (
        <div className="space-y-4" data-testid="copilot-v2-panel">
          {summary.data && (
            <div className="grid gap-2 sm:grid-cols-3">
              <AiMetric label="Risk" value={summary.data.risk_score == null ? "n/a" : `${Math.round(summary.data.risk_score)}`} />
              <AiMetric label="Alerts" value={`${summary.data.alert_count}`} />
              <AiMetric label="Confidence" value={activeAnswer ? `${Math.round(activeAnswer.confidence_score * 100)}%` : "pending"} />
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            {prompts.map((prompt) => (
              <button
                key={prompt}
                type="button"
                onClick={() => submit(prompt)}
                disabled={busy}
                className="rounded-md border border-border bg-background/50 px-2.5 py-1.5 text-left text-xs text-muted-foreground transition hover:border-primary/40 hover:text-foreground disabled:opacity-50"
              >
                {prompt}
              </button>
            ))}
          </div>

          <form
            onSubmit={(event) => {
              event.preventDefault();
              submit();
            }}
            className="flex items-center gap-2"
          >
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Ask Copilot v2..."
              className="min-w-0 flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <Btn type="submit" variant="hero" size="sm" disabled={busy} aria-label="Ask Copilot v2">
              <Send className="h-4 w-4" />
            </Btn>
          </form>

          <div className="flex flex-wrap gap-2">
            {incidentId ? (
              <>
                <Btn
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => executiveReport.mutate()}
                  disabled={busy}
                >
                  <FileText className="h-4 w-4" />
                  Executive
                </Btn>
                <Btn
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => technicalReport.mutate()}
                  disabled={busy}
                >
                  <FileText className="h-4 w-4" />
                  Technical
                </Btn>
              </>
            ) : (
              <Btn
                type="button"
                variant="outline"
                size="sm"
                onClick={() => chainActions.mutate()}
                disabled={busy}
              >
                <Shield className="h-4 w-4" />
                Actions
              </Btn>
            )}
          </div>

          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {error instanceof Error ? error.message : "Copilot v2 request failed."}
            </div>
          )}

          {report ? <CopilotReportCard report={report} /> : null}
          {activeAnswer ? <CopilotAnswerCard answer={activeAnswer} /> : null}
        </div>
      )}
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

function CopilotAnswerCard({ answer }: { answer: CopilotV2AnswerResponse }) {
  return (
    <div className="rounded-md border border-border bg-background/50 p-4" data-testid="copilot-v2-answer">
      <div className="text-sm font-semibold">Answer</div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{answer.short_explanation}</p>
      <AiList title="Evidence" items={answer.evidence_used} />
      <AiList title="Risk reasoning" items={answer.risk_reasoning} />
      <AiList title="Investigation steps" items={answer.suggested_investigation_steps} />
      {answer.suggested_response_actions.length > 0 && (
        <div className="mt-3">
          <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Recommended actions
          </div>
          <div className="space-y-2">
            {answer.suggested_response_actions.map((action) => (
              <div key={action.action} className="rounded-md border border-border bg-card px-3 py-2 text-sm">
                <div className="font-medium">{action.label}</div>
                <div className="mt-1 text-xs text-muted-foreground">{action.rationale}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {answer.mitre_techniques.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {answer.mitre_techniques.map((mapping, index) => (
            <span
              key={`${mapping.technique_id ?? mapping.technique_name}-${index}`}
              className="rounded-md border border-border px-2 py-1 font-mono text-xs"
            >
              {textOf(mapping.technique_id, textOf(mapping.technique_name, "MITRE"))}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function CopilotReportCard({ report }: { report: CopilotV2ReportResponse }) {
  return (
    <div className="rounded-md border border-primary/30 bg-primary/5 p-4" data-testid="copilot-v2-report">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-semibold capitalize">{report.report_type} summary</div>
        <div className="text-xs text-muted-foreground">
          {Math.round(report.confidence_score * 100)}% confidence
        </div>
      </div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{report.summary}</p>
      <AiList title="Report evidence" items={report.evidence_used} />
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
