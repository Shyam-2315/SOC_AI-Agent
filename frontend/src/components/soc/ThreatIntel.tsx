import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import {
  backend,
  type IncidentThreatIntelEnrichmentResponse,
  type ThreatIntelEnrichmentResponse,
  type ThreatIntelLookupResponse,
  type ThreatIntelVerdict,
} from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { EmptyState, LoadingState } from "./States";

const verdictStyles: Record<ThreatIntelVerdict, string> = {
  malicious: "border-destructive/30 bg-destructive/15 text-destructive",
  suspicious: "border-warning/30 bg-warning/15 text-warning",
  clean: "border-success/30 bg-success/15 text-success",
  unknown: "border-border bg-muted text-muted-foreground",
};

export function ThreatVerdictBadge({ verdict }: { verdict: ThreatIntelVerdict }) {
  return (
    <span
      className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-medium capitalize ${verdictStyles[verdict]}`}
      data-testid="threat-verdict-badge"
    >
      {verdict}
    </span>
  );
}

export function ThreatIntelLookupCard({ result }: { result: ThreatIntelLookupResponse }) {
  return (
    <section className="rounded-xl border border-border bg-card p-5 shadow-card" data-testid="threat-intel-result-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-mono text-sm">{result.normalized_indicator}</div>
          <div className="mt-1 text-xs text-muted-foreground">{textOf(result.type, "indicator")}</div>
        </div>
        <ThreatVerdictBadge verdict={result.verdict} />
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <Metric label="Reputation" value={String(result.reputation_score)} />
        <Metric label="Confidence" value={`${Math.round(result.confidence * 100)}%`} />
        <Metric label="Source" value={textOf(result.source, "none")} />
      </div>
      <p className="mt-4 text-sm text-muted-foreground">{result.explanation}</p>
      {result.tags.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {result.tags.map((tag) => (
            <span key={tag} className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground">
              {tag}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

export function AlertThreatIntelPanel({ alertId }: { alertId: string }) {
  const enrichment = useQuery({
    queryKey: ["threat-intel", "alert", alertId],
    queryFn: () => backend.enrichAlertThreatIntel(alertId),
    enabled: canQueryBackend() && !!alertId,
  });

  if (enrichment.isLoading) return <LoadingState label="Loading threat intelligence..." />;
  if (!enrichment.data) return null;
  return <ThreatIntelEnrichmentPanel title="Threat intelligence" enrichment={enrichment.data} />;
}

export function IncidentThreatIntelPanel({ incidentId }: { incidentId: string }) {
  const enrichment = useQuery({
    queryKey: ["threat-intel", "incident", incidentId],
    queryFn: () => backend.enrichIncidentThreatIntel(incidentId),
    enabled: canQueryBackend() && !!incidentId,
  });

  if (enrichment.isLoading) return <LoadingState label="Loading incident threat intelligence..." />;
  if (!enrichment.data) return null;
  return <IncidentThreatIntelContent enrichment={enrichment.data} />;
}

function ThreatIntelEnrichmentPanel({
  title,
  enrichment,
}: {
  title: string;
  enrichment: ThreatIntelEnrichmentResponse;
}) {
  return (
    <section className="rounded-xl border border-border bg-card p-5 shadow-card" data-testid="threat-intel-panel">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold">
        <ShieldAlert className="h-4 w-4 text-primary" />
        {title}
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <Metric label="Highest score" value={String(enrichment.highest_reputation_score)} />
        <div className="rounded-md border border-border bg-background/50 px-3 py-2">
          <div className="text-[11px] uppercase text-muted-foreground">Verdict</div>
          <div className="mt-1">
            <ThreatVerdictBadge verdict={enrichment.threat_verdict} />
          </div>
        </div>
        <Metric label="Action" value={enrichment.recommended_action.replaceAll("_", " ")} />
      </div>
      {enrichment.matched_iocs.length === 0 ? (
        <div className="mt-4">
          <EmptyState title="No matched IOCs" description="No known indicators were found in this alert." />
        </div>
      ) : (
        <MatchedIocs items={enrichment.matched_iocs} />
      )}
    </section>
  );
}

function IncidentThreatIntelContent({
  enrichment,
}: {
  enrichment: IncidentThreatIntelEnrichmentResponse;
}) {
  const alertShape: ThreatIntelEnrichmentResponse = {
    matched_iocs: enrichment.matched_indicators,
    highest_reputation_score: enrichment.highest_risk,
    threat_verdict:
      enrichment.highest_risk >= 80
        ? "malicious"
        : enrichment.highest_risk >= 50
          ? "suspicious"
          : enrichment.highest_risk > 0
            ? "clean"
            : "unknown",
    recommended_action: enrichment.recommended_actions.join(", "),
    explanation: [],
  };
  return <ThreatIntelEnrichmentPanel title="Incident threat intelligence" enrichment={alertShape} />;
}

function MatchedIocs({ items }: { items: ThreatIntelLookupResponse[] }) {
  return (
    <div className="mt-4 space-y-2">
      {items.map((item) => (
        <div key={`${item.type}-${item.normalized_indicator}`} className="rounded-md border border-border bg-background/40 p-3">
          <div className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs">{item.normalized_indicator}</span>
            <ThreatVerdictBadge verdict={item.verdict} />
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            Score {item.reputation_score} · {item.tags.join(", ") || "no tags"}
          </div>
        </div>
      ))}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-background/50 px-3 py-2">
      <div className="text-[11px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-semibold capitalize">{value}</div>
    </div>
  );
}
