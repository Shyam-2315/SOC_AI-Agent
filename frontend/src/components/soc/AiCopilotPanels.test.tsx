import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { backend, setToken } from "@/lib/api";
import { AlertAiPanel, CopilotV2Panel, IncidentAiPanel } from "./AiCopilotPanels";

function renderWithQueryClient(element: ReactElement) {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return render(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
}

describe("AI copilot panels", () => {
  beforeEach(() => {
    localStorage.clear();
    setToken("header.payload.signature");
    vi.restoreAllMocks();
  });

  it("renders alert AI summary panel", async () => {
    vi.spyOn(backend, "aiAlertTriage").mockResolvedValue({
      alert_id: "alert-1",
      risk_score: 88,
      priority: "critical",
      reasoning: ["Severity contributes risk."],
      recommended_action: "block_ip",
      mapped_mitre_techniques: [{ technique_id: "T1110", technique_name: "Brute Force" }],
    });
    vi.spyOn(backend, "aiAlertFalsePositiveScore").mockResolvedValue({
      alert_id: "alert-1",
      false_positive_score: 20,
      confidence: "high",
      reasons: ["MITRE mapping provides context."],
      suggested_status: "investigate",
    });

    renderWithQueryClient(<AlertAiPanel alertId="alert-1" />);

    expect(await screen.findByText("AI alert triage")).toBeInTheDocument();
    expect(screen.getByText("88")).toBeInTheDocument();
    expect(screen.getByText("block ip")).toBeInTheDocument();
    expect(screen.getByText("T1110")).toBeInTheDocument();
  });

  it("renders incident AI summary panel", async () => {
    vi.spyOn(backend, "aiIncidentSummary").mockResolvedValue({
      incident_id: "incident-1",
      title: "Brute force incident",
      executive_summary: "High incident with related alerts.",
      root_cause_guess: "Likely credential access attempt.",
      affected_assets: ["web-01"],
      attack_timeline: [],
      mitre_techniques: [{ technique_id: "T1110" }],
      recommended_actions: ["open_investigation", "run_threat_hunt"],
      analyst_next_steps: ["Review authentication logs."],
    });
    vi.spyOn(backend, "aiIncidentRecommendedActions").mockResolvedValue({
      incident_id: "incident-1",
      recommended_actions: ["open_investigation", "run_threat_hunt"],
      reasons: ["Incident severity requires investigation."],
    });

    renderWithQueryClient(<IncidentAiPanel incidentId="incident-1" />);

    expect(await screen.findByText("AI incident summary")).toBeInTheDocument();
    expect(screen.getByText("High incident with related alerts.")).toBeInTheDocument();
    expect(screen.getByText("run threat hunt")).toBeInTheDocument();
  });

  it("renders Copilot v2 answers for incidents", async () => {
    vi.spyOn(backend, "copilotV2IncidentSummary").mockResolvedValue({
      context_type: "incident",
      context_id: "incident-1",
      title: "Critical brute force incident",
      severity: "critical",
      status: "new",
      risk_score: 95,
      alert_count: 2,
      affected_assets: ["web-01"],
      source_ips: ["203.0.113.10"],
      timeline: ["Repeated failed login"],
      threat_intel: ["203.0.113.10: malicious (95/100)"],
      soar_actions: ["block_ip"],
    });
    vi.spyOn(backend, "copilotV2Ask").mockResolvedValue({
      context: {
        context_type: "incident",
        context_id: "incident-1",
        title: "Critical brute force incident",
        severity: "critical",
        status: "new",
        risk_score: 95,
        alert_count: 2,
        affected_assets: ["web-01"],
        source_ips: ["203.0.113.10"],
        timeline: ["Repeated failed login"],
        threat_intel: ["203.0.113.10: malicious (95/100)"],
        soar_actions: ["block_ip"],
      },
      short_explanation: "The incident is critical due to credential access evidence.",
      evidence_used: ["Related alerts: 2"],
      mitre_techniques: [{ technique_id: "T1110", technique_name: "Brute Force" }],
      risk_reasoning: ["Critical severity indicates potential business impact."],
      suggested_investigation_steps: ["Review authentication logs."],
      suggested_response_actions: [
        {
          action: "block_ip",
          label: "Block source IP",
          rationale: "Threat intel matched the source IP.",
          priority: "critical",
        },
      ],
      confidence_score: 0.82,
    });

    renderWithQueryClient(<CopilotV2Panel incidentId="incident-1" />);

    expect(await screen.findByText("SOC Analyst Copilot v2")).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("button", { name: /ask copilot v2/i }));
    expect(await screen.findByText("The incident is critical due to credential access evidence.")).toBeInTheDocument();
    expect(screen.getByText("Block source IP")).toBeInTheDocument();
  });
});
import "@testing-library/jest-dom/vitest";
