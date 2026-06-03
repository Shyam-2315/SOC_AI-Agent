import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { backend, setToken } from "@/lib/api";
import { AlertAiPanel, IncidentAiPanel } from "./AiCopilotPanels";

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
});
import "@testing-library/jest-dom/vitest";
