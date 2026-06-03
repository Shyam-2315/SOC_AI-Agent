import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { backend, setToken, type ThreatIntelLookupResponse } from "@/lib/api";
import { ThreatIntelPage } from "@/routes/_app.threat-intel";
import {
  AlertThreatIntelPanel,
  ThreatIntelLookupCard,
  ThreatVerdictBadge,
} from "./ThreatIntel";

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

const maliciousIp: ThreatIntelLookupResponse = {
  indicator: "203.0.113.10",
  normalized_indicator: "203.0.113.10",
  type: "ip",
  reputation_score: 95,
  verdict: "malicious",
  source: "demo_feed",
  tags: ["brute_force", "credential_access"],
  first_seen: "2025-01-01T00:00:00Z",
  last_seen: "2025-01-10T00:00:00Z",
  description: "Known brute-force source.",
  confidence: 0.92,
  explanation: "Matched demo feed indicator 203.0.113.10.",
};

describe("Threat intelligence UI", () => {
  beforeEach(() => {
    localStorage.clear();
    setToken("header.payload.signature");
    vi.restoreAllMocks();
  });

  it("renders verdict badges", () => {
    render(<ThreatVerdictBadge verdict="malicious" />);

    expect(screen.getByTestId("threat-verdict-badge")).toHaveTextContent("malicious");
  });

  it("renders lookup result cards", () => {
    render(<ThreatIntelLookupCard result={maliciousIp} />);

    expect(screen.getByTestId("threat-intel-result-card")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument();
    expect(screen.getByText("95")).toBeInTheDocument();
  });

  it("renders the threat intel page and lookup results", async () => {
    const user = userEvent.setup();
    vi.spyOn(backend, "getThreatIntelFeed").mockResolvedValue({
      items: [
        {
          indicator: "203.0.113.10",
          type: "ip",
          reputation_score: 95,
          verdict: "malicious",
          source: "demo_feed",
          tags: ["brute_force"],
          first_seen: "2025-01-01T00:00:00Z",
          last_seen: "2025-01-10T00:00:00Z",
          description: "Known brute-force source.",
          confidence: 0.92,
        },
      ],
    });
    vi.spyOn(backend, "lookupThreatIntel").mockResolvedValue(maliciousIp);

    renderWithQueryClient(<ThreatIntelPage />);

    expect(screen.getByTestId("threat-intel-page")).toBeInTheDocument();
    expect(await screen.findByText("Internal demo feed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /lookup/i }));

    await waitFor(() => {
      expect(backend.lookupThreatIntel).toHaveBeenCalledWith("203.0.113.10");
    });
    expect(await screen.findByTestId("threat-intel-result-card")).toBeInTheDocument();
    expect(screen.getAllByTestId("threat-verdict-badge")[0]).toHaveTextContent("malicious");
  });

  it("renders alert enrichment panels", async () => {
    vi.spyOn(backend, "enrichAlertThreatIntel").mockResolvedValue({
      matched_iocs: [maliciousIp],
      highest_reputation_score: 95,
      threat_verdict: "malicious",
      recommended_action: "block_ip",
      explanation: ["Matched malicious source IP."],
    });

    renderWithQueryClient(<AlertThreatIntelPanel alertId="alert-1" />);

    expect(await screen.findByTestId("threat-intel-panel")).toBeInTheDocument();
    expect(screen.getByText("block ip")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument();
  });
});
