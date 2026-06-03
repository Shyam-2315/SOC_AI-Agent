import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { backend } from "@/lib/api";
import { CopilotPage } from "./CopilotPage";

describe("CopilotPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the copilot page", () => {
    render(<CopilotPage />);

    expect(screen.getByTestId("copilot-page")).toBeInTheDocument();
    expect(screen.getByText("Show failed logins")).toBeInTheDocument();
    expect(screen.getByTestId("copilot-result-card")).toBeInTheDocument();
  });

  it("runs query examples with mocked API results", async () => {
    const user = userEvent.setup();
    vi.spyOn(backend, "aiCopilotQuery").mockResolvedValue({
      intent: "show_failed_logins",
      filters: { event_type: "failed_login" },
      backend_endpoint_suggestion: "/alerts/?event_type=failed_login",
      explanation: "The query asks for alerts with failed-login indicators.",
      result_preview: { count: 2, sample: [] },
    });

    render(<CopilotPage />);

    await user.click(screen.getByText("Show failed logins"));

    await waitFor(() => {
      expect(backend.aiCopilotQuery).toHaveBeenCalledWith("Show failed logins");
    });
    expect(await screen.findByText("show_failed_logins")).toBeInTheDocument();
    expect(screen.getByText("/alerts/?event_type=failed_login")).toBeInTheDocument();
  });

  it("renders threat lookup query results", async () => {
    const user = userEvent.setup();
    vi.spyOn(backend, "aiCopilotQuery").mockResolvedValue({
      intent: "threat_lookup",
      filters: { indicator: "203.0.113.10" },
      backend_endpoint_suggestion: "/api/threat-intel/lookup?indicator=203.0.113.10",
      explanation: "Looking up threat intelligence for 203.0.113.10.",
      result_preview: {
        indicator: "203.0.113.10",
        verdict: "malicious",
        reputation_score: 95,
      },
    });

    render(<CopilotPage />);

    await user.type(screen.getByPlaceholderText("Ask Copilot..."), "is 203.0.113.10 malicious?");
    await user.keyboard("{Enter}");

    expect(await screen.findByText("threat_lookup")).toBeInTheDocument();
    expect(screen.getByText("/api/threat-intel/lookup?indicator=203.0.113.10")).toBeInTheDocument();
    expect(within(screen.getByTestId("copilot-result-card")).getByText(/"verdict": "malicious"/)).toBeInTheDocument();
  });
});
