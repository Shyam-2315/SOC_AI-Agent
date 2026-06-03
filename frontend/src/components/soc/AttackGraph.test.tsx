import { render, screen } from "@testing-library/react";
import { AttackGraph } from "./AttackGraph";

describe("AttackGraph", () => {
  it("renders graph columns and relationships", () => {
    render(
      <AttackGraph
        graph={{
          incident_id: "incident-1",
          nodes: [
            {
              id: "ip-1",
              type: "source_ip",
              label: "203.0.113.10",
              metadata: {},
            },
            {
              id: "alert-1",
              type: "alert",
              label: "Brute force attempt",
              severity: "high",
              metadata: {},
            },
            {
              id: "incident-1",
              type: "incident",
              label: "Credential access incident",
              severity: "high",
              metadata: {},
            },
          ],
          edges: [
            { source: "ip-1", target: "alert-1", label: "triggered" },
            { source: "alert-1", target: "incident-1", label: "correlated" },
          ],
        }}
      />,
    );

    expect(screen.getByText("Source IPs")).toBeInTheDocument();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getAllByText("Credential access incident").length).toBeGreaterThan(0);
    expect(screen.getByText("triggered")).toBeInTheDocument();
    expect(screen.getByText("correlated")).toBeInTheDocument();
  });
});
