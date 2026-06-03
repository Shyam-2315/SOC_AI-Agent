import { api, backend, setToken, wsUrl } from "./api";

describe("api client", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("includes the bearer token in requests", async () => {
    setToken("header.payload.signature");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await api("/health");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1/health",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer header.payload.signature",
        }),
      }),
    );
  });

  it("throws structured ApiError responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            message: "Traffic blocked",
          },
        }),
        {
          status: 403,
          headers: { "content-type": "application/json" },
        },
      ),
    );

    await expect(api("/security/blocked-ips")).rejects.toMatchObject({
      message: "Traffic blocked",
      status: 403,
    });
  });

  it("builds websocket URLs with the current token", () => {
    setToken("token-123");

    expect(wsUrl("/ws/alerts")).toContain("token=token-123");
  });

  it("calls AI copilot endpoints", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await backend.aiAlertTriage("alert-1");
    await backend.aiAlertFalsePositiveScore("alert-1");
    await backend.aiIncidentSummary("incident-1");
    await backend.aiIncidentRecommendedActions("incident-1");
    await backend.aiCopilotQuery("show failed logins");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "http://127.0.0.1/api/ai/alerts/alert-1/triage",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1/api/ai/alerts/alert-1/false-positive-score",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "http://127.0.0.1/api/ai/incidents/incident-1/summary",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      4,
      "http://127.0.0.1/api/ai/incidents/incident-1/recommended-actions",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      "http://127.0.0.1/api/ai/copilot/query",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ query: "show failed logins" }),
      }),
    );
  });

  it("calls threat intelligence endpoints", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true, items: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await backend.lookupThreatIntel("203.0.113.10");
    await backend.bulkLookupThreatIntel(["203.0.113.10", "evil.example"]);
    await backend.getThreatIntelFeed();
    await backend.enrichAlertThreatIntel("alert-1");
    await backend.enrichIncidentThreatIntel("incident-1");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "http://127.0.0.1/api/threat-intel/lookup?indicator=203.0.113.10",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "http://127.0.0.1/api/threat-intel/bulk-lookup",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ indicators: ["203.0.113.10", "evil.example"] }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "http://127.0.0.1/api/threat-intel/feed",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      4,
      "http://127.0.0.1/api/threat-intel/enrich-alert/alert-1",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      "http://127.0.0.1/api/threat-intel/enrich-incident/incident-1",
      expect.objectContaining({ method: "POST" }),
    );
  });
});
