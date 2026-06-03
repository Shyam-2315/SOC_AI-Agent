import type { Page, Route } from "@playwright/test";

type JsonValue = Record<string, unknown> | Array<unknown> | string | number | boolean | null;

type MockState = {
  token: string;
  organization: Record<string, unknown>;
  alerts: Array<Record<string, unknown>>;
  incidents: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  collectors: Array<Record<string, unknown>>;
  rules: Array<Record<string, unknown>>;
  packs: Array<Record<string, unknown>>;
  starterPacks: Array<Record<string, unknown>>;
  users: Array<Record<string, unknown>>;
  logs: Array<Record<string, unknown>>;
  threatTimeline: Array<Record<string, unknown>>;
  campaigns: Array<Record<string, unknown>>;
  securityBlockedIps: Array<Record<string, unknown>>;
};

const now = "2026-05-27T12:00:00.000Z";

function createToken(email: string) {
  const encode = (value: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "HS256", typ: "JWT" })}.${encode({
    email,
    role: "admin",
    organization_id: "org-1",
  })}.signature`;
}

function response(route: Route, body: JsonValue, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
    },
  });
}

function paginated(items: Array<Record<string, unknown>>, url: URL) {
  const limit = Number(url.searchParams.get("limit") ?? (items.length || 100));
  const offset = Number(url.searchParams.get("offset") ?? 0);
  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    limit,
    offset,
  };
}

function createMockState(): MockState {
  const token = createToken("demo.admin@aisoc.dev");
  const alert = {
    id: "alert-1",
    title: "SSH brute force detected",
    message: "Repeated failed login from 203.0.113.10",
    event_type: "ssh_attack",
    severity: "high",
    ip_address: "203.0.113.10",
    source: "linux-1",
    hostname: "linux-1",
    matched_rule_name: "SSH brute force rule",
    mitre_tactic: "Credential Access",
    mitre_tactic_id: "TA0006",
    mitre_technique: "Brute Force",
    mitre_technique_id: "T1110",
    timestamp: now,
  };
  const action = {
    id: "action-1",
    incident_id: "incident-1",
    alert_id: "alert-1",
    event_type: "ssh_attack",
    severity: "high",
    ip_address: "203.0.113.10",
    automated_actions: ["Blocked malicious IP: 203.0.113.10"],
    blocked_ips: ["203.0.113.10"],
    status: "simulated",
    timestamp: now,
  };
  const timelineEvent = {
    alert_id: "alert-1",
    event_type: "ssh_attack",
    message: "Repeated failed login from 203.0.113.10",
    severity: "high",
    source: "linux-1",
    host: "linux-1",
    ip_address: "203.0.113.10",
    attack_stage: "Credential Access",
    mitre: {
      tactic_id: "TA0006",
      tactic_name: "Credential Access",
      technique_id: "T1110",
      technique_name: "Brute Force",
    },
    timestamp: now,
  };
  const incident = {
    id: "incident-1",
    incident_id: "incident-1",
    alert_id: "alert-1",
    title: "Credential access incident",
    description: "Correlated failed login activity",
    severity: "high",
    status: "investigating",
    assigned_to: "Analyst One",
    assigned_to_email: "analyst@example.com",
    investigation_summary: "Multiple failed logins correlated into a single incident.",
    investigation_notes: "Review source IP reputation.",
    attack_stage: "Credential Access",
    correlation_id: "corr-1",
    correlation_score: 73,
    related_alert_ids: ["alert-1"],
    related_alerts: [alert],
    related_hosts: ["linux-1"],
    related_ips: ["203.0.113.10"],
    mitre_tactic_id: "TA0006",
    mitre_tactic_name: "Credential Access",
    mitre_technique_id: "T1110",
    mitre_technique_name: "Brute Force",
    timeline_events: [timelineEvent],
    soar_actions: [action],
    timestamp: now,
    updated_at: now,
  };

  return {
    token,
    organization: {
      id: "org-1",
      name: "Demo SOC",
      created_at: now,
      created_by: "demo.admin@aisoc.dev",
    },
    alerts: [alert],
    incidents: [incident],
    actions: [action],
    collectors: [
      {
        id: "collector-1",
        name: "Linux collector",
        type: "linux",
        status: "active",
        last_seen_at: now,
        created_at: now,
      },
    ],
    rules: [
      {
        id: "rule-1",
        name: "SSH brute force rule",
        description: "Detect repeated failed logins",
        severity: "high",
        event_type: "ssh_attack",
        conditions: [{ field: "message", operator: "contains", value: "failed login" }],
        mitre_tactic_id: "TA0006",
        mitre_tactic_name: "Credential Access",
        mitre_technique_id: "T1110",
        mitre_technique_name: "Brute Force",
        enabled: true,
      },
    ],
    packs: [
      {
        id: "pack-1",
        name: "Authentication Starter",
        description: "Starter detections for auth signals",
        category: "authentication",
        version: "1.0.0",
        rules_count: 3,
        enabled: true,
      },
    ],
    starterPacks: [
      {
        key: "ssh_brute_force",
        name: "SSH Brute Force",
        description: "Starter SSH detections",
        category: "authentication",
        version: "1.0.0",
        rules_count: 1,
      },
    ],
    users: [
      {
        id: "user-1",
        username: "Demo Admin",
        email: "demo.admin@aisoc.dev",
        role: "admin",
        disabled: false,
      },
    ],
    logs: [
      {
        id: "log-1",
        source: "linux-1",
        event_type: "ssh_attack",
        severity: "high",
        message: "Repeated failed login from 203.0.113.10",
        ip_address: "203.0.113.10",
        timestamp: now,
      },
    ],
    threatTimeline: [timelineEvent],
    campaigns: [
      {
        id: "campaign-1",
        name: "Credential access cluster",
        attack_stage: "Credential Access",
      },
    ],
    securityBlockedIps: [
      {
        ip_address: "203.0.113.10",
        reason: "Automatic block",
        blocked_by: "system",
        blocked_at: now,
        expires_at: "2026-05-27T12:15:00.000Z",
        duration_minutes: 15,
      },
    ],
  };
}

function attackGraph() {
  return {
    incident_id: "incident-1",
    nodes: [
      { id: "ip-1", type: "source_ip", label: "203.0.113.10", metadata: {} },
      { id: "host-1", type: "host", label: "linux-1", metadata: {} },
      { id: "alert-1", type: "alert", label: "SSH brute force detected", severity: "high", metadata: {} },
      { id: "incident-1", type: "incident", label: "Credential access incident", severity: "high", metadata: {} },
      { id: "mitre-1", type: "mitre_technique", label: "T1110 Brute Force", metadata: {} },
    ],
    edges: [
      { source: "ip-1", target: "host-1", label: "targeted" },
      { source: "host-1", target: "alert-1", label: "triggered" },
      { source: "alert-1", target: "incident-1", label: "correlated" },
      { source: "alert-1", target: "mitre-1", label: "mapped" },
    ],
  };
}

function threatStatistics(state: MockState) {
  return {
    total_alerts: state.alerts.length,
    critical_alerts: 0,
    malware_alerts: 0,
    ransomware_alerts: 0,
    recent_attack_chains: [
      {
        correlation_id: "corr-1",
        incident_id: "incident-1",
        correlation_score: 73,
        attack_stage: "Credential Access",
      },
    ],
  };
}

function securitySummary(state: MockState) {
  return {
    requests_per_minute: 42,
    top_source_ips: [{ value: "203.0.113.10", count: 12 }],
    targeted_endpoints: [{ value: "/login", count: 8 }],
    possible_dos_detections: [
      {
        id: "dos-1",
        detection_type: "dos",
        event_type: "dos_attack",
        title: "Possible DoS Activity",
        severity: "high",
        source_ip: "203.0.113.10",
        target_path: "/login",
        reason: "Request threshold exceeded",
        evidence: { request_count: 12, error_count: 4, unique_ip_count: 1 },
        auto_block: false,
        created_at: now,
      },
    ],
    possible_ddos_detections: [],
    recent_detections: [],
    auto_block_enabled: false,
    thresholds: {
      dos_ip_requests_per_minute: 10,
      dos_ip_errors_per_minute: 5,
      ddos_endpoint_requests_per_minute: 20,
      ddos_endpoint_unique_ips_per_minute: 5,
    },
  };
}

export async function registerSocMocks(page: Page) {
  const state = createMockState();

  await page.addInitScript(() => {
    class MockWebSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSING = 2;
      static CLOSED = 3;
      readyState = MockWebSocket.CONNECTING;
      url: string;
      onopen: ((event: Event) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      onclose: ((event: { code: number }) => void) | null = null;

      constructor(url: string) {
        this.url = url;
        setTimeout(() => {
          this.readyState = MockWebSocket.OPEN;
          this.onopen?.(new Event("open"));
        }, 0);
      }

      send() {
        return undefined;
      }

      close() {
        this.readyState = MockWebSocket.CLOSED;
        this.onclose?.({ code: 1000 });
      }

      addEventListener() {
        return undefined;
      }

      removeEventListener() {
        return undefined;
      }
    }

    Object.defineProperty(window, "WebSocket", {
      writable: true,
      value: MockWebSocket,
    });
  });

  await page.route("http://127.0.0.1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();

    if (method === "OPTIONS") {
      return response(route, { ok: true });
    }

    if (method === "POST" && path === "/auth/login") {
      return response(route, {
        access_token: state.token,
        token_type: "bearer",
      });
    }

    if (method === "GET" && path === "/organizations/me") {
      return response(route, state.organization);
    }

    if (method === "GET" && path === "/alerts/") {
      return response(route, paginated(state.alerts, url));
    }

    if (method === "GET" && path === "/incidents/") {
      return response(route, paginated(state.incidents, url));
    }

    if (method === "POST" && path === "/incidents/") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const incident = {
        id: `incident-${state.incidents.length + 1}`,
        incident_id: `incident-${state.incidents.length + 1}`,
        status: "new",
        timestamp: now,
        updated_at: now,
        ...payload,
      };
      state.incidents.unshift(incident);
      return response(route, { message: "Incident created", incident }, 201);
    }

    if (method === "GET" && path === "/incidents/incident-1") {
      return response(route, state.incidents[0]);
    }

    if (method === "PATCH" && path.startsWith("/incidents/")) {
      const incident = state.incidents.find((item) => item.id === path.split("/").at(-1));
      if (!incident) return response(route, { detail: "Incident not found" }, 404);
      Object.assign(incident, JSON.parse(request.postData() ?? "{}"), { updated_at: now });
      return response(route, { message: "Incident updated" });
    }

    if (method === "GET" && path === "/incidents/incident-1/attack-graph") {
      return response(route, attackGraph());
    }

    if (method === "GET" && path === "/threat-hunting/statistics") {
      return response(route, threatStatistics(state));
    }

    if (method === "GET" && path === "/threat-hunting/campaigns") {
      return response(route, {
        detected_campaigns: state.campaigns,
        limit: Number(url.searchParams.get("limit") ?? 100),
        offset: Number(url.searchParams.get("offset") ?? 0),
      });
    }

    if (method === "GET" && path === "/threat-hunting/timeline") {
      return response(route, paginated(state.threatTimeline, url));
    }

    if (method === "GET" && path === "/threat-hunting/timeline/incident-1") {
      return response(route, {
        incident_id: "incident-1",
        summary: "Multiple failed logins were correlated into one incident.",
        correlation: {
          correlation_id: "corr-1",
          incident_id: "incident-1",
          correlation_score: 73,
          attack_stage: "Credential Access",
          related_alert_ids: ["alert-1"],
        },
        correlated_hosts: ["linux-1"],
        correlated_ips: ["203.0.113.10"],
        events: state.threatTimeline,
      });
    }

    if (method === "GET" && path === "/soar/actions") {
      const incidentId = url.searchParams.get("incident_id");
      const items = incidentId
        ? state.actions.filter((action) => action.incident_id === incidentId)
        : state.actions;
      return response(route, paginated(items, url));
    }

    if (method === "GET" && path === "/soar/blocked-ips") {
      return response(route, {
        blocked_ips: state.securityBlockedIps.map((item) => item.ip_address),
      });
    }

    if (method === "GET" && path.startsWith("/soar/playbook/")) {
      const eventType = path.split("/").at(-1) ?? "unknown";
      return response(route, {
        event_type: eventType,
        playbook: ["Investigate source", "Contain affected asset", "Notify analyst"],
      });
    }

    if (method === "GET" && path === "/collectors") {
      return response(route, paginated(state.collectors, url));
    }

    if (method === "POST" && path === "/collectors") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const collector = {
        id: `collector-${state.collectors.length + 1}`,
        status: "active",
        created_at: now,
        updated_at: now,
        ...payload,
      };
      state.collectors.unshift(collector);
      return response(route, {
        message: "Collector created",
        collector,
        api_key: "collector-test-token",
      }, 201);
    }

    if (method === "PATCH" && path.startsWith("/collectors/")) {
      const collector = state.collectors.find((item) => item.id === path.split("/").at(-1));
      if (!collector) return response(route, { detail: "Collector not found" }, 404);
      Object.assign(collector, JSON.parse(request.postData() ?? "{}"));
      return response(route, { message: "Collector updated", collector });
    }

    if (method === "DELETE" && path.startsWith("/collectors/")) {
      return response(route, { message: "Collector deleted" });
    }

    if (method === "GET" && path === "/rules") {
      return response(route, paginated(state.rules, url));
    }

    if (method === "POST" && path === "/rules") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const rule = {
        id: `rule-${state.rules.length + 1}`,
        created_at: now,
        updated_at: now,
        ...payload,
      };
      state.rules.unshift(rule);
      return response(route, { message: "Rule created", rule }, 201);
    }

    if (method === "PATCH" && path.startsWith("/rules/")) {
      const rule = state.rules.find((item) => item.id === path.split("/").at(-1));
      if (!rule) return response(route, { detail: "Rule not found" }, 404);
      Object.assign(rule, JSON.parse(request.postData() ?? "{}"), { updated_at: now });
      return response(route, { message: "Rule updated", rule });
    }

    if (method === "DELETE" && path.startsWith("/rules/")) {
      return response(route, { message: "Rule deleted" });
    }

    if (method === "GET" && path === "/rule-packs") {
      return response(route, paginated(state.packs, url));
    }

    if (method === "POST" && path === "/rule-packs") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const pack = {
        id: `pack-${state.packs.length + 1}`,
        rules_count: 0,
        created_at: now,
        updated_at: now,
        ...payload,
      };
      state.packs.unshift(pack);
      return response(route, { message: "Pack created", pack }, 201);
    }

    if (method === "PATCH" && path.startsWith("/rule-packs/")) {
      const pack = state.packs.find((item) => item.id === path.split("/").at(-1));
      if (!pack) return response(route, { detail: "Pack not found" }, 404);
      Object.assign(pack, JSON.parse(request.postData() ?? "{}"), { updated_at: now });
      return response(route, { message: "Pack updated", pack });
    }

    if (method === "DELETE" && path.startsWith("/rule-packs/")) {
      return response(route, { message: "Pack deleted" });
    }

    if (method === "GET" && path === "/rule-packs/starter") {
      return response(route, { items: state.starterPacks });
    }

    if (method === "POST" && path === "/rule-packs/import") {
      return response(route, { message: "Pack imported", pack: state.packs[0] }, 201);
    }

    if (method === "GET" && path.endsWith("/export")) {
      return response(route, {
        pack: state.packs[0],
        rules: state.rules,
      });
    }

    if (method === "GET" && path === "/security/traffic/summary") {
      return response(route, securitySummary(state));
    }

    if (method === "GET" && path === "/security/blocked-ips") {
      return response(route, { items: state.securityBlockedIps });
    }

    if (method === "POST" && path === "/security/block-ip") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const block = {
        ip_address: payload.ip,
        reason: payload.reason,
        blocked_by: "demo.admin@aisoc.dev",
        blocked_at: now,
        expires_at: "2026-05-27T12:15:00.000Z",
        duration_minutes: payload.duration_minutes ?? 15,
      };
      state.securityBlockedIps.unshift(block);
      return response(route, { message: "IP blocked", item: block });
    }

    if (method === "POST" && path === "/security/unblock-ip") {
      return response(route, { message: "IP unblocked", item: { ip_address: "203.0.113.10", active: false } });
    }

    if (method === "GET" && path === "/auth/users") {
      return response(route, paginated(state.users, url));
    }

    if (method === "POST" && path === "/auth/users") {
      const payload = JSON.parse(request.postData() ?? "{}");
      const user = { id: `user-${state.users.length + 1}`, disabled: false, ...payload };
      state.users.unshift(user);
      return response(route, { message: "User created", user }, 201);
    }

    if (method === "PATCH" && path.startsWith("/auth/users/")) {
      return response(route, { message: "User updated" });
    }

    if (method === "GET" && path === "/logs/") {
      return response(route, paginated(state.logs, url));
    }

    if (method === "POST" && path === "/copilot/query") {
      return response(route, {
        message: "Critical alerts: 0\nOpen incidents: 1\nTop dangerous IPs: [\"203.0.113.10\"]",
      });
    }

    if (method === "POST" && path === "/collector/ingest") {
      return response(route, {
        message: "Batch processed",
        organization_id: "org-1",
        accepted: 1,
        rejected: 0,
        results: [],
        errors: [],
      });
    }

    if (method === "POST" && path === "/organizations/") {
      return response(route, { message: "Organization created", organization_id: "org-2" }, 201);
    }

    return response(route, { detail: `Unhandled mock route for ${method} ${path}` }, 404);
  });

  return state;
}
