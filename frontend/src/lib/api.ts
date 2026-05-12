// API client for the AI SOC backend.
// Auth token storage intentionally stays in localStorage for compatibility with
// the existing Lovable frontend.

const TOKEN_KEY = "soc_auth_token";
const BASE_URL_KEY = "soc_api_base_url";
const DEFAULT_API_BASE = "http://127.0.0.1";
const API_DEBUG_EVENT = "soc-api-debug-change";
const WS_DEBUG_EVENT = "soc-ws-debug-change";

type ApiRequestInit = RequestInit & {
  collectorToken?: string;
  parseAs?: "json" | "text";
};

export type Paginated<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

export type BackendDocument = {
  _id?: string;
  id?: string;
  [key: string]: unknown;
};

export type LoginResponse = {
  access_token: string;
  token_type: string;
};

export type RegisterPayload = {
  username: string;
  email: string;
  password: string;
  organization_id: string;
};

export type RegisterResponse = {
  message: string;
  user_id: string;
  role?: UserRecord["role"];
};

export type AlertRecord = BackendDocument & {
  source?: string;
  event_type?: string;
  severity?: string;
  message?: string;
  ip_address?: string;
  status?: string;
  threat_score?: number;
  threat_label?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  matched_rule_id?: string | null;
  matched_rule_name?: string | null;
  timestamp?: string;
};

export type IncidentRecord = BackendDocument & {
  alert_id?: string;
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  assigned_to?: string | null;
  created_by?: string;
  timestamp?: string;
  updated_at?: string;
};

export type SoarActionRecord = BackendDocument & {
  alert_id?: string;
  event_type?: string;
  severity?: string;
  ip_address?: string;
  automated_actions?: string[];
  blocked_ips?: string[];
  status?: string;
  timestamp?: string;
};

export type DetectionRuleRecord = BackendDocument & {
  name: string;
  description: string;
  severity: string;
  event_type?: string | null;
  conditions: RuleCondition[];
  mitre_tactic?: string | null;
  mitre_technique?: string | null;
  pack_id?: string | null;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

export type RuleCondition = {
  field: "source" | "event_type" | "severity" | "message" | "ip_address";
  operator: "equals" | "contains";
  value: string;
};

export type DetectionPackRecord = BackendDocument & {
  name: string;
  description?: string;
  category?: string;
  version?: string;
  rules_count?: number;
  enabled?: boolean;
  created_at?: string;
  updated_at?: string;
};

export type StarterPackRecord = {
  key: string;
  name: string;
  description: string;
  category: string;
  version: string;
  rules_count: number;
};

export type CollectorRecord = BackendDocument & {
  name: string;
  type: "linux" | "windows" | "firewall" | "cloud" | "custom";
  status: "active" | "disabled";
  last_seen_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

export type LogRecord = BackendDocument & {
  source?: string;
  event_type?: string;
  severity?: string;
  message?: string;
  ip_address?: string;
  threat_label?: string;
  timestamp?: string;
};

export type UserRecord = BackendDocument & {
  username?: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  disabled?: boolean;
  created_at?: string;
};

export type OrganizationRecord = BackendDocument & {
  name?: string;
  created_at?: string;
  created_by?: string;
};

export type ThreatStatistics = {
  total_alerts: number;
  critical_alerts: number;
  malware_alerts: number;
  ransomware_alerts: number;
};

export type ThreatTimelineRecord = {
  event_type?: string;
  severity?: string;
  source?: string;
  ip_address?: string;
  timestamp?: string;
};

export type CampaignsResponse = {
  detected_campaigns: unknown[];
  limit: number;
  offset: number;
};

export type CollectorIngestResponse = {
  message: string;
  collector_id?: string;
  organization_id: string;
  accepted: number;
  rejected: number;
  results: unknown[];
  errors: unknown[];
};

export type ApiDebugError = {
  path: string;
  status: number;
  message: string;
  at: string;
};

let lastApiError: ApiDebugError | null = null;
let websocketStatus = "not connected";

function dispatchBrowserEvent(name: string) {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(name));
  }
}

function rememberApiError(error: ApiDebugError | null) {
  lastApiError = error;
  dispatchBrowserEvent(API_DEBUG_EVENT);
}

export function getLastApiError(): ApiDebugError | null {
  return lastApiError;
}

export function onApiDebugChange(listener: () => void): () => void {
  if (typeof window === "undefined") return () => undefined;
  window.addEventListener(API_DEBUG_EVENT, listener);
  return () => window.removeEventListener(API_DEBUG_EVENT, listener);
}

export function setWebsocketStatus(status: string) {
  websocketStatus = status;
  dispatchBrowserEvent(WS_DEBUG_EVENT);
}

export function getWebsocketStatus(): string {
  return websocketStatus;
}

export function onWebsocketStatusChange(listener: () => void): () => void {
  if (typeof window === "undefined") return () => undefined;
  window.addEventListener(WS_DEBUG_EVENT, listener);
  return () => window.removeEventListener(WS_DEBUG_EVENT, listener);
}

function envString(key: string): string | undefined {
  const env = import.meta.env as Record<string, string | undefined>;
  const value = env[key]?.trim();
  return value || undefined;
}

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

function normalizePath(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
}

function configuredApiBase(): string | undefined {
  return envString("VITE_API_BASE_URL");
}

function urlOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function httpToWs(url: string): string {
  return url.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
}

function withQuery(path: string, params?: Record<string, string | number | boolean | undefined>) {
  if (!params) return path;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const query = search.toString();
  if (!query) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${query}`;
}

function defaultHeaders(opts: ApiRequestInit): Record<string, string> {
  const headers: Record<string, string> = {
    ...(opts.headers as Record<string, string> | undefined),
  };
  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (opts.collectorToken) headers["X-Collector-Token"] = opts.collectorToken;
  return headers;
}

export function getApiBase(): string {
  const configured = configuredApiBase();
  if (configured) return normalizeBaseUrl(configured);

  if (typeof window === "undefined") {
    return normalizeBaseUrl(DEFAULT_API_BASE);
  }

  const stored = localStorage.getItem(BASE_URL_KEY);
  if (stored) return normalizeBaseUrl(stored);

  return normalizeBaseUrl(DEFAULT_API_BASE);
}

export function setApiBase(url: string) {
  localStorage.setItem(BASE_URL_KEY, normalizeBaseUrl(url));
}

export function getWsBase(): string {
  const configured = envString("VITE_WS_BASE_URL");
  if (configured) return normalizeBaseUrl(httpToWs(configured));

  const apiOrigin = urlOrigin(getApiBase());
  if (apiOrigin) return normalizeBaseUrl(httpToWs(apiOrigin));

  if (typeof window !== "undefined") {
    return normalizeBaseUrl(httpToWs(window.location.origin));
  }

  return normalizeBaseUrl(httpToWs(DEFAULT_API_BASE));
}

export function isDemoMode(): boolean {
  return (envString("VITE_DEMO_MODE") ?? "false").toLowerCase() === "true";
}

export function demoAdminEmail(): string {
  return envString("VITE_DEMO_ADMIN_EMAIL") ?? "demo.admin@aisoc.dev";
}

export function demoAdminPassword(): string {
  return envString("VITE_DEMO_ADMIN_PASSWORD") ?? "DemoAdmin123!";
}

export function demoCollectorToken(): string {
  return envString("VITE_DEMO_COLLECTOR_TOKEN") ?? "demo-collector-token";
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function getTokenClaims(): Record<string, unknown> | null {
  const token = getToken();
  if (!token) return null;
  const [, payload] = token.split(".");
  if (!payload) return null;
  try {
    const normalized = payload.replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

export function entityId(record: BackendDocument): string {
  return String(record.id ?? record._id ?? "");
}

export class ApiError extends Error {
  status: number;
  body?: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

export async function api<T = unknown>(path: string, opts: ApiRequestInit = {}): Promise<T> {
  const base = getApiBase();
  const headers = defaultHeaders(opts);
  const normalizedPath = normalizePath(path);
  let res: Response;
  try {
    res = await fetch(`${base}${normalizedPath}`, { ...opts, headers });
  } catch (error) {
    const message =
      error instanceof Error
        ? `Could not reach API at ${base}: ${error.message}`
        : `Could not reach API at ${base}`;
    rememberApiError({
      path: normalizedPath,
      status: 0,
      message,
      at: new Date().toISOString(),
    });
    throw new ApiError(message, 0, error);
  }
  const text = await res.text();

  if (opts.parseAs === "text") {
    if (!res.ok) {
      const message = text || `Request failed: ${res.status}`;
      rememberApiError({
        path: normalizedPath,
        status: res.status,
        message,
        at: new Date().toISOString(),
      });
      throw new ApiError(message, res.status, text);
    }
    return text as T;
  }

  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (!res.ok) {
    const fields = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const detail = fields.detail ?? fields.message;
    const message = typeof detail === "string" ? detail : `Request failed: ${res.status}`;
    rememberApiError({
      path: normalizedPath,
      status: res.status,
      message,
      at: new Date().toISOString(),
    });
    throw new ApiError(message, res.status, body);
  }

  return body as T;
}

export function wsUrl(path: string) {
  const token = getToken();
  const sep = path.includes("?") ? "&" : "?";
  return `${getWsBase()}${path}${token ? `${sep}token=${encodeURIComponent(token)}` : ""}`;
}

export const backend = {
  login: (email: string, password: string) =>
    api<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (payload: RegisterPayload) =>
    api<RegisterResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  users: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<UserRecord>>(withQuery("/auth/users", params)),
  createUser: (payload: {
    username: string;
    email: string;
    password: string;
    role: UserRecord["role"];
  }) =>
    api<{ message: string; user: UserRecord }>("/auth/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateUser: (id: string, payload: { role?: UserRecord["role"]; disabled?: boolean }) =>
    api<{ message: string }>(`/auth/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  organization: () => api<OrganizationRecord>("/organizations/me"),
  createOrganization: (name: string) =>
    api<{ message: string; organization_id: string }>("/organizations/", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  alerts: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<AlertRecord>>(withQuery("/alerts/", params)),
  incidents: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<IncidentRecord>>(withQuery("/incidents/", params)),
  createIncident: (payload: {
    title: string;
    description: string;
    severity: string;
    assigned_to?: string | null;
  }) =>
    api<{ message: string; incident: IncidentRecord }>("/incidents/", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateIncident: (id: string, status: string) =>
    api<{ message: string }>(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  logs: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<LogRecord>>(withQuery("/logs/", params)),
  soarActions: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<SoarActionRecord>>(withQuery("/soar/actions", params)),
  blockedIps: () => api<{ blocked_ips: string[] }>("/soar/blocked-ips"),
  playbook: (eventType: string) =>
    api<{ event_type: string; playbook: string[] }>(
      `/soar/playbook/${encodeURIComponent(eventType)}`,
    ),
  threatStatistics: () => api<ThreatStatistics>("/threat-hunting/statistics"),
  threatTimeline: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<ThreatTimelineRecord>>(withQuery("/threat-hunting/timeline", params)),
  threatCampaigns: (params?: { limit?: number; offset?: number }) =>
    api<CampaignsResponse>(withQuery("/threat-hunting/campaigns", params)),
  rules: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<DetectionRuleRecord>>(withQuery("/rules", params)),
  createRule: (payload: Omit<DetectionRuleRecord, "id" | "_id" | "created_at" | "updated_at">) =>
    api<{ message: string; rule: DetectionRuleRecord }>("/rules", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateRule: (id: string, payload: Partial<DetectionRuleRecord>) =>
    api<{ message: string; rule: DetectionRuleRecord }>(`/rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteRule: (id: string) =>
    api<{ message: string }>(`/rules/${id}`, {
      method: "DELETE",
    }),
  packs: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<DetectionPackRecord>>(withQuery("/rule-packs", params)),
  createPack: (payload: {
    name: string;
    description: string;
    category: string;
    version: string;
    enabled: boolean;
  }) =>
    api<{ message: string; pack: DetectionPackRecord }>("/rule-packs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updatePack: (id: string, payload: Partial<DetectionPackRecord>) =>
    api<{ message: string; pack: DetectionPackRecord }>(`/rule-packs/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deletePack: (id: string) =>
    api<{ message: string }>(`/rule-packs/${id}`, {
      method: "DELETE",
    }),
  starterPacks: () => api<{ items: StarterPackRecord[] }>("/rule-packs/starter"),
  importPack: (rawBody: string, contentType = "application/json") =>
    api<{ message: string; pack: DetectionPackRecord }>("/rule-packs/import", {
      method: "POST",
      headers: { "Content-Type": contentType },
      body: rawBody,
    }),
  exportPack: (id: string, format: "json" | "yaml" = "json") =>
    api<unknown>(withQuery(`/rule-packs/${id}/export`, { format })),
  collectors: (params?: { limit?: number; offset?: number }) =>
    api<Paginated<CollectorRecord>>(withQuery("/collectors", params)),
  createCollector: (payload: {
    name: string;
    type: CollectorRecord["type"];
    status?: CollectorRecord["status"];
  }) =>
    api<{ message: string; collector: CollectorRecord; api_key: string }>("/collectors", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateCollector: (id: string, payload: Partial<CollectorRecord>) =>
    api<{ message: string; collector: CollectorRecord }>(`/collectors/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteCollector: (id: string) =>
    api<{ message: string }>(`/collectors/${id}`, {
      method: "DELETE",
    }),
  ingestCollectorBatch: (collectorToken: string, logs: LogRecord[]) =>
    api<CollectorIngestResponse>("/collector/ingest", {
      method: "POST",
      collectorToken,
      body: JSON.stringify({ logs }),
    }),
  askCopilot: (query: string) =>
    api<Record<string, unknown>>("/copilot/query", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),
};
