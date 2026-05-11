export const API_BASE_URL =
  (typeof localStorage !== "undefined" && localStorage.getItem("api_base_url")) ||
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000";

export const WS_BASE_URL =
  (typeof localStorage !== "undefined" && localStorage.getItem("ws_url")) ||
  import.meta.env.VITE_WS_BASE_URL ||
  "ws://127.0.0.1:8000";

export const WS_ALERTS_URL = WS_BASE_URL.endsWith("/ws/alerts")
  ? WS_BASE_URL
  : `${WS_BASE_URL.replace(/\/$/, "")}/ws/alerts`;

export function getApiBaseUrl(): string {
  if (typeof localStorage !== "undefined") {
    return localStorage.getItem("api_base_url") || API_BASE_URL;
  }
  return API_BASE_URL;
}

export const ENDPOINTS = {
  root: "/",
  health: "/health",
  login: "/auth/login",
  register: "/auth/register",
  ingest: "/ingest/",
  ingestAsync: "/ingest/async",
  ingestTask: (id: string) => `/ingest/tasks/${id}`,
  logs: "/logs/",
  alerts: "/alerts/",
  incidents: "/incidents/",
  createIncident: "/incidents/",
  updateIncident: (id: string | number) => `/incidents/${id}`,
  soarActions: "/soar/actions",
  soarBlockedIps: "/soar/blocked-ips",
  soarPlaybook: (eventType: string) => `/soar/playbook/${encodeURIComponent(eventType)}`,
  huntingCampaigns: "/threat-hunting/campaigns",
  huntingTimeline: "/threat-hunting/timeline",
  huntingStats: "/threat-hunting/statistics",
  copilot: "/copilot/query",
  users: "/auth/users",
  createUser: "/auth/users",
  updateUser: (id: string | number) => `/auth/users/${id}`,
  organization: "/organizations/me",
  createOrganization: "/organizations/",
};

export const TOKEN_KEY = "soc_access_token";
export const USER_KEY = "soc_user";
export const COLLECTOR_TOKEN_KEY = "soc_collector_token";

export function getToken(): string | null {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof localStorage === "undefined") return;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function decodeJwtPayload<T = any>(token: string): T | null {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as T;
  } catch {
    return null;
  }
}

export function getCollectorToken(): string {
  if (typeof localStorage === "undefined") return "";
  return localStorage.getItem(COLLECTOR_TOKEN_KEY) || "";
}

export function setCollectorToken(token: string) {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(COLLECTOR_TOKEN_KEY, token);
}

export function formatApiErrorDetail(data: any): string | null {
  const detail = data?.error?.details ?? data?.detail;
  const envelopeMessage = data?.error?.message;

  if (detail === undefined || detail === null) {
    return typeof envelopeMessage === "string" ? envelopeMessage : null;
  }

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const details = detail
      .map((item) => {
        const location = Array.isArray(item?.loc) ? item.loc.join(".") : item?.loc;
        const message = item?.msg || item?.message || JSON.stringify(item);
        return location ? `${location}: ${message}` : message;
      })
      .join("; ");
    return envelopeMessage ? `${envelopeMessage}: ${details}` : details;
  }

  const details = JSON.stringify(detail);
  return envelopeMessage ? `${envelopeMessage}: ${details}` : details;
}

export class ApiError extends Error {
  status: number;
  data: any;
  constructor(message: string, status: number, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

type ReqOptions = {
  method?: string;
  body?: any;
  headers?: Record<string, string>;
  auth?: boolean;
  collectorToken?: boolean;
  query?: Record<string, any>;
  raw?: boolean;
};

export async function api<T = any>(path: string, opts: ReqOptions = {}): Promise<T> {
  const {
    method = "GET",
    body,
    headers = {},
    auth = true,
    collectorToken = false,
    query,
    raw = false,
  } = opts;

  let url = `${getApiBaseUrl()}${path}`;
  if (query) {
    const qs = new URLSearchParams(
      Object.entries(query)
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    if (qs) url += (url.includes("?") ? "&" : "?") + qs;
  }

  const finalHeaders: Record<string, string> = {
    Accept: "application/json",
    ...headers,
  };

  if (body !== undefined && !(body instanceof FormData)) {
    finalHeaders["Content-Type"] = "application/json";
  }
  if (auth) {
    const t = getToken();
    if (t) finalHeaders["Authorization"] = `Bearer ${t}`;
  }
  if (collectorToken) {
    const ct = getCollectorToken();
    if (ct) finalHeaders["X-Collector-Token"] = ct;
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: finalHeaders,
      body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
    });
  } catch (e: any) {
    throw new ApiError(`Network error: ${e?.message || "unreachable"}`, 0);
  }

  if (res.status === 401 && auth) {
    setToken(null);
    if (typeof localStorage !== "undefined") localStorage.removeItem(USER_KEY);
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
  }

  const text = await res.text();
  let data: any = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* keep text */
  }

  if (!res.ok) {
    const msg =
      formatApiErrorDetail(data) ||
      (data && (data.message || data.error)) ||
      `${res.status} ${res.statusText}`;
    throw new ApiError(typeof msg === "string" ? msg : JSON.stringify(msg), res.status, data);
  }
  return raw ? (data as T) : (data as T);
}

export async function pingBackend(): Promise<boolean> {
  try {
    await fetch(`${getApiBaseUrl()}${ENDPOINTS.health}`, { method: "GET" });
    return true;
  } catch {
    return false;
  }
}
