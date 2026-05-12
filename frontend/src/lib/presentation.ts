import type { Severity } from "@/components/soc/SeverityBadge";
import { entityId, isAuthenticated, type BackendDocument } from "@/lib/api";

export function canQueryBackend(): boolean {
  return typeof window !== "undefined" && isAuthenticated();
}

export function severityOf(value: unknown): Severity {
  const normalized = String(value ?? "info").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
    return normalized as Severity;
  }
  return "info";
}

export function textOf(value: unknown, fallback = "Unknown"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

export function timeOf(value: unknown): string {
  if (!value) return "Never";
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleTimeString();
}

export function dateTimeOf(value: unknown): string {
  if (!value) return "Never";
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

export function shortId(record: BackendDocument, prefix = ""): string {
  const id = entityId(record);
  if (!id) return "unknown";
  return `${prefix}${id.slice(-8)}`;
}

export function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
