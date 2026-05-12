import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const styles: Record<Severity, string> = {
  critical: "bg-critical/15 text-critical border-critical/30",
  high: "bg-destructive/15 text-destructive border-destructive/30",
  medium: "bg-warning/15 text-warning border-warning/30",
  low: "bg-info/15 text-info border-info/30",
  info: "bg-muted text-muted-foreground border-border",
};

export function SeverityBadge({
  severity,
  children,
  className,
}: {
  severity: Severity;
  children?: ReactNode;
  className?: string;
}) {
  const label = (children ?? severity).toString();
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        styles[severity],
        className,
      )}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          severity === "critical" && "bg-critical animate-pulse",
          severity === "high" && "bg-destructive",
          severity === "medium" && "bg-warning",
          severity === "low" && "bg-info",
          severity === "info" && "bg-muted-foreground",
        )}
      />
      {label}
    </span>
  );
}

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const s = status.toLowerCase();
  const cls =
    s === "online" || s === "active" || s === "success" || s === "resolved" || s === "closed"
      ? "bg-success/15 text-success border-success/30"
      : s === "running" || s === "investigating" || s === "open"
        ? "bg-info/15 text-info border-info/30"
        : s === "queued"
          ? "bg-warning/15 text-warning border-warning/30"
          : s === "failed" || s === "offline" || s === "disabled"
            ? "bg-destructive/15 text-destructive border-destructive/30"
            : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        cls,
        className,
      )}
    >
      {status}
    </span>
  );
}
