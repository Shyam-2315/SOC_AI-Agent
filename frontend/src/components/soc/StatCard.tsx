import { type ReactNode } from "react";
import { cn } from "@/lib/utils";

export function StatCard({
  label,
  value,
  hint,
  icon,
  accent,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  accent?: "primary" | "critical" | "success" | "warning" | "info";
  className?: string;
}) {
  const accentRing = {
    primary: "from-primary/30",
    critical: "from-critical/30",
    success: "from-success/30",
    warning: "from-warning/30",
    info: "from-info/30",
  }[accent ?? "primary"];
  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-card transition hover:border-primary/40",
        className,
      )}
    >
      <div
        className={cn(
          "pointer-events-none absolute -right-12 -top-12 h-32 w-32 rounded-full bg-gradient-to-br to-transparent opacity-60 blur-2xl",
          accentRing,
        )}
      />
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className="mt-2 text-3xl font-semibold tabular-nums">{value}</div>
          {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
        </div>
        {icon && (
          <div className="rounded-lg border border-border bg-background/50 p-2 text-primary">
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}
