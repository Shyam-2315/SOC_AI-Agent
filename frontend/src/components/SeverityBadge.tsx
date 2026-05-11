import { cn } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const s = (severity || "unknown").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-destructive/15 text-destructive border-destructive/30",
    high: "bg-[var(--color-critical)]/15 text-[var(--color-critical)] border-[var(--color-critical)]/30",
    medium:
      "bg-[var(--color-warning)]/15 text-[var(--color-warning)] border-[var(--color-warning)]/30",
    low: "bg-[var(--color-info)]/15 text-[var(--color-info)] border-[var(--color-info)]/30",
    info: "bg-muted text-muted-foreground border-border",
    unknown: "bg-muted text-muted-foreground border-border",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider",
        map[s] || map.unknown,
      )}
    >
      {s}
    </span>
  );
}
