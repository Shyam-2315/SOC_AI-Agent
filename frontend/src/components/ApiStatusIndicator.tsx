import { useEffect, useState } from "react";
import { ENDPOINTS, getApiBaseUrl } from "@/lib/api";
import { cn } from "@/lib/utils";

export function ApiStatusIndicator({ className }: { className?: string }) {
  const [status, setStatus] = useState<"checking" | "online" | "offline">("checking");

  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        const res = await fetch(`${getApiBaseUrl()}${ENDPOINTS.health}`);
        if (!active) return;
        setStatus(res.ok ? "online" : "offline");
      } catch {
        if (active) setStatus("offline");
      }
    };
    check();
    const id = setInterval(check, 15000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const color =
    status === "online"
      ? "bg-[var(--color-success)]"
      : status === "offline"
        ? "bg-destructive"
        : "bg-muted-foreground";
  const label =
    status === "online" ? "API Online" : status === "offline" ? "API Offline" : "Checking…";

  return (
    <div className={cn("flex items-center gap-2 text-xs text-muted-foreground", className)}>
      <span className={cn("h-2 w-2 rounded-full", color, status === "online" && "animate-pulse")} />
      <span className="font-mono">{label}</span>
      <span className="hidden md:inline text-muted-foreground/60">· {getApiBaseUrl()}</span>
    </div>
  );
}
