import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard,
  Upload,
  Bell,
  AlertTriangle,
  Zap,
  Crosshair,
  Bot,
  Radio,
  Users,
  Building2,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

const items = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/ingest", label: "Log Ingestion", icon: Upload },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/soar", label: "SOAR", icon: Zap },
  { to: "/hunting", label: "Threat Hunting", icon: Crosshair },
  { to: "/copilot", label: "Copilot", icon: Bot },
  { to: "/realtime", label: "Realtime", icon: Radio },
  { to: "/users", label: "Users", icon: Users },
  { to: "/organization", label: "Organization", icon: Building2 },
] as const;

export function AppSidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <aside className="hidden md:flex w-60 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
      <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
          <Shield className="h-4 w-4" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">AI SOC</div>
          <div className="text-[10px] uppercase text-muted-foreground tracking-widest">
            Platform
          </div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto p-2">
        {items.map((it) => {
          const active = pathname === it.to || pathname.startsWith(it.to + "/");
          const Icon = it.icon;
          return (
            <Link
              key={it.to}
              to={it.to}
              className={cn(
                "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
              )}
            >
              <Icon
                className={cn(
                  "h-4 w-4 shrink-0",
                  active
                    ? "text-primary"
                    : "text-sidebar-foreground/50 group-hover:text-sidebar-foreground",
                )}
              />
              <span>{it.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-sidebar-border p-3 text-[10px] text-muted-foreground font-mono">
        v1.0 · SOC Console
      </div>
    </aside>
  );
}
