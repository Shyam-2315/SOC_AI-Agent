import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard,
  Bell,
  AlertOctagon,
  Zap,
  Crosshair,
  FileCode2,
  Package,
  Radio,
  Building2,
  Users,
  Bot,
  Activity,
  Database,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

const groups: { label: string; items: { to: string; label: string; icon: React.ElementType }[] }[] =
  [
    {
      label: "Operations",
      items: [
        { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
        { to: "/alerts", label: "Alerts", icon: Bell },
        { to: "/incidents", label: "Incidents", icon: AlertOctagon },
        { to: "/soar", label: "SOAR Actions", icon: Zap },
        { to: "/hunting", label: "Threat Hunting", icon: Crosshair },
        { to: "/realtime", label: "Realtime Feed", icon: Activity },
      ],
    },
    {
      label: "Detection",
      items: [
        { to: "/rules", label: "Detection Rules", icon: FileCode2 },
        { to: "/packs", label: "Rule Packs", icon: Package },
        { to: "/collectors", label: "Collectors", icon: Radio },
        { to: "/ingest", label: "Log Ingestion", icon: Database },
      ],
    },
    {
      label: "Workspace",
      items: [
        { to: "/copilot", label: "Copilot", icon: Bot },
        { to: "/orgs", label: "Organizations", icon: Building2 },
        { to: "/users", label: "Users", icon: Users },
      ],
    },
  ];

export function Sidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <Link
        to="/dashboard"
        className="flex items-center gap-2 border-b border-sidebar-border px-5 py-4"
      >
        <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-primary shadow-glow">
          <ShieldCheck className="h-5 w-5 text-primary-foreground" />
        </div>
        <div>
          <div className="text-sm font-semibold leading-tight">
            Sentinel<span className="text-primary">AI</span>
          </div>
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
            SOC Console
          </div>
        </div>
      </Link>
      <nav className="scrollbar-thin flex-1 overflow-y-auto px-3 py-4">
        {groups.map((g) => (
          <div key={g.label} className="mb-5">
            <div className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              {g.label}
            </div>
            <ul className="space-y-0.5">
              {g.items.map((it) => {
                const active = pathname === it.to || pathname.startsWith(it.to + "/");
                const Icon = it.icon;
                return (
                  <li key={it.to}>
                    <Link
                      to={it.to}
                      className={cn(
                        "group flex items-center gap-3 rounded-md px-2.5 py-2 text-sm transition",
                        active
                          ? "bg-sidebar-accent text-sidebar-accent-foreground"
                          : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-4 w-4",
                          active
                            ? "text-primary"
                            : "text-muted-foreground group-hover:text-foreground",
                        )}
                      />
                      <span className="truncate">{it.label}</span>
                      {active && (
                        <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary shadow-glow" />
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="border-t border-sidebar-border p-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-primary" />
          Tenant API console
        </div>
        <div className="mt-1 font-mono text-[10px]">v1.0.0 · build 2026.05</div>
      </div>
    </aside>
  );
}
