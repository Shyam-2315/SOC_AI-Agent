import type { ElementType } from "react";
import {
  Activity,
  Bell,
  Bot,
  Building2,
  Crosshair,
  Database,
  FileCode2,
  LayoutDashboard,
  Package,
  Radio,
  Shield,
  ShieldAlert,
  Users,
  Zap,
  AlertOctagon,
  GitBranch,
} from "lucide-react";

export type NavItem = {
  to: string;
  label: string;
  icon: ElementType;
};

export type NavGroup = {
  label: string;
  items: NavItem[];
};

export const navGroups: NavGroup[] = [
  {
    label: "Operations",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { to: "/alerts", label: "Alerts", icon: Bell },
      { to: "/incidents", label: "Incidents", icon: AlertOctagon },
      { to: "/attack-chains", label: "Attack Chains", icon: GitBranch },
      { to: "/soar", label: "SOAR Actions", icon: Zap },
      { to: "/hunting", label: "Threat Hunting", icon: Crosshair },
      { to: "/threat-intel", label: "Threat Intel", icon: ShieldAlert },
      { to: "/realtime", label: "Realtime Feed", icon: Activity },
      { to: "/security", label: "Traffic Security", icon: Shield },
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
