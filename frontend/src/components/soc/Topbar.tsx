import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Bell, Search, LogOut, ChevronDown } from "lucide-react";
import { backend, getTokenClaims, setToken } from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { useState } from "react";
import { useMounted } from "@/hooks/use-mounted";

export function Topbar() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const mounted = useMounted();
  const claims = mounted ? getTokenClaims() : null;
  const organization = useQuery({
    queryKey: ["topbar", "organization"],
    queryFn: backend.organization,
    enabled: mounted && canQueryBackend(),
  });
  const orgName = textOf(organization.data?.name, "Current organization");
  const email = textOf(claims?.email, "signed-in user");
  const apiState = !mounted
    ? "checking"
    : organization.isLoading
      ? "checking"
      : organization.error
        ? "error"
        : "connected";

  function logout() {
    setToken(null);
    navigate({ to: "/login" });
  }

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur md:px-6">
      <div className="relative max-w-md flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          placeholder="Search alerts, incidents, IOCs…"
          className="w-full rounded-md border border-border bg-card py-1.5 pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        />
      </div>
      <div className="ml-auto flex items-center gap-2">
        <div
          className={`hidden items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs sm:flex ${
            apiState === "connected"
              ? "border-success/30 bg-success/10"
              : apiState === "error"
                ? "border-destructive/30 bg-destructive/10"
                : "border-border bg-card"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              apiState === "connected"
                ? "bg-success animate-pulse"
                : apiState === "error"
                  ? "bg-destructive"
                  : "bg-muted-foreground"
            }`}
          />
          <span className="text-muted-foreground">API</span>
          <span className="font-medium">{apiState}</span>
        </div>
        <Link
          to="/realtime"
          className="relative grid h-9 w-9 place-items-center rounded-md border border-border bg-card text-muted-foreground transition hover:text-foreground"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-critical" />
        </Link>
        <div className="relative">
          <button
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-sm hover:border-primary/40"
          >
            <div className="grid h-7 w-7 place-items-center rounded-full bg-gradient-primary text-xs font-semibold text-primary-foreground">
              {email[0]?.toUpperCase()}
            </div>
            <div className="hidden text-left sm:block">
              <div className="text-xs leading-none">{orgName}</div>
              <div className="text-[10px] text-muted-foreground">{email}</div>
            </div>
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
          {open && (
            <div className="absolute right-0 mt-2 w-56 rounded-md border border-border bg-popover p-1 text-sm shadow-lg">
              <div className="px-3 py-2 text-xs uppercase tracking-wider text-muted-foreground">
                Workspace
              </div>
              <Link
                to="/orgs"
                onClick={() => setOpen(false)}
                className="block rounded px-3 py-1.5 hover:bg-accent"
              >
                {orgName}
              </Link>
              <Link
                to="/users"
                onClick={() => setOpen(false)}
                className="block rounded px-3 py-1.5 hover:bg-accent"
              >
                Manage users
              </Link>
              <div className="my-1 h-px bg-border" />
              <button
                onClick={logout}
                className="flex w-full items-center gap-2 rounded px-3 py-1.5 text-left text-destructive hover:bg-destructive/10"
              >
                <LogOut className="h-4 w-4" /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
