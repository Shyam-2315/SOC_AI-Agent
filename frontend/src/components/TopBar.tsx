import { LogOut, User as UserIcon } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { ApiStatusIndicator } from "./ApiStatusIndicator";
import { Button } from "@/components/ui/button";

export function TopBar() {
  const { user, logout } = useAuth();
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-border bg-background/80 px-4 backdrop-blur md:px-6">
      <div className="flex items-center gap-3">
        <div className="text-sm font-semibold tracking-tight md:text-base">AI SOC Platform</div>
        <span className="hidden md:inline-block rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
          Console
        </span>
      </div>
      <div className="flex items-center gap-4">
        <ApiStatusIndicator />
        <div className="hidden md:flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-xs">
          <UserIcon className="h-3.5 w-3.5 text-primary" />
          <span className="font-medium text-foreground">
            {user?.email || user?.username || "user"}
          </span>
          {user?.role && (
            <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[10px] uppercase text-primary">
              {user.role}
            </span>
          )}
        </div>
        <Button size="sm" variant="outline" onClick={logout} className="gap-2">
          <LogOut className="h-3.5 w-3.5" />
          Logout
        </Button>
      </div>
    </header>
  );
}
