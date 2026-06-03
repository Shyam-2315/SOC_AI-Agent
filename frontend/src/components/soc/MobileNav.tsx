import { Link, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { navGroups } from "./nav";

const flatItems = navGroups.flatMap((group) => group.items);

export function MobileNav() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  return (
    <nav
      className="border-b border-border bg-background/95 px-4 py-3 md:hidden"
      aria-label="Mobile navigation"
      data-testid="mobile-nav"
    >
      <div className="scrollbar-thin flex gap-2 overflow-x-auto pb-1">
        {flatItems.map((item) => {
          const active = pathname === item.to || pathname.startsWith(`${item.to}/`);
          const Icon = item.icon;
          return (
            <Link
              key={item.to}
              to={item.to}
              className={cn(
                "inline-flex shrink-0 items-center gap-2 rounded-full border px-3 py-2 text-xs transition",
                active
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border bg-card text-muted-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {item.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
