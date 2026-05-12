import { useMemo, useState, type ReactNode } from "react";
import { Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { EmptyState } from "./States";

export type Column<T> = {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  className?: string;
  sortable?: boolean;
  accessor?: (row: T) => string | number;
};

export function DataTable<T extends { id: string | number }>({
  rows,
  columns,
  searchPlaceholder = "Search…",
  searchKeys,
  emptyTitle = "No results",
  actions,
}: {
  rows: T[];
  columns: Column<T>[];
  searchPlaceholder?: string;
  searchKeys?: (keyof T)[];
  emptyTitle?: string;
  actions?: ReactNode;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    if (!q.trim()) return rows;
    const needle = q.toLowerCase();
    return rows.filter((r) => {
      const keys = searchKeys ?? (Object.keys(r) as (keyof T)[]);
      return keys.some((k) =>
        String((r as Record<string, unknown>)[k as string] ?? "")
          .toLowerCase()
          .includes(needle),
      );
    });
  }, [rows, q, searchKeys]);

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card shadow-card">
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-card/60 px-4 py-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full rounded-md border border-border bg-background/60 py-2 pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div className="text-xs text-muted-foreground">
          {filtered.length} of {rows.length}
        </div>
        {actions}
      </div>
      {filtered.length === 0 ? (
        <div className="p-6">
          <EmptyState
            title={emptyTitle}
            description={
              rows.length === 0
                ? "No backend records were returned for this tenant."
                : "Try adjusting your filters or search query."
            }
          />
        </div>
      ) : (
        <div className="scrollbar-thin overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-background/30 text-left text-xs uppercase tracking-wider text-muted-foreground">
                {columns.map((c) => (
                  <th key={c.key} className={cn("px-4 py-3 font-medium", c.className)}>
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr
                  key={String(r.id)}
                  className="border-b border-border/60 transition hover:bg-accent/40"
                >
                  {columns.map((c) => (
                    <td key={c.key} className={cn("px-4 py-3 align-middle", c.className)}>
                      {c.render(r)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
