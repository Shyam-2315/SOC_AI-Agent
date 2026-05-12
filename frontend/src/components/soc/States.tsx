import { type ReactNode } from "react";
import { Loader2, AlertTriangle, Inbox } from "lucide-react";

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 rounded-xl border border-border bg-card/50 p-12 text-sm text-muted-foreground">
      <Loader2 className="h-4 w-4 animate-spin text-primary" /> {label}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message,
  action,
  onRetry,
}: {
  title?: string;
  message?: string;
  action?: ReactNode;
  onRetry?: () => void;
}) {
  const retry = onRetry ?? (typeof window !== "undefined" ? () => window.location.reload() : null);
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-destructive/30 bg-destructive/5 p-10 text-center">
      <AlertTriangle className="h-6 w-6 text-destructive" />
      <div>
        <div className="text-base font-medium">{title}</div>
        {message && <div className="mt-1 max-w-md text-sm text-muted-foreground">{message}</div>}
      </div>
      {action ??
        (retry && (
          <button
            type="button"
            onClick={retry}
            className="rounded-md border border-border bg-card px-3 py-1.5 text-xs text-foreground transition hover:border-primary/40"
          >
            Retry
          </button>
        ))}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border bg-card/30 p-12 text-center">
      <div className="rounded-full border border-border bg-card p-3 text-muted-foreground">
        {icon ?? <Inbox className="h-5 w-5" />}
      </div>
      <div>
        <div className="text-base font-medium">{title}</div>
        {description && (
          <div className="mt-1 max-w-md text-sm text-muted-foreground">{description}</div>
        )}
      </div>
      {action}
    </div>
  );
}
