import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  backend,
  entityId,
  getApiBase,
  getLastApiError,
  getToken,
  getTokenClaims,
  getWebsocketStatus,
  getWsBase,
  isDemoMode,
  onApiDebugChange,
  onWebsocketStatusChange,
} from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { useMounted } from "@/hooks/use-mounted";

export function DebugPanel() {
  const visible = import.meta.env.DEV || isDemoMode();
  const mounted = useMounted();
  const [lastError, setLastError] = useState<ReturnType<typeof getLastApiError>>(() => null);
  const [wsStatus, setWsStatus] = useState("not connected");
  const claims = mounted ? getTokenClaims() : null;
  const organization = useQuery({
    queryKey: ["debug", "organization"],
    queryFn: backend.organization,
    enabled: visible && mounted && canQueryBackend(),
  });

  useEffect(() => {
    setLastError(getLastApiError());
    setWsStatus(getWebsocketStatus());
    const removeApi = onApiDebugChange(() => setLastError(getLastApiError()));
    const removeWs = onWebsocketStatusChange(() => setWsStatus(getWebsocketStatus()));
    return () => {
      removeApi();
      removeWs();
    };
  }, []);

  if (!visible) return null;

  return (
    <details className="fixed bottom-3 right-3 z-50 w-[min(26rem,calc(100vw-1.5rem))] rounded-lg border border-border bg-popover/95 text-xs shadow-lg backdrop-blur">
      <summary className="cursor-pointer select-none px-3 py-2 font-medium text-foreground">
        Frontend debug
      </summary>
      <div className="space-y-2 border-t border-border p-3 text-muted-foreground">
        <DebugRow label="Mode" value={isDemoMode() ? "demo" : "development"} />
        <DebugRow label="API base" value={mounted ? getApiBase() : "checking"} mono />
        <DebugRow label="WS base" value={mounted ? getWsBase() : "checking"} mono />
        <DebugRow label="Token" value={mounted && getToken() ? "present" : "missing"} />
        <DebugRow label="User" value={textOf(claims?.email, "not logged in")} mono />
        <DebugRow
          label="Org"
          value={
            organization.data
              ? `${textOf(organization.data.name, "Organization")} (${entityId(organization.data)})`
              : organization.isLoading
                ? "loading"
                : "unavailable"
          }
          mono
        />
        <DebugRow label="WebSocket" value={wsStatus} />
        <div>
          <div className="mb-1 font-medium text-foreground">Last API error</div>
          <div className="rounded-md border border-border bg-background p-2 font-mono text-[11px]">
            {lastError ? `${lastError.status} ${lastError.path}: ${lastError.message}` : "none"}
          </div>
        </div>
      </div>
    </details>
  );
}

function DebugRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[6rem_1fr] gap-2">
      <div className="font-medium text-foreground">{label}</div>
      <div className={mono ? "break-all font-mono text-[11px]" : ""}>{value}</div>
    </div>
  );
}
