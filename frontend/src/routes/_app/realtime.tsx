import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Radio, RotateCcw, Trash2, PlugZap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { JsonViewer } from "@/components/JsonViewer";
import { WS_ALERTS_URL, getToken } from "@/lib/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_app/realtime")({
  component: RealtimePage,
});

type Event = { id: number; ts: string; data: any };

function RealtimePage() {
  const [status, setStatus] = useState<"idle" | "connecting" | "open" | "closed" | "error">("idle");
  const [events, setEvents] = useState<Event[]>([]);
  const [url, setUrl] = useState(WS_ALERTS_URL);
  const wsRef = useRef<WebSocket | null>(null);
  const counter = useRef(0);

  function disconnect() {
    wsRef.current?.close();
    wsRef.current = null;
  }

  function connect() {
    disconnect();
    setStatus("connecting");
    const token = getToken();
    const sep = url.includes("?") ? "&" : "?";
    const wsUrl = token ? `${url}${sep}token=${encodeURIComponent(token)}` : url;
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => {
        setStatus("open");
        ws.send(
          JSON.stringify({
            action: "subscribe",
            replace: true,
            event_types: [
              "soc.alert.created",
              "soc.incident.created",
              "soc.response_action.created",
              "system.connected",
            ],
          }),
        );
      };
      ws.onmessage = (ev) => {
        let data: any = ev.data;
        try {
          data = JSON.parse(ev.data);
        } catch {
          data = ev.data;
        }
        counter.current += 1;
        setEvents((prev) =>
          [{ id: counter.current, ts: new Date().toISOString(), data }, ...prev].slice(0, 200),
        );
      };
      ws.onclose = () => setStatus("closed");
      ws.onerror = () => setStatus("error");
    } catch {
      setStatus("error");
    }
  }

  useEffect(() => {
    connect();
    return () => disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dot = {
    idle: "bg-muted-foreground",
    connecting: "bg-[var(--color-warning)] animate-pulse",
    open: "bg-[var(--color-success)] animate-pulse",
    closed: "bg-muted-foreground",
    error: "bg-destructive",
  }[status];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Radio className="h-5 w-5 text-primary" /> Realtime WebSocket
          </h1>
          <p className="text-sm text-muted-foreground">Live alerts, incidents, and SOAR events.</p>
        </div>
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-xs",
            )}
          >
            <span className={cn("h-2 w-2 rounded-full", dot)} />
            <span className="font-mono uppercase">{status}</span>
          </div>
          <Button onClick={connect} variant="outline" size="sm" className="gap-2">
            <RotateCcw className="h-3.5 w-3.5" /> Reconnect
          </Button>
          <Button onClick={() => setEvents([])} variant="outline" size="sm" className="gap-2">
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-col gap-2 p-4 sm:flex-row">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 rounded-md border border-border bg-input px-3 py-2 text-xs font-mono"
            placeholder="ws://127.0.0.1:8000/ws/alerts"
          />
          <Button onClick={connect} className="gap-2">
            <PlugZap className="h-4 w-4" /> Connect
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {events.length === 0 ? (
            <div className="p-10 text-center text-sm text-muted-foreground">
              Waiting for events…
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {events.map((e) => (
                <li key={e.id} className="p-4 space-y-2">
                  <div className="flex items-center gap-3 text-xs">
                    <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-primary">
                      #{e.id}
                    </span>
                    <span className="font-mono text-muted-foreground">{e.ts}</span>
                    {(e.data?.event_type || e.data?.type) && (
                      <span className="rounded border border-border px-1.5 py-0.5 font-mono uppercase text-[10px]">
                        {String(e.data.event_type || e.data.type)}
                      </span>
                    )}
                  </div>
                  <JsonViewer data={e.data} maxHeight="200px" />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
