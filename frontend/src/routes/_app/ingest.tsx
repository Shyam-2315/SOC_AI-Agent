import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { toast } from "sonner";
import { Send, Save, Loader2, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JsonViewer } from "@/components/JsonViewer";
import { ApiError, api, ENDPOINTS, getCollectorToken, setCollectorToken } from "@/lib/api";

export const Route = createFileRoute("/_app/ingest")({
  component: IngestPage,
});

const SEVERITIES = ["low", "medium", "high", "critical"];
const DEFAULT_COLLECTOR_TOKEN = "test-collector-token";

function IngestPage() {
  const [collector, setCollector] = useState(getCollectorToken() || DEFAULT_COLLECTOR_TOKEN);
  const [form, setForm] = useState({
    source: "firewall",
    event_type: "connection_attempt",
    severity: "medium",
    message: "Suspicious outbound connection",
    ip_address: "10.0.0.1",
  });
  const [submitting, setSubmitting] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [taskStatus, setTaskStatus] = useState<any>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    },
    [],
  );

  function saveCollector() {
    setCollectorToken(collector.trim());
    toast.success("Collector token saved");
  }

  async function submit(async = false) {
    const collectorToken = collector.trim();
    if (!collectorToken) {
      const message = "Collector token is required";
      toast.error(message);
      setResponse({ error: message });
      return;
    }

    setCollectorToken(collectorToken);
    setSubmitting(true);
    setResponse(null);
    setTaskStatus(null);
    try {
      const res = await api(async ? ENDPOINTS.ingestAsync : ENDPOINTS.ingest, {
        method: "POST",
        body: form,
        auth: false,
        headers: { "X-Collector-Token": collectorToken },
      });
      setResponse(res);
      toast.success(async ? "Async job submitted" : "Log ingested");
      const taskId = (res as any)?.task_id || (res as any)?.id;
      if (async && taskId) startPolling(String(taskId));
    } catch (e: any) {
      const message =
        e instanceof ApiError && e.status === 401
          ? "Missing or invalid collector token. Check X-Collector-Token."
          : e?.message || "Ingestion failed";
      toast.error(message);
      setResponse({ error: message, status: e?.status, data: e?.data });
    } finally {
      setSubmitting(false);
    }
  }

  function startPolling(taskId: string) {
    const collectorToken = collector.trim();
    if (!collectorToken) {
      toast.error("Collector token is required");
      return;
    }

    if (pollRef.current) window.clearInterval(pollRef.current);
    const tick = async () => {
      try {
        const t = await api(ENDPOINTS.ingestTask(taskId), {
          auth: false,
          headers: { "X-Collector-Token": collectorToken },
        });
        setTaskStatus(t);
        const status = String((t as any)?.status || "").toLowerCase();
        if (status === "completed" || status === "failed" || status === "success") {
          if (pollRef.current) window.clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch (e: any) {
        if (pollRef.current) window.clearInterval(pollRef.current);
        pollRef.current = null;
        const message =
          e instanceof ApiError && e.status === 401
            ? "Task polling stopped: missing or invalid collector token"
            : "Task polling stopped: " + (e?.message || "request failed");
        toast.error(message);
        setTaskStatus({ error: message, status: e?.status, data: e?.data });
      }
    };
    tick();
    pollRef.current = window.setInterval(tick, 1500);
  }

  const taskState = String(taskStatus?.status || "").toLowerCase();
  const stateColor =
    taskState === "completed" || taskState === "success"
      ? "text-[var(--color-success)]"
      : taskState === "failed"
        ? "text-destructive"
        : taskState === "processing"
          ? "text-[var(--color-info)]"
          : "text-[var(--color-warning)]";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Log Ingestion</h1>
        <p className="text-sm text-muted-foreground">
          Send logs to <code className="font-mono">/ingest</code> or queue async via{" "}
          <code className="font-mono">/ingest/async</code>.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Collector Token</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={collector}
            onChange={(e) => setCollector(e.target.value)}
            placeholder="Paste collector token (saved locally)"
            className="font-mono text-xs"
          />
          <Button onClick={saveCollector} variant="outline" className="gap-2">
            <Save className="h-4 w-4" /> Save
          </Button>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">New Log Event</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Source</Label>
                <Input
                  value={form.source}
                  onChange={(e) => setForm({ ...form, source: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Event type</Label>
                <Input
                  value={form.event_type}
                  onChange={(e) => setForm({ ...form, event_type: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Severity</Label>
                <Select
                  value={form.severity}
                  onValueChange={(v) => setForm({ ...form, severity: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>IP address</Label>
                <Input
                  value={form.ip_address}
                  onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Message</Label>
              <Textarea
                rows={4}
                value={form.message}
                onChange={(e) => setForm({ ...form, message: e.target.value })}
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={() => submit(false)} disabled={submitting} className="gap-2">
                {submitting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
                Ingest
              </Button>
              <Button
                onClick={() => submit(true)}
                disabled={submitting}
                variant="outline"
                className="gap-2"
              >
                <Zap className="h-4 w-4" /> Async
              </Button>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Response</CardTitle>
            </CardHeader>
            <CardContent>
              <JsonViewer data={response} />
            </CardContent>
          </Card>
          {taskStatus && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  Task status:
                  <span className={`font-mono uppercase ${stateColor}`}>
                    {taskStatus.status || "unknown"}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <JsonViewer data={taskStatus} />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
