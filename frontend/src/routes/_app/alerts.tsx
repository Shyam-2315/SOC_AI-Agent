import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/SeverityBadge";
import { JsonViewer } from "@/components/JsonViewer";
import { api, ENDPOINTS } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/alerts")({
  component: AlertsPage,
});

function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [selected, setSelected] = useState<any>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await api<any>(ENDPOINTS.alerts);
      const arr: any[] = Array.isArray(data) ? data : data?.items || data?.results || [];
      setAlerts(arr);
    } catch (e: any) {
      toast.error(e?.message || "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (sev && String(a.severity || "").toLowerCase() !== sev.toLowerCase()) return false;
      if (!q) return true;
      const hay = JSON.stringify(a).toLowerCase();
      return hay.includes(q.toLowerCase());
    });
  }, [alerts, q, sev]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
          <p className="text-sm text-muted-foreground">
            {alerts.length} total · {filtered.length} shown
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search…"
              className="h-9 pl-8 w-56"
            />
          </div>
          <select
            value={sev}
            onChange={(e) => setSev(e.target.value)}
            className="h-9 rounded-md border border-border bg-input px-2 text-sm"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <Button onClick={load} variant="outline" size="sm" className="gap-2">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Event</TableHead>
                <TableHead>Threat</TableHead>
                <TableHead>Score</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>MITRE Tactic</TableHead>
                <TableHead>MITRE Technique</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-sm text-muted-foreground py-8">
                    Loading…
                  </TableCell>
                </TableRow>
              )}
              {!loading && filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-sm text-muted-foreground py-8">
                    No alerts
                  </TableCell>
                </TableRow>
              )}
              {!loading &&
                filtered.map((a, i) => (
                  <TableRow
                    key={a.id ?? i}
                    className="cursor-pointer"
                    onClick={() => setSelected(a)}
                  >
                    <TableCell>
                      <SeverityBadge severity={a.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.event_type || a.type || "—"}
                    </TableCell>
                    <TableCell className="text-xs">{a.threat_label || a.threat || "—"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.threat_score ?? a.score ?? a.risk_score ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.ip_address || a.src_ip || "—"}
                    </TableCell>
                    <TableCell className="text-xs">{a.mitre_tactic || a.tactic || "—"}</TableCell>
                    <TableCell className="text-xs">
                      {a.mitre_technique || a.technique || "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {a.created_at || a.timestamp || "—"}
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selected && (
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">Alert detail</div>
              <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>
                Close
              </Button>
            </div>
            <JsonViewer data={selected} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
