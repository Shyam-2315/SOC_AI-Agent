import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { RefreshCw, Shield, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JsonViewer } from "@/components/JsonViewer";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, ENDPOINTS } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/soar")({
  component: SoarPage,
});

function SoarPage() {
  const [actions, setActions] = useState<any[]>([]);
  const [ips, setIps] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);

  async function load() {
    setLoading(true);
    const safe = async <T,>(p: Promise<T>) =>
      p.catch((e) => {
        toast.error(e?.message || "Error");
        return null;
      });
    const [a, i] = await Promise.all([
      safe(api<any>(ENDPOINTS.soarActions)),
      safe(api<any>(ENDPOINTS.soarBlockedIps)),
    ]);
    setActions(Array.isArray(a) ? a : (a as any)?.items || (a as any)?.actions || []);
    setIps(Array.isArray(i) ? i : (i as any)?.items || (i as any)?.blocked_ips || []);
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">SOAR</h1>
          <p className="text-sm text-muted-foreground">
            Automated response actions and blocked IPs.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-2">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap className="h-4 w-4 text-primary" /> Automated Actions ({actions.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Playbook</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center text-sm text-muted-foreground py-6"
                    >
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {!loading && actions.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center text-sm text-muted-foreground py-6"
                    >
                      No actions
                    </TableCell>
                  </TableRow>
                )}
                {actions.map((a, i) => (
                  <TableRow
                    key={a.id ?? i}
                    className="cursor-pointer"
                    onClick={() => setSelected(a)}
                  >
                    <TableCell className="text-xs">
                      {a.playbook || a.playbook_name || "—"}
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {a.action || a.action_type || "—"}
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {a.target || a.ip_address || "—"}
                    </TableCell>
                    <TableCell className="text-xs">
                      <span className="font-mono uppercase text-primary">{a.status || "—"}</span>
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

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-[var(--color-info)]" /> Blocked IPs ({ips.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Blocked at</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && (
                  <TableRow>
                    <TableCell
                      colSpan={3}
                      className="text-center text-sm text-muted-foreground py-6"
                    >
                      Loading…
                    </TableCell>
                  </TableRow>
                )}
                {!loading && ips.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={3}
                      className="text-center text-sm text-muted-foreground py-6"
                    >
                      None
                    </TableCell>
                  </TableRow>
                )}
                {ips.map((row, i) => {
                  const ip = typeof row === "string" ? row : row.ip_address || row.ip;
                  const reason = typeof row === "string" ? "" : row.reason || row.message;
                  const ts = typeof row === "string" ? "" : row.blocked_at || row.created_at;
                  return (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{ip}</TableCell>
                      <TableCell className="text-xs">{reason || "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{ts || "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {selected && (
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">Action / playbook detail</div>
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
