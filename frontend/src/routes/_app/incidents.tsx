import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { RefreshCw, Plus, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "@/components/SeverityBadge";
import { JsonViewer } from "@/components/JsonViewer";
import { api, ENDPOINTS } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/incidents")({
  component: IncidentsPage,
});

const STATUSES = ["open", "investigating", "contained", "resolved", "closed"];

function IncidentsPage() {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    title: "",
    description: "",
    severity: "medium",
    assigned_to: "",
  });
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<any>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await api<any>(ENDPOINTS.incidents);
      setItems(Array.isArray(data) ? data : data?.items || data?.results || []);
    } catch (e: any) {
      toast.error(e?.message || "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create() {
    setCreating(true);
    try {
      await api(ENDPOINTS.createIncident, {
        method: "POST",
        body: {
          title: form.title,
          description: form.description,
          severity: form.severity,
          assigned_to: form.assigned_to || null,
        },
      });
      toast.success("Incident created");
      setOpen(false);
      setForm({ title: "", description: "", severity: "medium", assigned_to: "" });
      load();
    } catch (e: any) {
      toast.error(e?.message || "Create failed");
    } finally {
      setCreating(false);
    }
  }

  async function updateStatus(it: any, status: string) {
    try {
      await api(ENDPOINTS.updateIncident(it.id), { method: "PATCH", body: { status } });
      toast.success("Status updated");
      load();
    } catch (e: any) {
      toast.error(e?.message || "Update failed");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Incidents</h1>
          <p className="text-sm text-muted-foreground">{items.length} incidents</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} className="gap-2">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="gap-2">
                <Plus className="h-3.5 w-3.5" /> New incident
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create incident</DialogTitle>
              </DialogHeader>
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label>Title</Label>
                  <Input
                    value={form.title}
                    onChange={(e) => setForm({ ...form, title: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Description</Label>
                  <Textarea
                    rows={3}
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
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
                        {["low", "medium", "high", "critical"].map((s) => (
                          <SelectItem key={s} value={s}>
                            {s}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Assigned to</Label>
                    <Input
                      value={form.assigned_to}
                      onChange={(e) => setForm({ ...form, assigned_to: e.target.value })}
                    />
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={create} disabled={creating}>
                  {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {loading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!loading && items.length === 0 && (
        <div className="text-sm text-muted-foreground">No incidents.</div>
      )}

      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
        {items.map((it, i) => (
          <Card
            key={it.id ?? i}
            className="cursor-pointer hover:border-primary/40 transition-colors"
            onClick={() => setSelected(it)}
          >
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">{it.title || `Incident #${it.id ?? i}`}</CardTitle>
                <SeverityBadge severity={it.severity} />
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="line-clamp-3 text-xs text-muted-foreground">
                {it.description || it.summary || "—"}
              </p>
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-mono uppercase text-primary">{it.status || "open"}</span>
                <span className="text-muted-foreground">{it.created_at || ""}</span>
              </div>
              {it.alert_id && (
                <div className="text-[11px] text-muted-foreground">
                  Linked alert: <code>{it.alert_id}</code>
                </div>
              )}
              <div className="flex flex-wrap gap-1" onClick={(e) => e.stopPropagation()}>
                {STATUSES.map((s) => (
                  <button
                    key={s}
                    onClick={() => updateStatus(it, s)}
                    className="rounded border border-border bg-secondary/40 px-2 py-0.5 text-[10px] hover:bg-secondary"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {selected && (
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">Incident detail</div>
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
