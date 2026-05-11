import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Building2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JsonViewer } from "@/components/JsonViewer";
import { api, ApiError, ENDPOINTS } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/organization")({
  component: OrgPage,
});

function OrgPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const d = await api(ENDPOINTS.organization);
      setData(d);
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 403) {
        toast.error("Organization details are admin only");
        setData({ error: "Admin access required" });
      } else {
        toast.error(e?.message || "Failed to load organization");
        setData(null);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Building2 className="h-5 w-5 text-primary" /> Organization
          </h1>
          <p className="text-sm text-muted-foreground">Current organization details.</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-2">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {data && typeof data === "object" && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Object.entries(data)
            .filter(([, v]) => typeof v !== "object")
            .map(([k, v]) => (
              <Card key={k}>
                <CardContent className="p-4">
                  <div className="text-xs uppercase tracking-wider text-muted-foreground">{k}</div>
                  <div className="mt-1 text-sm font-mono break-all">{String(v ?? "—")}</div>
                </CardContent>
              </Card>
            ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Raw response</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-xs text-muted-foreground">Loading…</div>
          ) : (
            <JsonViewer data={data} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
