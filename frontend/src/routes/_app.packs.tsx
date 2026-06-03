import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type DetectionPackRecord } from "@/lib/api";
import { canQueryBackend, downloadJson, textOf } from "@/lib/presentation";
import { Download, Package, Plus, Trash2, Upload } from "lucide-react";

export const Route = createFileRoute("/_app/packs")({
  head: () => ({ meta: [{ title: "Rule Packs — SentinelAI" }] }),
  component: PacksPage,
});

function PacksPage() {
  const queryClient = useQueryClient();
  const [importText, setImportText] = useState("");
  const [draft, setDraft] = useState({
    name: "",
    description: "",
    category: "authentication",
    version: "1.0.0",
    enabled: true,
  });
  const packs = useQuery({
    queryKey: ["rule-packs"],
    queryFn: () => backend.packs({ limit: 100 }),
    enabled: canQueryBackend(),
  });
  const starters = useQuery({
    queryKey: ["starter-packs"],
    queryFn: backend.starterPacks,
    enabled: canQueryBackend(),
  });
  const updatePack = useMutation({
    mutationFn: (pack: DetectionPackRecord) =>
      backend.updatePack(entityId(pack), { enabled: !pack.enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rule-packs"] }),
  });
  const createPack = useMutation({
    mutationFn: () => backend.createPack(draft),
    onSuccess: () => {
      setDraft({
        name: "",
        description: "",
        category: "authentication",
        version: "1.0.0",
        enabled: true,
      });
      queryClient.invalidateQueries({ queryKey: ["rule-packs"] });
    },
  });
  const importPack = useMutation({
    mutationFn: (rawBody: string) =>
      backend.importPack(
        rawBody,
        rawBody.trim().startsWith("{") ? "application/json" : "application/x-yaml",
      ),
    onSuccess: () => {
      setImportText("");
      queryClient.invalidateQueries({ queryKey: ["rule-packs"] });
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const deletePack = useMutation({
    mutationFn: backend.deletePack,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rule-packs"] });
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  const queries = [packs, starters];
  if (queries.some((q) => q.isLoading || q.isPending))
    return <LoadingState label="Loading rule packs…" />;
  const error = queries.find((q) => q.error)?.error;
  if (error)
    return (
      <ErrorState message={error instanceof Error ? error.message : "Could not load rule packs."} />
    );

  async function exportPack(id: string, name: string) {
    const exported = await backend.exportPack(id, "json");
    downloadJson(`${name || "rule-pack"}.json`, exported);
  }

  return (
    <div className="space-y-6" data-testid="packs-page">
      <PageHeader
        eyebrow="Detection"
        title="Rule Packs"
        description="Import, export and toggle Sigma-compatible rule bundles."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-3">
          <div className="rounded-xl border border-border bg-card p-4 shadow-card">
            <div className="mb-3 text-sm font-semibold">Create rule pack</div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-muted-foreground">Name</span>
                <input
                  value={draft.name}
                  onChange={(event) => setDraft((value) => ({ ...value, name: event.target.value }))}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  aria-label="Rule pack name"
                  placeholder="Endpoint Starter"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-muted-foreground">
                  Category
                </span>
                <input
                  value={draft.category}
                  onChange={(event) =>
                    setDraft((value) => ({ ...value, category: event.target.value }))
                  }
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  aria-label="Rule pack category"
                  placeholder="authentication"
                />
              </label>
              <label className="block md:col-span-2">
                <span className="mb-1 block text-xs font-medium text-muted-foreground">
                  Description
                </span>
                <textarea
                  value={draft.description}
                  onChange={(event) =>
                    setDraft((value) => ({ ...value, description: event.target.value }))
                  }
                  rows={3}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  aria-label="Rule pack description"
                  placeholder="SOC starter rules for a specific use case."
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-medium text-muted-foreground">
                  Version
                </span>
                <input
                  value={draft.version}
                  onChange={(event) =>
                    setDraft((value) => ({ ...value, version: event.target.value }))
                  }
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  aria-label="Rule pack version"
                  placeholder="1.0.0"
                />
              </label>
            </div>
            <div className="mt-3 flex justify-end">
              <Btn
                variant="hero"
                size="sm"
                onClick={() => createPack.mutate()}
                disabled={!draft.name.trim() || !draft.description.trim() || createPack.isPending}
                data-testid="create-pack-button"
              >
                <Plus className="h-4 w-4" /> Create pack
              </Btn>
            </div>
          </div>
          {(packs.data?.items ?? []).length === 0 ? (
            <EmptyState
              title="No rule packs"
              description="Install a starter pack or import JSON/YAML to add tenant rules."
            />
          ) : (
            (packs.data?.items ?? []).map((pack) => (
              <div
                key={entityId(pack)}
                className="flex items-center gap-4 rounded-xl border border-border bg-card p-4 shadow-card"
              >
                <div className="grid h-10 w-10 place-items-center rounded-lg bg-primary/10 text-primary">
                  <Package className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{pack.name}</span>
                    <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-muted-foreground">
                      v{textOf(pack.version, "0.0.0")}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {pack.rules_count ?? 0} rules · {textOf(pack.category, "uncategorized")}
                  </div>
                </div>
                <button
                  onClick={() => updatePack.mutate(pack)}
                  className={`relative h-6 w-11 rounded-full border ${pack.enabled ? "border-primary bg-primary/30" : "border-border bg-muted"}`}
                >
                  <span
                    className={`absolute top-0.5 h-4 w-4 rounded-full bg-foreground transition ${pack.enabled ? "left-6" : "left-0.5"}`}
                  />
                </button>
                <Btn
                  variant="outline"
                  size="sm"
                  onClick={() => exportPack(entityId(pack), pack.name)}
                >
                  <Download className="h-4 w-4" /> Export
                </Btn>
                <Btn
                  variant="ghost"
                  size="sm"
                  onClick={() => deletePack.mutate(entityId(pack))}
                  className="text-destructive hover:bg-destructive/10"
                >
                  <Trash2 className="h-4 w-4" />
                </Btn>
              </div>
            ))
          )}
          {(createPack.error || updatePack.error || importPack.error || deletePack.error) && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {(createPack.error ?? updatePack.error ?? importPack.error ?? deletePack.error) instanceof Error
                ? (createPack.error ?? updatePack.error ?? importPack.error ?? deletePack.error)
                    ?.message
                : "Rule pack operation failed."}
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-4 shadow-card">
            <div className="mb-2 text-sm font-semibold">Import pack</div>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder='{"pack":{"name":"My Pack","description":"Custom rules","category":"custom","version":"1.0.0"},"rules":[]}'
              rows={6}
              className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <Btn
              className="mt-2 w-full"
              variant="hero"
              size="sm"
              onClick={() => importPack.mutate(importText)}
              disabled={!importText.trim() || importPack.isPending}
            >
              <Upload className="h-4 w-4" /> Import JSON / YAML
            </Btn>
          </div>
          <div className="rounded-xl border border-border bg-card p-4 shadow-card">
            <div className="mb-2 text-sm font-semibold">Starter packs</div>
            <ul className="space-y-1.5 text-sm">
              {(starters.data?.items ?? []).map((starter) => (
                <li
                  key={starter.key}
                  className="flex items-center justify-between rounded-md border border-border bg-background/50 px-3 py-2"
                >
                  <span>{starter.name}</span>
                  <button
                    className="text-xs text-primary hover:underline"
                    onClick={() => importPack.mutate(JSON.stringify({ starter_pack: starter.key }))}
                  >
                    Install
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
