import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Building2 } from "lucide-react";
import { Btn } from "@/components/soc/Btn";
import { ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId } from "@/lib/api";
import { canQueryBackend, dateTimeOf, textOf } from "@/lib/presentation";

export const Route = createFileRoute("/_app/orgs")({
  head: () => ({ meta: [{ title: "Organizations — SentinelAI" }] }),
  component: OrgsPage,
});

function OrgsPage() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const organization = useQuery({
    queryKey: ["organization"],
    queryFn: backend.organization,
    enabled: canQueryBackend(),
  });
  const createOrg = useMutation({
    mutationFn: backend.createOrganization,
    onSuccess: () => {
      setName("");
      queryClient.invalidateQueries({ queryKey: ["organization"] });
    },
  });

  if (organization.isLoading || organization.isPending)
    return <LoadingState label="Loading organization…" />;
  if (organization.error)
    return (
      <ErrorState
        message={
          organization.error instanceof Error
            ? organization.error.message
            : "Could not load organization."
        }
      />
    );

  const org = organization.data;

  return (
    <div className="space-y-6" data-testid="orgs-page">
      <PageHeader
        eyebrow="Workspace"
        title="Organizations"
        description="Current tenant from the backend."
        actions={
          <Btn
            variant="hero"
            size="sm"
            onClick={() => name.trim() && createOrg.mutate(name.trim())}
            disabled={!name.trim() || createOrg.isPending}
          >
            + New organization
          </Btn>
        }
      />
      <div className="rounded-xl border border-border bg-card p-4 shadow-card">
        <div className="mb-3 text-sm font-semibold">Create organization</div>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-muted-foreground">
            Organization name
          </span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            aria-label="Organization name"
            placeholder="Acme Security"
          />
        </label>
        {createOrg.error ? (
          <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {createOrg.error instanceof Error
              ? createOrg.error.message
              : "Organization creation failed."}
          </div>
        ) : null}
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <div className="rounded-xl border border-border bg-card p-5 shadow-card transition hover:border-primary/40">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-lg bg-gradient-primary text-primary-foreground">
              <Building2 className="h-5 w-5" />
            </div>
            <div>
              <div className="font-semibold">{textOf(org?.name, "Organization")}</div>
              <div className="text-xs text-muted-foreground">{entityId(org ?? {})}</div>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="text-muted-foreground text-xs">Created</div>
              <div className="font-medium">{dateTimeOf(org?.created_at)}</div>
            </div>
            <div>
              <div className="text-muted-foreground text-xs">Status</div>
              <div className="font-medium text-success">Active</div>
            </div>
          </div>
          <div className="mt-4 flex gap-2">
            <Btn variant="outline" size="sm">
              Manage
            </Btn>
            <Btn variant="ghost" size="sm">
              Current
            </Btn>
          </div>
        </div>
      </div>
    </div>
  );
}
