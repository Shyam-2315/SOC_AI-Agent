import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { DataTable, type Column } from "@/components/soc/DataTable";
import { Btn } from "@/components/soc/Btn";
import { StatusBadge } from "@/components/soc/SeverityBadge";
import { ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type UserRecord } from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";

export const Route = createFileRoute("/_app/users")({
  head: () => ({ meta: [{ title: "Users — SentinelAI" }] }),
  component: UsersPage,
});

type UserRow = UserRecord & {
  id: string;
  name: string;
};

function UsersPage() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [draft, setDraft] = useState({
    username: "",
    email: "",
    password: "",
    role: "analyst" as UserRecord["role"],
  });
  const users = useQuery({
    queryKey: ["users"],
    queryFn: () => backend.users({ limit: 100 }),
    enabled: canQueryBackend(),
  });
  const updateUser = useMutation({
    mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) =>
      backend.updateUser(id, { disabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });
  const createUser = useMutation({
    mutationFn: (payload: {
      username: string;
      email: string;
      password: string;
      role: UserRecord["role"];
    }) => backend.createUser(payload),
    onSuccess: () => {
      setShowForm(false);
      setDraft({
        username: "",
        email: "",
        password: "",
        role: "analyst",
      });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  if (users.isLoading || users.isPending) return <LoadingState label="Loading users…" />;
  if (users.error)
    return (
      <ErrorState
        message={users.error instanceof Error ? users.error.message : "Could not load users."}
      />
    );

  const rows: UserRow[] = (users.data?.items ?? []).map((user) => ({
    ...user,
    id: entityId(user),
    name: textOf(user.username, user.email),
  }));
  const cols: Column<UserRow>[] = [
    {
      key: "name",
      header: "Name",
      render: (r) => (
        <div className="flex items-center gap-2">
          <div className="grid h-7 w-7 place-items-center rounded-full bg-gradient-primary text-xs font-semibold text-primary-foreground">
            {r.name[0]?.toUpperCase()}
          </div>
          <span className="font-medium">{r.name}</span>
        </div>
      ),
    },
    {
      key: "email",
      header: "Email",
      render: (r) => <span className="font-mono text-xs text-muted-foreground">{r.email}</span>,
    },
    {
      key: "role",
      header: "Role",
      render: (r) => (
        <span className="rounded-md border border-border px-2 py-0.5 text-xs">{r.role}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (r) => <StatusBadge status={r.disabled ? "disabled" : "active"} />,
    },
    {
      key: "actions",
      header: "",
      render: (r) => (
        <Btn
          size="sm"
          variant="ghost"
          onClick={() => updateUser.mutate({ id: r.id, disabled: !r.disabled })}
        >
          {r.disabled ? "Enable" : "Disable"}
        </Btn>
      ),
      className: "text-right",
    },
  ];

  return (
    <div className="space-y-6" data-testid="users-page">
      <PageHeader
        eyebrow="Workspace"
        title="Users"
        description="Members and roles in your organization."
        actions={
          <Btn variant="hero" size="sm" onClick={() => setShowForm((value) => !value)}>
            + Invite user
          </Btn>
        }
      />
      {showForm ? (
        <div className="rounded-xl border border-border bg-card p-4 shadow-card">
          <div className="mb-3 text-sm font-semibold">Invite organization user</div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Display name
              </span>
              <input
                value={draft.username}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, username: event.target.value }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="User display name"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Email</span>
              <input
                value={draft.email}
                onChange={(event) => setDraft((value) => ({ ...value, email: event.target.value }))}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="User email"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Temporary password
              </span>
              <input
                type="password"
                value={draft.password}
                onChange={(event) =>
                  setDraft((value) => ({ ...value, password: event.target.value }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Temporary password"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Role</span>
              <select
                value={draft.role}
                onChange={(event) =>
                  setDraft((value) => ({
                    ...value,
                    role: event.target.value as UserRecord["role"],
                  }))
                }
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="User role"
              >
                {["admin", "analyst", "viewer"].map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <Btn variant="ghost" size="sm" onClick={() => setShowForm(false)}>
              Cancel
            </Btn>
            <Btn
              variant="hero"
              size="sm"
              onClick={() => createUser.mutate(draft)}
              disabled={
                !draft.username.trim() ||
                !draft.email.trim() ||
                draft.password.length < 12 ||
                createUser.isPending
              }
            >
              Invite user
            </Btn>
          </div>
        </div>
      ) : null}
      <DataTable
        rows={rows}
        columns={cols}
        searchPlaceholder="Search users…"
        searchKeys={["name", "email", "role"]}
        emptyTitle="No users"
      />
      {(createUser.error || updateUser.error) && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {(createUser.error ?? updateUser.error) instanceof Error
            ? (createUser.error ?? updateUser.error)?.message
            : "User operation failed."}
        </div>
      )}
    </div>
  );
}
