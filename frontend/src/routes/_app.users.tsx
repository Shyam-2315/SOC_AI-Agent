import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
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

  function invite() {
    const email = window.prompt("User email");
    if (!email?.trim()) return;
    const username = window.prompt("Display name", email.split("@")[0]) || email;
    const password = window.prompt("Temporary password (12+ characters)");
    if (!password) return;
    createUser.mutate({ username, email, password, role: "analyst" });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace"
        title="Users"
        description="Members and roles in your organization."
        actions={
          <Btn variant="hero" size="sm" onClick={invite}>
            + Invite user
          </Btn>
        }
      />
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
