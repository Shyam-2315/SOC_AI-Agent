import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Plus, RefreshCw, Loader2, ShieldAlert, Pencil } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, ENDPOINTS, ApiError } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/users")({
  component: UsersPage,
});

const ROLES = ["admin", "analyst", "viewer"];

function UsersPage() {
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<any>(null);
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    role: "analyst",
    disabled: false,
  });
  const [busy, setBusy] = useState(false);

  async function load() {
    setLoading(true);
    setForbidden(false);
    try {
      const data = await api<any>(ENDPOINTS.users);
      setUsers(Array.isArray(data) ? data : data?.items || data?.users || []);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setForbidden(true);
      } else if (e instanceof ApiError && e.status === 404) {
        toast.error("Users endpoint not available");
      } else {
        toast.error((e as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function startCreate() {
    setEditing(null);
    setForm({ username: "", email: "", password: "", role: "analyst", disabled: false });
    setOpen(true);
  }
  function startEdit(u: any) {
    setEditing(u);
    setForm({
      username: u.username || "",
      email: u.email || "",
      password: "",
      role: u.role || "analyst",
      disabled: Boolean(u.disabled),
    });
    setOpen(true);
  }

  async function save() {
    setBusy(true);
    try {
      if (editing) {
        await api(ENDPOINTS.updateUser(editing.id), {
          method: "PATCH",
          body: { role: form.role, disabled: form.disabled },
        });
        toast.success("User updated");
      } else {
        await api(ENDPOINTS.createUser, {
          method: "POST",
          body: {
            username: form.username || form.email.split("@")[0],
            email: form.email,
            password: form.password,
            role: form.role,
          },
        });
        toast.success("User created");
      }
      setOpen(false);
      load();
    } catch (e: any) {
      toast.error(e?.message || "Failed");
    } finally {
      setBusy(false);
    }
  }

  if (forbidden) {
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
        <ShieldAlert className="h-10 w-10 text-destructive" />
        <h2 className="text-lg font-semibold">Admin only</h2>
        <p className="text-sm text-muted-foreground">
          Your role does not have access to user management.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
          <p className="text-sm text-muted-foreground">{users.length} users</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load} className="gap-2">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button size="sm" onClick={startCreate} className="gap-2">
            <Plus className="h-3.5 w-3.5" /> New user
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-sm text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              )}
              {!loading && users.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-sm text-muted-foreground">
                    No users
                  </TableCell>
                </TableRow>
              )}
              {users.map((u, i) => (
                <TableRow key={u.id ?? i}>
                  <TableCell className="text-sm">{u.email || u.username}</TableCell>
                  <TableCell>
                    <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[10px] font-mono uppercase text-primary">
                      {u.role || "—"}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {u.created_at || "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => startEdit(u)}
                      className="gap-1"
                    >
                      <Pencil className="h-3 w-3" /> Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          <span />
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? "Edit user" : "Create user"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label>Username</Label>
              <Input
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                disabled={Boolean(editing)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Email</Label>
              <Input
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                disabled={Boolean(editing)}
              />
            </div>
            {!editing && (
              <div className="space-y-1.5">
                <Label>{editing ? "New password (optional)" : "Password"}</Label>
                <Input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                />
              </div>
            )}
            <div className="space-y-1.5">
              <Label>Role</Label>
              <select
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}
                className="h-9 w-full rounded-md border border-border bg-input px-2 text-sm"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
            {editing && (
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.disabled}
                  onChange={(e) => setForm({ ...form, disabled: e.target.checked })}
                />
                Disabled
              </label>
            )}
          </div>
          <DialogFooter>
            <Button onClick={save} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
