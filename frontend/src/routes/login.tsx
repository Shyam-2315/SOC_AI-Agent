import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, ArrowRight, Loader2 } from "lucide-react";
import { Btn } from "@/components/soc/Btn";
import {
  ApiError,
  backend,
  demoAdminEmail,
  demoAdminPassword,
  isDemoMode,
  setToken,
} from "@/lib/api";

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>) => ({
    mode: search.mode === "register" ? "register" : "login",
  }),
  head: () => ({ meta: [{ title: "Sign in — SentinelAI" }] }),
  component: Login,
});

const DEMO = { email: demoAdminEmail(), password: demoAdminPassword() };
type AuthMode = "login" | "register";

function Login() {
  const navigate = useNavigate();
  const search = Route.useSearch();
  const [mode, setMode] = useState<AuthMode>(search.mode);
  const [email, setEmail] = useState(isDemoMode() ? DEMO.email : "");
  const [password, setPassword] = useState(isDemoMode() ? DEMO.password : "");
  const [organizationName, setOrganizationName] = useState("");
  const [username, setUsername] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    setMode(search.mode);
  }, [search.mode]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await backend.login(email, password);
      setToken(res.access_token);
      navigate({ to: "/dashboard" });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Could not reach the auth service. Check that the stack is running.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function register(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSuccess(null);
    try {
      if (registerPassword !== confirmPassword) {
        throw new ApiError("Passwords do not match", 400);
      }
      const organization = await backend.createOrganization(organizationName.trim());
      await backend.register({
        username: username.trim(),
        email: registerEmail.trim(),
        password: registerPassword,
        organization_id: organization.organization_id,
      });
      setEmail(registerEmail.trim());
      setPassword(registerPassword);
      setMode("login");
      setSuccess("Organization created and admin user registered. Sign in with the new user.");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Registration failed. Check the API service and registration settings.",
      );
    } finally {
      setBusy(false);
    }
  }

  function useDemo() {
    setEmail(DEMO.email);
    setPassword(DEMO.password);
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2 bg-gradient-hero">
      <div className="hidden flex-col justify-between border-r border-border bg-card/30 p-10 lg:flex">
        <div className="flex items-center gap-2">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-primary shadow-glow">
            <ShieldCheck className="h-5 w-5 text-primary-foreground" />
          </div>
          <span className="font-semibold">
            Sentinel<span className="text-primary">AI</span>
          </span>
        </div>
        <div>
          <h2 className="text-3xl font-semibold tracking-tight">Autonomous SOC, in one console.</h2>
          <p className="mt-3 max-w-md text-sm text-muted-foreground">
            Triage, investigate and respond at machine speed. Sentinel fuses detection-as-code with
            agentic AI to give your analysts superpowers.
          </p>
        </div>
        <div className="text-xs text-muted-foreground">© 2026 SentinelAI</div>
      </div>
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-md rounded-2xl border border-border bg-card p-7 shadow-card">
          <div className="lg:hidden flex items-center gap-2">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-primary">
              <ShieldCheck className="h-4 w-4 text-primary-foreground" />
            </div>
            <span className="font-semibold">SentinelAI</span>
          </div>
          <div className="mt-5 grid grid-cols-2 rounded-lg border border-border bg-background/50 p-1">
            <button
              type="button"
              onClick={() => {
                setMode("login");
                setError(null);
              }}
              className={`rounded-md px-3 py-2 text-sm transition ${
                mode === "login"
                  ? "bg-card text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Login
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("register");
                setError(null);
              }}
              className={`rounded-md px-3 py-2 text-sm transition ${
                mode === "register"
                  ? "bg-card text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Create organization
            </button>
          </div>

          {mode === "login" ? (
            <form onSubmit={submit} className="mt-5 space-y-5">
              <div>
                <h1 className="text-xl font-semibold">Sign in</h1>
                <p className="mt-1 text-sm text-muted-foreground">Use your organization account.</p>
              </div>
              <div className="space-y-3">
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-muted-foreground">
                    Email
                  </span>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="you@company.com"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-muted-foreground">
                    Password
                  </span>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="Password"
                  />
                </label>
              </div>
              {success && (
                <div className="rounded-md border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">
                  {success}
                </div>
              )}
              {error && (
                <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {error}
                </div>
              )}
              <Btn type="submit" variant="hero" size="lg" className="w-full" disabled={busy}>
                {busy ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    Sign in <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Btn>
              <button
                type="button"
                onClick={() => {
                  setMode("register");
                  setError(null);
                }}
                className="w-full text-center text-sm text-primary hover:underline"
              >
                Create organization / register
              </button>
              {isDemoMode() && (
                <div className="rounded-md border border-dashed border-border bg-background/40 p-3 text-xs">
                  <div className="mb-1 font-semibold uppercase tracking-wider text-muted-foreground">
                    Demo mode
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground">
                    {DEMO.email} · {DEMO.password}
                  </div>
                  <button
                    type="button"
                    onClick={useDemo}
                    className="mt-2 text-primary hover:underline"
                  >
                    Use Demo Admin →
                  </button>
                </div>
              )}
            </form>
          ) : (
            <form onSubmit={register} className="mt-5 space-y-5">
              <div>
                <h1 className="text-xl font-semibold">Create organization</h1>
                <p className="mt-1 text-sm text-muted-foreground">
                  Register the first user for a tenant. The first user is created as admin.
                </p>
              </div>
              <div className="space-y-3">
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-muted-foreground">
                    Organization name
                  </span>
                  <input
                    required
                    minLength={2}
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="Acme Security"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-muted-foreground">
                    Username
                  </span>
                  <input
                    required
                    minLength={2}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="Admin"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-muted-foreground">
                    Email
                  </span>
                  <input
                    type="email"
                    required
                    value={registerEmail}
                    onChange={(e) => setRegisterEmail(e.target.value)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="admin@company.com"
                  />
                </label>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="block">
                    <span className="mb-1 block text-xs font-medium text-muted-foreground">
                      Password
                    </span>
                    <input
                      type="password"
                      required
                      minLength={12}
                      value={registerPassword}
                      onChange={(e) => setRegisterPassword(e.target.value)}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                      placeholder="12+ characters"
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1 block text-xs font-medium text-muted-foreground">
                      Confirm
                    </span>
                    <input
                      type="password"
                      required
                      minLength={12}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                      placeholder="Repeat password"
                    />
                  </label>
                </div>
              </div>
              {error && (
                <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {error}
                </div>
              )}
              <Btn type="submit" variant="hero" size="lg" className="w-full" disabled={busy}>
                {busy ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    Create organization <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Btn>
              <button
                type="button"
                onClick={() => {
                  setMode("login");
                  setError(null);
                }}
                className="w-full text-center text-sm text-primary hover:underline"
              >
                Back to login
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
