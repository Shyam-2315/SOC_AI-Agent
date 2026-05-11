import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { Shield, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/lib/auth";
import { API_BASE_URL } from "@/lib/api";

export const Route = createFileRoute("/login")({
  component: LoginPage,
});

function LoginPage() {
  const { login, token } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [baseUrl, setBaseUrl] = useState(API_BASE_URL);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (token) navigate({ to: "/dashboard" });
  }, [token, navigate]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      if (baseUrl && baseUrl !== API_BASE_URL) {
        localStorage.setItem("api_base_url", baseUrl);
      }
      await login(email, password);
      toast.success("Logged in");
      navigate({ to: "/dashboard" });
    } catch (e: any) {
      toast.error(e?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="absolute inset-0 -z-10 opacity-30 [background-image:radial-gradient(circle_at_30%_20%,oklch(0.78_0.18_165/0.25),transparent_40%),radial-gradient(circle_at_70%_80%,oklch(0.70_0.16_235/0.25),transparent_40%)]" />
      <div className="w-full max-w-md rounded-xl border border-border bg-card/80 p-8 backdrop-blur-md shadow-2xl">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <Shield className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">AI SOC Platform</h1>
            <p className="text-xs text-muted-foreground">Sign in to the operator console</p>
          </div>
        </div>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="api">Backend URL</Label>
            <Input
              id="api"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://127.0.0.1:8000"
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Sign in"}
          </Button>
        </form>
        <p className="mt-6 text-center text-[11px] text-muted-foreground">
          Token is stored locally and attached to all API requests automatically.
        </p>
      </div>
    </div>
  );
}
