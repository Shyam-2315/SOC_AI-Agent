import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldCheck, Zap, Bot, Activity, Lock, ArrowRight, Cpu, Eye, Network } from "lucide-react";
import { Btn } from "@/components/soc/Btn";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SentinelAI — Autonomous AI SOC Platform" },
      {
        name: "description",
        content:
          "Autonomous security operations powered by AI. Detect, investigate and respond to threats at machine speed.",
      },
      { property: "og:title", content: "SentinelAI — Autonomous AI SOC Platform" },
      { property: "og:description", content: "Autonomous security operations powered by AI." },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen bg-gradient-hero text-foreground">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Link to="/" className="flex items-center gap-2">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-primary shadow-glow">
            <ShieldCheck className="h-5 w-5 text-primary-foreground" />
          </div>
          <span className="font-semibold">
            Sentinel<span className="text-primary">AI</span>
          </span>
        </Link>
        <nav className="hidden items-center gap-7 text-sm text-muted-foreground md:flex">
          <a href="#features" className="hover:text-foreground">
            Features
          </a>
          <a href="#architecture" className="hover:text-foreground">
            Architecture
          </a>
          <a href="#stack" className="hover:text-foreground">
            Platform
          </a>
        </nav>
        <div className="flex items-center gap-2">
          <Link to="/login">
            <Btn variant="ghost" size="sm">
              Sign in
            </Btn>
          </Link>
          <a href="/login?mode=register">
            <Btn variant="hero" size="sm">
              Create organization <ArrowRight className="h-4 w-4" />
            </Btn>
          </a>
        </div>
      </header>

      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-grid opacity-[0.4]" />
        <div className="relative mx-auto max-w-7xl px-6 py-24 text-center">
          <div className="mx-auto mb-5 inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground backdrop-blur">
            <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" /> Now live:
            Autonomous Tier-1 triage
          </div>
          <h1 className="mx-auto max-w-4xl text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
            AI SOC for your own <span className="text-gradient">tenant data</span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-base text-muted-foreground md:text-lg">
            Create an organization, register the first admin, then connect collectors, detections,
            SOAR and Copilot to real backend APIs.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <a href="/login?mode=register">
              <Btn variant="hero" size="lg">
                Create organization <ArrowRight className="h-4 w-4" />
              </Btn>
            </a>
            <Link to="/login">
              <Btn variant="outline" size="lg">
                Sign in
              </Btn>
            </Link>
          </div>
          <div className="mx-auto mt-14 grid max-w-4xl grid-cols-2 gap-3 text-left md:grid-cols-4">
            {[
              ["1", "Create organization"],
              ["2", "Register first admin"],
              ["3", "Login with your user"],
              ["4", "Connect tenant data"],
            ].map(([v, l]) => (
              <div key={l} className="rounded-xl border border-border bg-card/60 p-4 backdrop-blur">
                <div className="text-2xl font-semibold">{v}</div>
                <div className="text-xs text-muted-foreground">{l}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="features" className="mx-auto max-w-7xl px-6 py-20">
        <div className="mb-12 text-center">
          <div className="text-xs font-medium uppercase tracking-widest text-primary">
            Capabilities
          </div>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">
            A complete SOC, in one console
          </h2>
        </div>
        <div className="grid gap-5 md:grid-cols-3">
          {[
            {
              icon: Eye,
              title: "AI Detection",
              desc: "Sigma-style rule packs, behavioral baselines and ML anomaly detection out of the box.",
            },
            {
              icon: Zap,
              title: "SOAR & Playbooks",
              desc: "Block IPs, isolate hosts, revoke sessions — automatically and auditable.",
            },
            {
              icon: Bot,
              title: "Copilot Analyst",
              desc: "Ask questions in natural language. Get answers grounded in your telemetry.",
            },
            {
              icon: Activity,
              title: "Realtime Streams",
              desc: "Live websocket feed of every alert and response action across your estate.",
            },
            {
              icon: Network,
              title: "Universal Collectors",
              desc: "Ingest from EDR, cloud trails, firewalls, k8s and custom sources.",
            },
            {
              icon: Cpu,
              title: "Threat Hunting",
              desc: "Pivot across IOCs, MITRE tactics and campaigns with one query.",
            },
          ].map((f) => (
            <div
              key={f.title}
              className="group rounded-xl border border-border bg-card p-6 shadow-card transition hover:border-primary/40"
            >
              <div className="mb-3 inline-grid h-10 w-10 place-items-center rounded-lg bg-primary/10 text-primary">
                <f.icon className="h-5 w-5" />
              </div>
              <div className="text-base font-semibold">{f.title}</div>
              <p className="mt-1 text-sm text-muted-foreground">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="architecture" className="border-y border-border bg-card/30">
        <div className="mx-auto max-w-7xl px-6 py-20">
          <div className="grid items-center gap-10 md:grid-cols-2">
            <div>
              <div className="text-xs font-medium uppercase tracking-widest text-primary">
                Architecture
              </div>
              <h2 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">
                Built for scale, designed for analysts
              </h2>
              <p className="mt-3 text-muted-foreground">
                A streaming detection engine, an agentic AI tier and an open SOAR layer —
                composable, multi-tenant, and deployable to your cloud.
              </p>
              <ul className="mt-5 space-y-2 text-sm">
                {[
                  "Multi-tenant orgs & RBAC",
                  "Sigma-compatible rule engine",
                  "Pluggable LLM providers",
                  "Audit-grade SOAR actions",
                ].map((x) => (
                  <li key={x} className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-primary" /> {x}
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-2xl border border-border bg-card p-5 shadow-card">
              <pre className="scrollbar-thin overflow-auto rounded-lg bg-background/60 p-4 text-xs leading-relaxed text-muted-foreground">
                {`Collectors ──┐
EDR / FW / K8s│   ┌──────────────┐    ┌────────────┐
Cloud Trails  ├──▶│ Stream Engine├──▶│ Detections │
Suricata     ─┘   └──────┬───────┘    └─────┬──────┘
                          ▼                  ▼
                    ┌──────────┐       ┌──────────┐
                    │  Copilot │◀─────▶│  SOAR    │
                    │  (LLM)   │       │  Engine  │
                    └────┬─────┘       └────┬─────┘
                         ▼                   ▼
                   Analyst Console     Response (block/iso)
`}
              </pre>
            </div>
          </div>
        </div>
      </section>

      <section id="stack" className="mx-auto max-w-7xl px-6 py-24 text-center">
        <h2 className="text-3xl font-semibold tracking-tight md:text-4xl">
          Ready to use your own tenant?
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
          Start with real organization registration, or sign in if your tenant already exists.
        </p>
        <div className="mt-7 flex flex-wrap justify-center gap-3">
          <a href="/login?mode=register">
            <Btn variant="hero" size="lg">
              Create organization <ArrowRight className="h-4 w-4" />
            </Btn>
          </a>
          <Link to="/login">
            <Btn variant="outline" size="lg">
              Sign in
            </Btn>
          </Link>
        </div>
      </section>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 px-6 py-6 text-xs text-muted-foreground md:flex-row">
          <div>© 2026 SentinelAI · Real tenant onboarding enabled</div>
          <div className="font-mono">v1.0.0</div>
        </div>
      </footer>
    </div>
  );
}
