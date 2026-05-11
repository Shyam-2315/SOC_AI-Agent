import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Shield,
  Bot,
  Radio,
  Zap,
  Crosshair,
  Bell,
  AlertTriangle,
  Activity,
  ArrowRight,
  Check,
  Github,
  Lock,
  Cpu,
  Network,
  Database,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { getToken } from "@/lib/api";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AI SOC Platform — Autonomous Security Operations" },
      {
        name: "description",
        content:
          "Detect, investigate, and respond to threats in seconds. AI-driven SOC with realtime alerts, SOAR automation, threat hunting, and a security copilot.",
      },
      { property: "og:title", content: "AI SOC Platform — Autonomous Security Operations" },
      {
        property: "og:description",
        content:
          "AI-driven Security Operations Center: realtime detection, MITRE-mapped alerts, SOAR playbooks, and a Copilot that talks your environment.",
      },
    ],
  }),
  component: Landing,
});

const FEATURES = [
  {
    icon: Bell,
    title: "Realtime Detection",
    desc: "Stream logs from any source and get MITRE-mapped alerts the moment they fire.",
  },
  {
    icon: Bot,
    title: "SOC Copilot",
    desc: "Natural-language Q&A across alerts, incidents, IPs, and active campaigns.",
  },
  {
    icon: Zap,
    title: "SOAR Automation",
    desc: "Playbooks block IPs, isolate hosts, and contain threats without a human in the loop.",
  },
  {
    icon: Crosshair,
    title: "Threat Hunting",
    desc: "Pivot through campaigns, attack timelines, and statistics by tactic and technique.",
  },
  {
    icon: Radio,
    title: "Live WebSocket",
    desc: "Subscribe to a live feed of alerts, incidents, and SOAR actions over WS.",
  },
  {
    icon: Lock,
    title: "Zero-Copy Auth",
    desc: "JWT is captured at login and attached automatically — no Swagger token juggling.",
  },
];

const STATS = [
  { value: "<1s", label: "Alert latency" },
  { value: "200+", label: "Detections" },
  { value: "12", label: "Auto-response playbooks" },
  { value: "24/7", label: "Continuous monitoring" },
];

const PIPELINE = [
  { icon: Database, title: "Ingest", desc: "Logs from EDR, firewall, cloud, and apps." },
  { icon: Cpu, title: "Analyze", desc: "ML models score risk and map MITRE ATT&CK." },
  { icon: AlertTriangle, title: "Alert", desc: "Severity-tagged incidents with full context." },
  { icon: Network, title: "Respond", desc: "SOAR runs playbooks and notifies the team." },
];

function Landing() {
  const authed = typeof window !== "undefined" && !!getToken();

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <header className="sticky top-0 z-30 border-b border-border bg-background/70 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
              <Shield className="h-4 w-4" />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold tracking-tight">AI SOC</div>
              <div className="text-[10px] uppercase text-muted-foreground tracking-widest">
                Platform
              </div>
            </div>
          </Link>
          <nav className="hidden md:flex items-center gap-6 text-sm text-muted-foreground">
            <a href="#features" className="hover:text-foreground transition-colors">
              Features
            </a>
            <a href="#pipeline" className="hover:text-foreground transition-colors">
              How it works
            </a>
            <a href="#pricing" className="hover:text-foreground transition-colors">
              Pricing
            </a>
          </nav>
          <div className="flex items-center gap-2">
            {authed ? (
              <Link to="/dashboard">
                <Button size="sm" className="gap-2">
                  Open Console <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </Link>
            ) : (
              <>
                <Link to="/login">
                  <Button size="sm" variant="ghost">
                    Sign in
                  </Button>
                </Link>
                <Link to="/login">
                  <Button size="sm" className="gap-2">
                    Get started <ArrowRight className="h-3.5 w-3.5" />
                  </Button>
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 -z-10 opacity-60 [background-image:radial-gradient(circle_at_20%_10%,oklch(0.78_0.18_165/0.18),transparent_50%),radial-gradient(circle_at_80%_30%,oklch(0.70_0.16_235/0.18),transparent_50%),radial-gradient(circle_at_50%_90%,oklch(0.62_0.26_15/0.12),transparent_55%)]" />
        <div
          className="absolute inset-0 -z-10 opacity-[0.07]"
          style={{
            backgroundImage:
              "linear-gradient(var(--color-border) 1px, transparent 1px), linear-gradient(90deg, var(--color-border) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
        <div className="mx-auto max-w-7xl px-6 py-20 md:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/80 px-3 py-1 text-[11px] font-mono text-muted-foreground backdrop-blur">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-success)] animate-pulse" />
              SOC v1.0 — autonomous detection & response
            </div>
            <h1 className="mt-6 text-4xl font-semibold tracking-tight md:text-6xl">
              Autonomous Security Operations,{" "}
              <span className="bg-gradient-to-r from-primary to-[var(--color-info)] bg-clip-text text-transparent">
                powered by AI
              </span>
            </h1>
            <p className="mt-5 text-base text-muted-foreground md:text-lg">
              Detect, investigate, and respond to threats in seconds. Stream logs, get MITRE-mapped
              alerts, automate playbooks, and ask your SOC Copilot anything — all from one console.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <Link to={authed ? "/dashboard" : "/login"}>
                <Button size="lg" className="gap-2">
                  {authed ? "Open Console" : "Launch Console"} <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
              <a href="#features">
                <Button size="lg" variant="outline" className="gap-2">
                  <Github className="h-4 w-4" /> See features
                </Button>
              </a>
            </div>
            <div className="mt-6 text-[11px] font-mono text-muted-foreground">
              No token juggling. No Swagger. Sign in once.
            </div>
          </div>

          {/* Console preview */}
          <div className="relative mt-16">
            <div className="absolute inset-x-0 -top-10 -z-10 mx-auto h-40 max-w-3xl bg-primary/20 blur-3xl" />
            <div className="mx-auto max-w-5xl overflow-hidden rounded-xl border border-border bg-card/70 shadow-2xl backdrop-blur">
              <div className="flex items-center justify-between border-b border-border bg-sidebar/60 px-4 py-2">
                <div className="flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-destructive/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-[var(--color-warning)]/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-[var(--color-success)]/70" />
                </div>
                <div className="text-[10px] font-mono text-muted-foreground">
                  soc.console — live
                </div>
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-[var(--color-success)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-success)] animate-pulse" />{" "}
                  connected
                </div>
              </div>
              <div className="grid gap-4 p-6 md:grid-cols-3">
                {[
                  {
                    label: "Alerts",
                    value: "1,284",
                    icon: Bell,
                    tone: "text-[var(--color-warning)] bg-[var(--color-warning)]/10",
                  },
                  {
                    label: "Incidents",
                    value: "37",
                    icon: AlertTriangle,
                    tone: "text-destructive bg-destructive/10",
                  },
                  { label: "Actions", value: "612", icon: Zap, tone: "text-primary bg-primary/10" },
                ].map((s) => (
                  <div
                    key={s.label}
                    className="flex items-center justify-between rounded-md border border-border bg-background/60 p-4"
                  >
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                        {s.label}
                      </div>
                      <div className="mt-1 text-2xl font-semibold">{s.value}</div>
                    </div>
                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-md ${s.tone}`}
                    >
                      <s.icon className="h-4 w-4" />
                    </div>
                  </div>
                ))}
              </div>
              <div className="space-y-2 px-6 pb-6 font-mono text-[11px]">
                {[
                  {
                    sev: "CRITICAL",
                    color: "text-destructive border-destructive/30 bg-destructive/10",
                    txt: "ransomware.encrypt detected · host=prod-db-04 · technique=T1486",
                  },
                  {
                    sev: "HIGH",
                    color:
                      "text-[var(--color-critical)] border-[var(--color-critical)]/30 bg-[var(--color-critical)]/10",
                    txt: "lateral_movement · src=10.0.4.21 → dst=10.0.4.99 · T1021",
                  },
                  {
                    sev: "MEDIUM",
                    color:
                      "text-[var(--color-warning)] border-[var(--color-warning)]/30 bg-[var(--color-warning)]/10",
                    txt: "anomalous_login · user=jdoe · geo=RU · risk=0.78",
                  },
                  {
                    sev: "LOW",
                    color:
                      "text-[var(--color-info)] border-[var(--color-info)]/30 bg-[var(--color-info)]/10",
                    txt: "port_scan · src=193.42.18.7 · ports=22,80,443",
                  },
                ].map((row) => (
                  <div
                    key={row.txt}
                    className="flex items-center gap-3 rounded border border-border bg-background/40 px-3 py-2"
                  >
                    <span
                      className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${row.color}`}
                    >
                      {row.sev}
                    </span>
                    <span className="truncate text-muted-foreground">{row.txt}</span>
                    <Activity className="ml-auto h-3 w-3 text-primary animate-pulse" />
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="mt-16 grid gap-4 md:grid-cols-4">
            {STATS.map((s) => (
              <div
                key={s.label}
                className="rounded-lg border border-border bg-card/40 p-5 text-center"
              >
                <div className="text-3xl font-semibold text-primary">{s.value}</div>
                <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">
                  {s.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="border-t border-border">
        <div className="mx-auto max-w-7xl px-6 py-20">
          <div className="mx-auto max-w-2xl text-center">
            <div className="text-[11px] font-mono uppercase tracking-widest text-primary">
              Capabilities
            </div>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">
              Everything your SOC needs
            </h2>
            <p className="mt-3 text-muted-foreground">
              From log ingestion to autonomous response — built for analysts, not Swagger UIs.
            </p>
          </div>
          <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="group relative overflow-hidden rounded-lg border border-border bg-card p-6 transition-colors hover:border-primary/50"
              >
                <div className="absolute inset-x-0 -top-px h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 text-primary">
                  <f.icon className="h-5 w-5" />
                </div>
                <h3 className="mt-4 font-medium">{f.title}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section id="pipeline" className="border-t border-border bg-card/30">
        <div className="mx-auto max-w-7xl px-6 py-20">
          <div className="mx-auto max-w-2xl text-center">
            <div className="text-[11px] font-mono uppercase tracking-widest text-primary">
              How it works
            </div>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">
              Logs in. Threats out. Automatically.
            </h2>
          </div>
          <div className="mt-12 grid gap-4 md:grid-cols-4">
            {PIPELINE.map((step, i) => (
              <div
                key={step.title}
                className="relative rounded-lg border border-border bg-background p-5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/15 text-primary">
                    <step.icon className="h-4 w-4" />
                  </div>
                  <div className="font-mono text-[10px] text-muted-foreground">0{i + 1}</div>
                </div>
                <h3 className="mt-4 text-sm font-medium">{step.title}</h3>
                <p className="mt-1 text-xs text-muted-foreground">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing teaser */}
      <section id="pricing" className="border-t border-border">
        <div className="mx-auto max-w-7xl px-6 py-20">
          <div className="grid gap-6 md:grid-cols-3">
            {[
              {
                name: "Starter",
                price: "Free",
                desc: "For solo analysts evaluating the platform.",
                features: ["Up to 1k events/day", "Alerts & incidents", "Copilot (limited)"],
              },
              {
                name: "Team",
                price: "$499/mo",
                desc: "Production SOC teams running 24/7.",
                features: [
                  "Unlimited events",
                  "SOAR playbooks",
                  "Realtime WebSocket",
                  "MITRE analytics",
                ],
                featured: true,
              },
              {
                name: "Enterprise",
                price: "Talk to us",
                desc: "Air-gapped, multi-tenant, custom playbooks.",
                features: ["Self-hosted", "RBAC + SSO", "Dedicated support"],
              },
            ].map((p) => (
              <div
                key={p.name}
                className={`relative flex flex-col rounded-lg border p-6 ${
                  p.featured
                    ? "border-primary/60 bg-card shadow-[0_0_40px_-15px_oklch(0.78_0.18_165_/_0.5)]"
                    : "border-border bg-card/60"
                }`}
              >
                {p.featured && (
                  <div className="absolute -top-2 left-6 rounded bg-primary px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider text-primary-foreground">
                    Most popular
                  </div>
                )}
                <div className="text-sm font-medium">{p.name}</div>
                <div className="mt-2 text-3xl font-semibold">{p.price}</div>
                <p className="mt-1 text-xs text-muted-foreground">{p.desc}</p>
                <ul className="mt-5 space-y-2 text-sm">
                  {p.features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-muted-foreground">
                      <Check className="h-3.5 w-3.5 text-primary" /> {f}
                    </li>
                  ))}
                </ul>
                <Link to="/login" className="mt-6">
                  <Button variant={p.featured ? "default" : "outline"} className="w-full">
                    Get started
                  </Button>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-border">
        <div className="mx-auto max-w-4xl px-6 py-20 text-center">
          <h2 className="text-3xl font-semibold tracking-tight md:text-4xl">
            Stop juggling tabs. Start running your SOC.
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
            Sign in once and every endpoint — ingestion, alerts, SOAR, hunting, copilot, realtime —
            is a click away.
          </p>
          <div className="mt-7 flex justify-center gap-3">
            <Link to={authed ? "/dashboard" : "/login"}>
              <Button size="lg" className="gap-2">
                {authed ? "Open Console" : "Launch Console"} <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 px-6 py-8 text-xs text-muted-foreground md:flex-row">
          <div className="flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-primary" />
            <span>AI SOC Platform · v1.0</span>
          </div>
          <div className="font-mono">© {new Date().getFullYear()} — Built for defenders.</div>
        </div>
      </footer>
    </div>
  );
}
