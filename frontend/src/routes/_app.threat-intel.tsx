import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { ThreatIntelLookupCard, ThreatVerdictBadge } from "@/components/soc/ThreatIntel";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, type ThreatIntelLookupResponse } from "@/lib/api";
import { canQueryBackend, textOf } from "@/lib/presentation";
import { Search, ShieldAlert } from "lucide-react";

export const Route = createFileRoute("/_app/threat-intel")({
  head: () => ({ meta: [{ title: "Threat Intel - SentinelAI" }] }),
  component: ThreatIntelPage,
});

export function ThreatIntelPage() {
  const [input, setInput] = useState("203.0.113.10");
  const [result, setResult] = useState<ThreatIntelLookupResponse | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const feed = useQuery({
    queryKey: ["threat-intel", "feed"],
    queryFn: backend.getThreatIntelFeed,
    enabled: canQueryBackend(),
  });

  async function lookup(indicator = input) {
    if (!indicator.trim()) return;
    setBusy(true);
    setLookupError(null);
    try {
      const response = await backend.lookupThreatIntel(indicator.trim());
      setResult(response);
      setInput(indicator.trim());
    } catch (error) {
      setLookupError(error instanceof Error ? error.message : "Threat lookup failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6" data-testid="threat-intel-page">
      <PageHeader
        eyebrow="Intelligence"
        title="Threat Intel"
        description="Deterministic IOC reputation and enrichment from internal demo intelligence."
      />

      <section className="rounded-xl border border-border bg-card p-5 shadow-card">
        <form
          className="flex flex-col gap-3 sm:flex-row"
          onSubmit={(event) => {
            event.preventDefault();
            lookup();
          }}
        >
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="IP, domain, URL, hash, or email"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <Btn type="submit" variant="hero" disabled={busy}>
            <ShieldAlert className="h-4 w-4" />
            Lookup
          </Btn>
        </form>
        <div className="mt-3 flex flex-wrap gap-2">
          {["203.0.113.10", "evil.example", "https://phish.example/login", "44d88612fea8a8f36de82e1278abb02f", "8.8.8.8"].map((ioc) => (
            <button
              key={ioc}
              type="button"
              onClick={() => lookup(ioc)}
              className="rounded-md border border-border px-2 py-1 font-mono text-xs text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
            >
              {ioc}
            </button>
          ))}
        </div>
        {lookupError && <div className="mt-3 text-sm text-destructive">{lookupError}</div>}
      </section>

      {result ? <ThreatIntelLookupCard result={result} /> : null}

      <section className="rounded-xl border border-border bg-card shadow-card">
        <div className="border-b border-border px-5 py-3 text-sm font-semibold">Internal demo feed</div>
        {feed.isLoading ? (
          <LoadingState label="Loading threat feed..." />
        ) : feed.error ? (
          <ErrorState message={feed.error instanceof Error ? feed.error.message : "Could not load feed."} />
        ) : (feed.data?.items ?? []).length === 0 ? (
          <div className="p-5">
            <EmptyState title="No feed indicators" description="No deterministic feed entries are available." />
          </div>
        ) : (
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-background/30 text-left text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-3 font-medium">Indicator</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Verdict</th>
                  <th className="px-4 py-3 font-medium">Score</th>
                  <th className="px-4 py-3 font-medium">Tags</th>
                </tr>
              </thead>
              <tbody>
                {(feed.data?.items ?? []).map((item) => (
                  <tr key={`${item.type}-${item.indicator}`} className="border-t border-border/60">
                    <td className="px-4 py-3 font-mono text-xs">{item.indicator}</td>
                    <td className="px-4 py-3">{item.type}</td>
                    <td className="px-4 py-3">
                      <ThreatVerdictBadge verdict={item.verdict} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{item.reputation_score}</td>
                    <td className="px-4 py-3 text-muted-foreground">{textOf(item.tags.join(", "), "none")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
