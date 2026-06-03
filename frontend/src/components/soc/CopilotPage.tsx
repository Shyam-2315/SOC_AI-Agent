import * as React from "react";
import { ApiError, backend, type AiCopilotQueryResponse } from "@/lib/api";
import { Bot, DatabaseZap, Send, Sparkles, User } from "lucide-react";
import { Btn } from "./Btn";
import { PageHeader } from "./PageHeader";

const PROMPTS = [
  "Show failed logins",
  "Show high severity alerts",
  "Show DoS incidents",
  "Show blocked IPs",
  "Show MITRE T1110 activity",
  "Is 203.0.113.10 malicious?",
  "Lookup domain evil.example",
  "Show threat feed",
];

type Msg = { role: "user" | "assistant"; content: string };

function formatCopilotResponse(response: AiCopilotQueryResponse): string {
  const count = response.result_preview?.count;
  return [
    `Intent: ${response.intent}`,
    `Suggested query: ${response.backend_endpoint_suggestion}`,
    response.explanation,
    typeof count === "number" ? `Preview count: ${count}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

export function CopilotPage() {
  const [msgs, setMsgs] = React.useState<Msg[]>([
    {
      role: "assistant",
      content:
        "Ask me about failed logins, high severity alerts, DoS incidents, blocked IPs, threat intelligence, hosts, or MITRE techniques.",
    },
  ]);
  const [input, setInput] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<AiCopilotQueryResponse | null>(null);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (ref.current && "scrollTo" in ref.current) {
      ref.current.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
    }
  }, [msgs]);

  async function send(text: string) {
    if (!text.trim() || busy) return;
    setMsgs((m) => [...m, { role: "user", content: text }]);
    setInput("");
    setBusy(true);
    try {
      const response = await backend.aiCopilotQuery(text);
      setLastResult(response);
      setMsgs((m) => [...m, { role: "assistant", content: formatCopilotResponse(response) }]);
    } catch (error) {
      setMsgs((m) => [
        ...m,
        {
          role: "assistant",
          content: error instanceof ApiError ? error.message : "Copilot backend request failed.",
        },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4" data-testid="copilot-page">
      <PageHeader
        eyebrow="Workspace"
        title="Copilot"
        description="Natural-language analyst assistant grounded in your telemetry."
      />

      <div className="grid flex-1 min-h-0 gap-4 lg:grid-cols-[1fr_340px]">
        <div className="flex min-h-0 flex-col rounded-xl border border-border bg-card shadow-card">
          <div ref={ref} className="scrollbar-thin flex-1 space-y-4 overflow-y-auto p-5">
            {msgs.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
                <div
                  className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${m.role === "user" ? "bg-secondary" : "bg-gradient-primary"}`}
                >
                  {m.role === "user" ? (
                    <User className="h-4 w-4" />
                  ) : (
                    <Bot className="h-4 w-4 text-primary-foreground" />
                  )}
                </div>
                <pre
                  className={`max-w-[75%] whitespace-pre-wrap rounded-2xl px-4 py-2.5 text-sm ${m.role === "user" ? "bg-primary text-primary-foreground" : "border border-border bg-background"}`}
                >
                  {m.content}
                </pre>
              </div>
            ))}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(input);
            }}
            className="flex items-center gap-2 border-t border-border p-3"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Copilot..."
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <Btn type="submit" variant="hero" size="md" disabled={busy}>
              <Send className="h-4 w-4" />
            </Btn>
          </form>
        </div>

        <div className="space-y-4">
          <div className="rounded-xl border border-border bg-card p-4 shadow-card">
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
              <Sparkles className="h-4 w-4 text-primary" /> Examples
            </div>
            <div className="space-y-2">
              {PROMPTS.map((prompt) => (
                <button
                  key={prompt}
                  onClick={() => send(prompt)}
                  className="w-full rounded-md border border-border bg-background/40 px-3 py-2 text-left text-sm text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 shadow-card" data-testid="copilot-result-card">
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
              <DatabaseZap className="h-4 w-4 text-primary" /> Query result
            </div>
            {lastResult ? (
              <div className="space-y-3">
                <ResultField label="Intent" value={lastResult.intent} />
                <ResultField label="Suggested backend query" value={lastResult.backend_endpoint_suggestion} mono />
                <ResultField label="Explanation" value={lastResult.explanation} />
                <div>
                  <div className="text-xs uppercase text-muted-foreground">Filters</div>
                  <pre className="mt-1 max-h-32 overflow-auto rounded-md border border-border bg-background/50 p-2 text-xs">
                    {JSON.stringify(lastResult.filters, null, 2)}
                  </pre>
                </div>
                <div>
                  <div className="text-xs uppercase text-muted-foreground">Result preview</div>
                  <pre className="mt-1 max-h-44 overflow-auto rounded-md border border-border bg-background/50 p-2 text-xs">
                    {JSON.stringify(lastResult.result_preview ?? {}, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Run a query to see parsed intent and preview data.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ResultField({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs uppercase text-muted-foreground">{label}</div>
      <div className={`mt-1 text-sm ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}
