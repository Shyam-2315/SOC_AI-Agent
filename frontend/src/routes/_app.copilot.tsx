import { createFileRoute } from "@tanstack/react-router";
import { useState, useRef, useEffect } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { ApiError, backend } from "@/lib/api";
import { Bot, Send, Sparkles, User } from "lucide-react";

export const Route = createFileRoute("/_app/copilot")({
  head: () => ({ meta: [{ title: "Copilot — SentinelAI" }] }),
  component: CopilotPage,
});

const PROMPTS = [
  "summary overview",
  "Show critical alerts",
  "Show malware alerts",
  "MITRE analysis",
  "dangerous ip",
];

type Msg = { role: "user" | "assistant"; content: string };

function formatCopilotResponse(response: Record<string, unknown>): string {
  if (typeof response.message === "string") return response.message;
  if (response.summary && typeof response.summary === "object") {
    const summary = response.summary as Record<string, unknown>;
    return [
      `Total alerts: ${summary.total_alerts ?? 0}`,
      `Critical alerts: ${summary.critical_alerts ?? 0}`,
      `Open incidents: ${summary.open_incidents ?? 0}`,
      `Top dangerous IPs: ${JSON.stringify(summary.top_dangerous_ips ?? [])}`,
    ].join("\n");
  }
  if (Array.isArray(response.results)) {
    return response.results.length
      ? JSON.stringify(response.results.slice(0, 10), null, 2)
      : "No matching backend results.";
  }
  return JSON.stringify(response, null, 2);
}

function CopilotPage() {
  const [msgs, setMsgs] = useState<Msg[]>([
    {
      role: "assistant",
      content:
        "Ask me about summaries, critical alerts, malware, ransomware, MITRE, or dangerous IPs.",
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [msgs]);

  async function send(text: string) {
    if (!text.trim() || busy) return;
    setMsgs((m) => [...m, { role: "user", content: text }]);
    setInput("");
    setBusy(true);
    try {
      const response = await backend.askCopilot(text);
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
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4">
      <PageHeader
        eyebrow="Workspace"
        title="Copilot"
        description="Natural-language analyst assistant grounded in your telemetry."
      />

      <div className="grid flex-1 min-h-0 gap-4 lg:grid-cols-[1fr_280px]">
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
              placeholder="Ask Copilot…"
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <Btn type="submit" variant="hero" size="md" disabled={busy}>
              <Send className="h-4 w-4" />
            </Btn>
          </form>
        </div>

        <div className="rounded-xl border border-border bg-card p-4 shadow-card">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Sparkles className="h-4 w-4 text-primary" /> Example prompts
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
      </div>
    </div>
  );
}
