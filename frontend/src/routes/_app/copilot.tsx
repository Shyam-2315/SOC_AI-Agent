import { createFileRoute } from "@tanstack/react-router";
import { useState, useRef, useEffect } from "react";
import { Bot, Send, User as UserIcon, Loader2, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { api, ENDPOINTS } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/copilot")({
  component: CopilotPage,
});

type Msg = { role: "user" | "assistant"; content: string; raw?: any };
type CopilotRequest = { query: string };

const QUICK = [
  "Show critical alerts",
  "Summarize malware activity",
  "MITRE analysis",
  "Show dangerous IPs",
  "SOC summary",
];

function CopilotPage() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  async function send(text?: string) {
    const q = (text ?? input).trim();
    if (!q) return;
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setLoading(true);
    try {
      const res = await api<any>(ENDPOINTS.copilot, {
        method: "POST",
        body: { query: q } satisfies CopilotRequest,
      });
      const content =
        res?.response ||
        res?.answer ||
        res?.message ||
        res?.result ||
        res?.text ||
        (typeof res === "string" ? res : JSON.stringify(res, null, 2));
      setMessages((m) => [...m, { role: "assistant", content, raw: res }]);
    } catch (e: any) {
      const message = e?.message || "Copilot error";
      toast.error(message);
      setMessages((m) => [...m, { role: "assistant", content: `Error: ${message}` }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" /> AI SOC Copilot
        </h1>
        <p className="text-sm text-muted-foreground">Ask questions about your environment.</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {QUICK.map((q) => (
          <Button key={q} size="sm" variant="outline" onClick={() => send(q)} disabled={loading}>
            {q}
          </Button>
        ))}
      </div>

      <Card className="flex-1 overflow-hidden">
        <CardContent className="flex h-full flex-col p-0">
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 && (
              <div className="flex h-full items-center justify-center text-center text-muted-foreground">
                <div>
                  <Bot className="mx-auto mb-2 h-8 w-8 text-primary/60" />
                  <div className="text-sm">Ask the SOC Copilot anything.</div>
                </div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
                {m.role === "assistant" && (
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
                    <Bot className="h-4 w-4" />
                  </div>
                )}
                <div
                  className={`max-w-[75%] rounded-lg px-4 py-2.5 text-sm whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : "bg-secondary text-foreground"
                  }`}
                >
                  {m.content}
                </div>
                {m.role === "user" && (
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-secondary text-foreground">
                    <UserIcon className="h-4 w-4" />
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
                  <Bot className="h-4 w-4" />
                </div>
                <div className="rounded-lg bg-secondary px-4 py-2.5 text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" />
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>
          <div className="border-t border-border p-3">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send();
              }}
              className="flex gap-2"
            >
              <Textarea
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                placeholder="Ask the Copilot…"
                className="min-h-[40px] resize-none"
              />
              <Button type="submit" disabled={loading || !input.trim()} className="gap-2">
                <Send className="h-4 w-4" />
              </Button>
            </form>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
