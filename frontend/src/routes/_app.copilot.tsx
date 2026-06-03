import { createFileRoute } from "@tanstack/react-router";
import { CopilotPage } from "@/components/soc/CopilotPage";

export const Route = createFileRoute("/_app/copilot")({
  head: () => ({ meta: [{ title: "Copilot — SentinelAI" }] }),
  component: CopilotPage,
});
