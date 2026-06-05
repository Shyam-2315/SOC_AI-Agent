import { createFileRoute } from "@tanstack/react-router";
import { PacksPage } from "./_app.packs";

export const Route = createFileRoute("/_app/rule-packs")({
  head: () => ({ meta: [{ title: "Rule Packs - SentinelAI" }] }),
  component: PacksPage,
});
