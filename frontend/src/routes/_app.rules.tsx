import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader } from "@/components/soc/PageHeader";
import { Btn } from "@/components/soc/Btn";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { EmptyState, ErrorState, LoadingState } from "@/components/soc/States";
import { backend, entityId, type DetectionRuleRecord, type RuleCondition } from "@/lib/api";
import { canQueryBackend, severityOf, textOf } from "@/lib/presentation";
import { Trash2, Plus, X } from "lucide-react";

export const Route = createFileRoute("/_app/rules")({
  head: () => ({ meta: [{ title: "Detection Rules — SentinelAI" }] }),
  component: RulesPage,
});

const FIELDS: RuleCondition["field"][] = [
  "source",
  "event_type",
  "severity",
  "message",
  "ip_address",
];
const OPERATORS: RuleCondition["operator"][] = ["equals", "contains"];

function newRule(): DetectionRuleRecord {
  return {
    id: "",
    name: "New rule",
    description: "Describe the detection logic.",
    severity: "medium",
    event_type: "ssh_attack",
    conditions: [{ field: "message", operator: "contains", value: "failed login" }],
    mitre_tactic: "Credential Access",
    mitre_technique: "T1110",
    enabled: true,
  };
}

function rulePayload(rule: DetectionRuleRecord) {
  return {
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    event_type: rule.event_type || undefined,
    conditions: rule.conditions,
    mitre_tactic: rule.mitre_tactic || undefined,
    mitre_technique: rule.mitre_technique || undefined,
    pack_id: rule.pack_id || undefined,
    enabled: rule.enabled,
  };
}

function RulesPage() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<DetectionRuleRecord | null>(null);
  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: () => backend.rules({ limit: 100 }),
    enabled: canQueryBackend(),
  });
  const saveRule = useMutation({
    mutationFn: (rule: DetectionRuleRecord) => {
      const id = entityId(rule);
      return id ? backend.updateRule(id, rulePayload(rule)) : backend.createRule(rulePayload(rule));
    },
    onSuccess: () => {
      setEditing(null);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const deleteRule = useMutation({
    mutationFn: backend.deleteRule,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });
  const toggleRule = useMutation({
    mutationFn: (rule: DetectionRuleRecord) =>
      backend.updateRule(entityId(rule), { enabled: !rule.enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  if (rules.isLoading || rules.isPending) return <LoadingState label="Loading detection rules…" />;
  if (rules.error)
    return (
      <ErrorState
        message={
          rules.error instanceof Error ? rules.error.message : "Could not load detection rules."
        }
      />
    );

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Detection"
        title="Detection Rules"
        description="Sigma-style rules powering streaming detection."
        actions={
          <Btn variant="hero" size="sm" onClick={() => setEditing(newRule())}>
            <Plus className="h-4 w-4" /> New rule
          </Btn>
        }
      />
      {(saveRule.error || deleteRule.error || toggleRule.error) && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          {(saveRule.error ?? deleteRule.error ?? toggleRule.error) instanceof Error
            ? (saveRule.error ?? deleteRule.error ?? toggleRule.error)?.message
            : "Rule operation failed."}
        </div>
      )}
      <div className="grid gap-3">
        {(rules.data?.items ?? []).length === 0 ? (
          <EmptyState
            title="No detection rules"
            description="Create a rule or import a rule pack to start generating alerts."
          />
        ) : (
          (rules.data?.items ?? []).map((rule) => (
            <div
              key={entityId(rule)}
              className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4 shadow-card md:flex-row md:items-center"
            >
              <button
                onClick={() => toggleRule.mutate(rule)}
                className={`relative h-6 w-11 shrink-0 rounded-full border transition ${rule.enabled ? "border-primary bg-primary/30" : "border-border bg-muted"}`}
              >
                <span
                  className={`absolute top-0.5 h-4 w-4 rounded-full bg-foreground transition ${rule.enabled ? "left-6" : "left-0.5"}`}
                />
              </button>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{rule.name}</span>
                  <SeverityBadge severity={severityOf(rule.severity)} />
                </div>
                <div className="mt-1 text-xs text-muted-foreground">{rule.description}</div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                  {textOf(rule.event_type, "any event")} · {rule.conditions.length} conditions
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Btn size="sm" variant="outline" onClick={() => setEditing(rule)}>
                  Edit
                </Btn>
                <Btn
                  size="sm"
                  variant="ghost"
                  onClick={() => deleteRule.mutate(entityId(rule))}
                  className="text-destructive hover:bg-destructive/10"
                >
                  <Trash2 className="h-4 w-4" />
                </Btn>
              </div>
            </div>
          ))
        )}
      </div>

      {editing && (
        <RuleEditor
          rule={editing}
          busy={saveRule.isPending}
          onClose={() => setEditing(null)}
          onSave={(rule) => saveRule.mutate(rule)}
        />
      )}
    </div>
  );
}

function RuleEditor({
  rule,
  busy,
  onClose,
  onSave,
}: {
  rule: DetectionRuleRecord;
  busy: boolean;
  onClose: () => void;
  onSave: (r: DetectionRuleRecord) => void;
}) {
  const [draft, setDraft] = useState<DetectionRuleRecord>(rule);
  const conds = draft.conditions ?? [];
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-background/70 p-4 backdrop-blur">
      <div className="w-full max-w-xl rounded-xl border border-border bg-card shadow-card">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <div className="text-sm font-semibold">Edit rule</div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-3 p-5">
          <Field label="Name">
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              className="inp"
            />
          </Field>
          <Field label="Description">
            <input
              value={draft.description}
              onChange={(e) => setDraft({ ...draft, description: e.target.value })}
              className="inp"
            />
          </Field>
          <Field label="Severity">
            <select
              value={draft.severity}
              onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
              className="inp"
            >
              {["critical", "high", "medium", "low"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Event type">
            <input
              value={draft.event_type ?? ""}
              onChange={(e) => setDraft({ ...draft, event_type: e.target.value || null })}
              className="inp"
            />
          </Field>
          <div>
            <div className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Conditions
            </div>
            <div className="space-y-2">
              {conds.map((condition, index) => (
                <div key={index} className="grid grid-cols-[1fr_auto_1fr_auto] gap-2">
                  <select
                    value={condition.field}
                    onChange={(e) => {
                      const next = [...conds];
                      next[index] = {
                        ...condition,
                        field: e.target.value as RuleCondition["field"],
                      };
                      setDraft({ ...draft, conditions: next });
                    }}
                    className="inp"
                  >
                    {FIELDS.map((field) => (
                      <option key={field}>{field}</option>
                    ))}
                  </select>
                  <select
                    value={condition.operator}
                    onChange={(e) => {
                      const next = [...conds];
                      next[index] = {
                        ...condition,
                        operator: e.target.value as RuleCondition["operator"],
                      };
                      setDraft({ ...draft, conditions: next });
                    }}
                    className="inp"
                  >
                    {OPERATORS.map((operator) => (
                      <option key={operator}>{operator}</option>
                    ))}
                  </select>
                  <input
                    value={condition.value}
                    placeholder="value"
                    onChange={(e) => {
                      const next = [...conds];
                      next[index] = { ...condition, value: e.target.value };
                      setDraft({ ...draft, conditions: next });
                    }}
                    className="inp"
                  />
                  <button
                    onClick={() =>
                      setDraft({ ...draft, conditions: conds.filter((_, j) => j !== index) })
                    }
                    className="rounded-md border border-border px-2 text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
            <button
              onClick={() =>
                setDraft({
                  ...draft,
                  conditions: [...conds, { field: "message", operator: "contains", value: "" }],
                })
              }
              className="mt-2 text-xs text-primary hover:underline"
            >
              + Add condition
            </button>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Btn variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Btn>
          <Btn variant="hero" size="sm" onClick={() => onSave(draft)} disabled={busy}>
            Save rule
          </Btn>
        </div>
      </div>
      <style>{`.inp{width:100%;border:1px solid var(--color-border);background:var(--color-background);padding:0.5rem 0.75rem;font-size:.875rem;border-radius:.375rem}.inp:focus{outline:none;border-color:var(--color-primary);box-shadow:0 0 0 1px var(--color-primary)}`}</style>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}
