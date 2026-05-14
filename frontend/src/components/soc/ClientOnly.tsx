import type { ReactNode } from "react";
import { useMounted } from "@/hooks/use-mounted";
import { dateTimeOf, timeOf } from "@/lib/presentation";

export function ClientOnly({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return useMounted() ? children : fallback;
}

export function ClientDateTime({
  value,
  fallback = "—",
}: {
  value: unknown;
  fallback?: ReactNode;
}) {
  const mounted = useMounted();
  return mounted ? dateTimeOf(value) : fallback;
}

export function ClientTime({ value, fallback = "—" }: { value: unknown; fallback?: ReactNode }) {
  const mounted = useMounted();
  return mounted ? timeOf(value) : fallback;
}
