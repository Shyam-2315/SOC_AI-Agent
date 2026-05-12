import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { DebugPanel } from "@/components/soc/DebugPanel";
import { Sidebar } from "@/components/soc/Sidebar";
import { Topbar } from "@/components/soc/Topbar";
import { getToken } from "@/lib/api";

export const Route = createFileRoute("/_app")({
  beforeLoad: () => {
    if (typeof window !== "undefined" && !getToken()) {
      throw redirect({ to: "/login" });
    }
  },
  component: AppLayout,
});

function AppLayout() {
  return (
    <div className="flex min-h-screen w-full bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 px-4 py-6 md:px-8 md:py-8">
          <Outlet />
        </main>
        <DebugPanel />
      </div>
    </div>
  );
}
