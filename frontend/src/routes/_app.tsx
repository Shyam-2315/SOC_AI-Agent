import { createFileRoute, redirect, Outlet } from "@tanstack/react-router";
import { AppSidebar } from "@/components/AppSidebar";
import { TopBar } from "@/components/TopBar";
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
    <div className="flex min-h-screen w-full bg-background text-foreground">
      <AppSidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
