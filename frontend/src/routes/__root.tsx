import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Outlet, createRootRouteWithContext, HeadContent, Scripts } from "@tanstack/react-router";
import { Toaster } from "sonner";

import appCss from "../styles.css?url";
import { AuthProvider } from "@/lib/auth";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "AI SOC Platform — Console" },
      {
        name: "description",
        content:
          "AI SOC Platform operator console: alerts, incidents, SOAR, threat hunting, and Copilot.",
      },
      { name: "color-scheme", content: "dark" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFound,
  errorComponent: ErrorView,
});

function RootShell({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Outlet />
        <Toaster theme="dark" richColors position="top-right" />
      </AuthProvider>
    </QueryClientProvider>
  );
}

function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-primary">404</h1>
        <p className="mt-2 text-muted-foreground">Page not found</p>
        <a href="/dashboard" className="mt-4 inline-block text-primary underline">
          Go to console
        </a>
      </div>
    </div>
  );
}

function ErrorView({ error }: { error: Error }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="max-w-md rounded-lg border border-destructive/40 bg-card p-6 text-center">
        <h2 className="text-lg font-semibold text-destructive">Something went wrong</h2>
        <p className="mt-2 text-sm text-muted-foreground">{error.message}</p>
        <a href="/dashboard" className="mt-4 inline-block text-primary underline text-sm">
          Reload console
        </a>
      </div>
    </div>
  );
}
