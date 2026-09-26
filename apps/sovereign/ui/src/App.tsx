// Callers: src/main.tsx.
// API: `App`: connects to the local service, shows onboarding until Sovereign is set up and
// has a project, then the workspace. Live updates come from the event stream.
// Schema: SessionResponse, SetupStatus, ProjectsResponse from control-api-v2.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "./api/client";
import { useLiveUpdates, useProjects, useSession, useSetup } from "./api/query";
import { BrandMark, Button, Spinner, ToastProvider } from "./components/ui";
import { Onboarding } from "./screens/Onboarding";
import { Workspace } from "./screens/Workspace";

const ONBOARDING_KEY = "sovereign.onboarding.done";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: true, retry: 1 } },
});

function readFlag(key: string): boolean {
  try {
    return window.localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key: string): void {
  try {
    window.localStorage.setItem(key, "1");
  } catch {
    // Private windows may refuse storage; onboarding then shows again next time.
  }
}

function Offline({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const expired = error instanceof ApiError && error.status === 401;
  return (
    <main className="offline">
      <BrandMark className="brand-mark" />
      <h1>{expired ? "This page needs a fresh link" : "Sovereign isn't running"}</h1>
      <p className="muted">
        Open Terminal and type <code>sovereign</code>. It starts Sovereign and opens this page again.
      </p>
      <div>
        <Button onClick={onRetry}>Try again</Button>
      </div>
    </main>
  );
}

function Shell() {
  const session = useSession();
  const ready = session.isSuccess;
  const setup = useSetup(ready);
  const projects = useProjects(ready);
  useLiveUpdates(ready);
  const [onboarded, setOnboarded] = useState(() => readFlag(ONBOARDING_KEY));
  const [showSetup, setShowSetup] = useState(false);

  if (session.isError) {
    return <Offline error={session.error} onRetry={() => void session.refetch()} />;
  }
  if (!ready || setup.isPending || projects.isPending) {
    return (
      <main className="offline">
        <Spinner label="Opening Sovereign" />
      </main>
    );
  }
  const hasProjects = (projects.data?.projects.length ?? 0) > 0;
  const needsOnboarding = showSetup || (!onboarded && (!setup.data?.ready || !hasProjects));
  if (needsOnboarding) {
    return (
      <Onboarding
        setup={setup.data}
        hasProjects={hasProjects}
        initialStep={showSetup ? 1 : 0}
        onRecheck={() => void setup.refetch()}
        onDone={() => {
          writeFlag(ONBOARDING_KEY);
          setOnboarded(true);
          setShowSetup(false);
        }}
      />
    );
  }
  return <Workspace setup={setup.data} onOpenSetup={() => setShowSetup(true)} />;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <Shell />
      </ToastProvider>
    </QueryClientProvider>
  );
}
