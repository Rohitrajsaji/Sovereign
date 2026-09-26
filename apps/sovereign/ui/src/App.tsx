// Callers: src/main.tsx.
// API: HashRouter screens plus TanStack Query and SSE invalidation.
// Schema: schemas/control-api-v2.json.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Prioritize turning the existing SPA into the exceptional polished Sovereign UI specified by the plan.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { HashRouter, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useDoctor, useInvalidateOnEvents, useProjects, useSession, useSettings } from "./api/query";
import { AppShell, CommandPalette, OfflineState, Toast } from "./components/ui";
import { WelcomeScreen } from "./screens/Welcome";
import {
  ApprovalsScreen,
  DiagnosticsScreen,
  GoalDetailScreen,
  GoalsScreen,
  HomeScreen,
  ProjectsScreen,
  RecoveryScreen,
  SettingsScreen,
} from "./screens/Workspace";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
});

function Shell() {
  const navigate = useNavigate();
  const session = useSession();
  const ready = session.isSuccess;
  const doctor = useDoctor(ready);
  const projects = useProjects(ready);
  const settings = useSettings(ready);
  const [palette, setPalette] = useState(false);
  const [toast, setToast] = useState("Connecting to the local Controller.");
  useInvalidateOnEvents(ready);

  useEffect(() => {
    document.documentElement.dataset.theme = localStorage.getItem("sovereign-theme") ?? "system";
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (session.isError) {
      setToast("Offline. The local Controller did not answer.");
    } else if (session.isSuccess) {
      setToast("Connected to the local Controller.");
    }
  }, [session.isError, session.isSuccess]);

  const needsOnboarding = useMemo(() => {
    const doctorFailed = (doctor.data ?? []).some((check) => check.status === "fail");
    const noProjects = (projects.data?.projects.length ?? 0) === 0;
    const noModel = !settings.data?.model_path;
    return doctorFailed || noProjects || noModel;
  }, [doctor.data, projects.data, settings.data]);

  return (
    <AppShell message={toast} onOpenPalette={() => setPalette(true)}>
      {session.isError ? <OfflineState /> : null}
      <Routes>
        <Route path="/welcome" element={<WelcomeScreen ready={ready} />} />
        <Route path="/" element={needsOnboarding && ready ? <Navigate to="/welcome" replace /> : <HomeScreen ready={ready} />} />
        <Route path="/projects" element={<ProjectsScreen ready={ready} />} />
        <Route path="/goals" element={<GoalsScreen ready={ready} />} />
        <Route path="/goals/new" element={<GoalsScreen ready={ready} />} />
        <Route path="/goals/:id" element={<GoalDetailScreen ready={ready} />} />
        <Route path="/approvals" element={<ApprovalsScreen ready={ready} />} />
        <Route path="/recovery" element={<RecoveryScreen ready={ready} />} />
        <Route path="/settings" element={<SettingsScreen ready={ready} />} />
        <Route path="/diagnostics" element={<DiagnosticsScreen ready={ready} />} />
      </Routes>
      <Toast message={toast} />
      <CommandPalette open={palette} onClose={() => setPalette(false)} onNavigate={navigate} />
    </AppShell>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Shell />
      </HashRouter>
    </QueryClientProvider>
  );
}
