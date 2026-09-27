// Callers: the app shell, onboarding, conversation, side panel, and settings.
// API: typed /v2 queries and mutations. The event stream refreshes what changes with work.
// Schema: schemas/control-api-v2.json (types in ./generated).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { api, connectEvents, setCsrfToken } from "./client";
import type {
  DeveloperToolsInstallResponse,
  DoctorResponse,
  DownloadResponse,
  GoalActivityResponse,
  GoalIntent,
  GoalView,
  OverviewResponse,
  PreviewResponse,
  ProjectFileContent,
  ProjectFilesResponse,
  ProjectOpenResponse,
  ProjectsResponse,
  QueuedCommandResponse,
  LandingRecord,
  ModelRemoveResponse,
  ModelSelectResponse,
  SessionResponse,
  StartAnywayResponse,
  SettingsV1,
  SetupStatus,
} from "./generated";

export const keys = {
  session: ["session"] as const,
  setup: ["setup"] as const,
  overview: ["overview"] as const,
  doctor: ["doctor"] as const,
  projects: ["projects"] as const,
  goals: ["goals"] as const,
  activity: (id: string) => ["activity", id] as const,
  preview: ["preview"] as const,
  files: ["files"] as const,
  file: (path: string) => ["file", path] as const,
  settings: ["settings"] as const,
};

/** A command the service accepted but will apply after the current step. */
export function isQueued(value: unknown): value is QueuedCommandResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    "applied" in value &&
    (value as QueuedCommandResponse).applied === false
  );
}

const WORKING_POLL_MS = 1500;

export function useSession() {
  return useQuery({
    queryKey: keys.session,
    queryFn: async () => {
      const session = await api<SessionResponse>("/v2/session");
      setCsrfToken(session.csrf_token);
      return session;
    },
    retry: 1,
  });
}

export function useSetup(enabled: boolean) {
  return useQuery({
    queryKey: keys.setup,
    queryFn: () => api<SetupStatus>("/v2/setup"),
    enabled,
    refetchInterval: (query) => {
      const phase = query.state.data?.download.phase;
      return phase && ["checking", "downloading_runtime", "downloading_model", "verifying"].includes(phase)
        ? 1000
        : false;
    },
  });
}

function anyGoalRunning(goals: GoalView[] | undefined): boolean {
  return (goals ?? []).some((goal) => !goal.progress.terminal);
}

/**
 * True while a chosen project waits for the current step to finish. Until then the service still
 * reads the previous project, so its requests, preview, and files are not this project's.
 */
export function isSwitchingProject(overview: OverviewResponse | undefined): boolean {
  return (overview?.pending_commands ?? []).some((command) => command.kind === "switch_project");
}

export function useOverview(enabled: boolean) {
  return useQuery({
    queryKey: keys.overview,
    queryFn: () => api<OverviewResponse>("/v2/overview"),
    enabled,
    refetchInterval: (query) =>
      query.state.data?.working || isSwitchingProject(query.state.data) ? WORKING_POLL_MS : false,
  });
}

/** Reloads everything once a project switch that had to wait is applied. */
export function useProjectSwitchRefresh(switching: boolean) {
  const client = useQueryClient();
  const previous = useRef(switching);
  useEffect(() => {
    if (previous.current && !switching) {
      void client.invalidateQueries();
    }
    previous.current = switching;
  }, [client, switching]);
}

export function useGoals(enabled: boolean) {
  return useQuery({
    queryKey: keys.goals,
    queryFn: () => api<GoalView[]>("/v2/goals"),
    enabled,
    // Progress inside a long step (a model call) produces no events, so poll while working.
    refetchInterval: (query) => (anyGoalRunning(query.state.data) ? WORKING_POLL_MS : false),
  });
}

export function useGoalActivity(goalId: string | undefined) {
  return useQuery({
    queryKey: keys.activity(goalId ?? ""),
    queryFn: () => api<GoalActivityResponse>(`/v2/goals/${encodeURIComponent(goalId ?? "")}/activity`),
    enabled: Boolean(goalId) && !goalId?.startsWith("pending-"),
  });
}

export function useProjects(enabled: boolean) {
  return useQuery({
    queryKey: keys.projects,
    queryFn: () => api<ProjectsResponse>("/v2/projects"),
    enabled,
  });
}

export function usePreview(enabled: boolean) {
  return useQuery({
    queryKey: keys.preview,
    queryFn: () => api<PreviewResponse>("/v2/preview"),
    enabled,
  });
}

export function useFiles(enabled: boolean) {
  return useQuery({
    queryKey: keys.files,
    queryFn: () => api<ProjectFilesResponse>("/v2/files"),
    enabled,
  });
}

export function useFileContent(path: string | undefined) {
  return useQuery({
    queryKey: keys.file(path ?? ""),
    queryFn: () => api<ProjectFileContent>(`/v2/files/content?path=${encodeURIComponent(path ?? "")}`),
    enabled: Boolean(path),
  });
}

export function useDoctor(enabled: boolean) {
  return useQuery({
    queryKey: keys.doctor,
    queryFn: () => api<DoctorResponse>("/v2/doctor"),
    enabled,
  });
}

export function useSettings(enabled: boolean) {
  return useQuery({
    queryKey: keys.settings,
    queryFn: () => api<SettingsV1>("/v2/settings"),
    enabled,
  });
}

/** Refreshes work-related views whenever the Controller records an event. */
export function useLiveUpdates(ready: boolean) {
  const client = useQueryClient();
  useEffect(() => {
    if (!ready) {
      return;
    }
    return connectEvents(() => {
      void client.invalidateQueries({ queryKey: keys.goals });
      void client.invalidateQueries({ queryKey: keys.overview });
      void client.invalidateQueries({ queryKey: ["activity"] });
    });
  }, [client, ready]);
}

function useRefreshWork() {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: keys.goals });
    void client.invalidateQueries({ queryKey: keys.overview });
  };
}

export function useSubmitGoal() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: (goal: string) =>
      api<GoalIntent | QueuedCommandResponse>("/v2/goals", {
        method: "POST",
        body: JSON.stringify({ goal }),
      }),
    onSuccess: refresh,
  });
}

export function useCancelGoal() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: (goalId: string) =>
      api<GoalIntent | QueuedCommandResponse>(`/v2/goals/${encodeURIComponent(goalId)}/cancel`, {
        method: "POST",
        body: "{}",
      }),
    onSuccess: refresh,
  });
}

function useLandingAction(action: "undo" | "apply") {
  const client = useQueryClient();
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: (goalId: string) =>
      api<LandingRecord | QueuedCommandResponse>(`/v2/goals/${encodeURIComponent(goalId)}/${action}`, {
        method: "POST",
        body: "{}",
      }),
    onSuccess: () => {
      refresh();
      void client.invalidateQueries({ queryKey: keys.files });
      void client.invalidateQueries({ queryKey: ["file"] });
    },
  });
}

export function useUndoGoal() {
  return useLandingAction("undo");
}

export function useApplyGoal() {
  return useLandingAction("apply");
}

export function useRespondApproval() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: (body: { request_id: string; decision: "approve" | "deny"; principal: string }) =>
      api("/v2/approvals/respond", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: refresh,
  });
}

function useProjectChange() {
  const client = useQueryClient();
  return () => {
    // Everything shown belongs to the active project.
    void client.invalidateQueries();
  };
}

export function useCreateProject() {
  const changed = useProjectChange();
  return useMutation({
    mutationFn: (name: string) =>
      api<ProjectOpenResponse>("/v2/projects/create", { method: "POST", body: JSON.stringify({ name }) }),
    onSuccess: changed,
  });
}

export function useOpenFolder() {
  const changed = useProjectChange();
  return useMutation({
    mutationFn: (root?: string) =>
      api<ProjectOpenResponse>("/v2/projects/open", {
        method: "POST",
        body: JSON.stringify(root ? { root } : {}),
      }),
    onSuccess: changed,
  });
}

export function useActivateProject() {
  const changed = useProjectChange();
  return useMutation({
    mutationFn: (projectId: string) =>
      api<ProjectsResponse>(`/v2/projects/${encodeURIComponent(projectId)}/activate`, {
        method: "POST",
        body: "{}",
      }),
    onSuccess: changed,
  });
}

/** Downloads the model setup picked for this Mac, or one chosen in the model switcher. */
export function useStartDownload() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (modelId?: string) =>
      api<DownloadResponse>("/v2/setup/model/download", {
        method: "POST",
        body: JSON.stringify(modelId ? { model_id: modelId } : {}),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.setup }),
  });
}

/** Makes a downloaded model the one in use, now or when the next request starts. */
export function useSelectModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ modelId, when }: { modelId: string; when: "now" | "after_current" }) =>
      api<ModelSelectResponse>("/v2/models/select", {
        method: "POST",
        body: JSON.stringify({ model_id: modelId, when }),
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.setup });
      void client.invalidateQueries({ queryKey: keys.settings });
    },
  });
}

export function useRemoveModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (modelId: string) =>
      api<ModelRemoveResponse>("/v2/models/remove", {
        method: "POST",
        body: JSON.stringify({ model_id: modelId }),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.setup }),
  });
}

/** Lends a request waiting for a little memory what it is short by. */
export function useStartAnyway() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: (goalId: string) =>
      api<StartAnywayResponse>(`/v2/goals/${encodeURIComponent(goalId)}/start-anyway`, {
        method: "POST",
        body: "{}",
      }),
    onSuccess: refresh,
  });
}

export function useCancelDownload() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api<DownloadResponse>("/v2/setup/model/cancel", { method: "POST", body: "{}" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.setup }),
  });
}

export function useInstallDeveloperTools() {
  return useMutation({
    mutationFn: () =>
      api<DeveloperToolsInstallResponse>("/v2/setup/developer-tools/install", {
        method: "POST",
        body: "{}",
      }),
  });
}

export function usePause() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: () => api("/v2/control/pause", { method: "POST", body: "{}" }),
    onSuccess: refresh,
  });
}

export function useResume() {
  const refresh = useRefreshWork();
  return useMutation({
    mutationFn: () => api("/v2/control/resume", { method: "POST", body: "{}" }),
    onSuccess: refresh,
  });
}

export function useSaveSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<SettingsV1>) =>
      api<SettingsV1>("/v2/settings", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.settings }),
  });
}

export function useVerifyModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { runtime_path: string; model_path: string }) =>
      api<{ ok: boolean; detail: string }>("/v2/setup/model/verify", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.settings });
      void client.invalidateQueries({ queryKey: keys.setup });
    },
  });
}
