// Callers: SPA screens via TanStack Query.
// API: typed /v2 queries and mutations. SSE invalidates the read model.
// Schema: schemas/control-api-v2.json.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. All data comes from TanStack Query plus SSE invalidation.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { api, connectEvents, setCsrfToken } from "./client";
import type {
  DoctorResponse,
  GoalDetail,
  GoalIntent,
  OverviewResponse,
  ProjectsResponse,
  RecoveryExplanation,
  SessionResponse,
  SettingsV1,
} from "./generated";

export const keys = {
  session: ["session"] as const,
  overview: ["overview"] as const,
  doctor: ["doctor"] as const,
  projects: ["projects"] as const,
  goals: ["goals"] as const,
  goal: (id: string) => ["goal", id] as const,
  events: ["events"] as const,
  recovery: ["recovery"] as const,
  settings: ["settings"] as const,
};

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

export function useOverview(enabled: boolean) {
  return useQuery({
    queryKey: keys.overview,
    queryFn: () => api<OverviewResponse>("/v2/overview"),
    enabled,
  });
}

export function useDoctor(enabled: boolean) {
  return useQuery({
    queryKey: keys.doctor,
    queryFn: () => api<DoctorResponse>("/v2/doctor"),
    enabled,
  });
}

export function useProjects(enabled: boolean) {
  return useQuery({
    queryKey: keys.projects,
    queryFn: () => api<ProjectsResponse>("/v2/projects"),
    enabled,
  });
}

export function useGoals(enabled: boolean) {
  return useQuery({
    queryKey: keys.goals,
    queryFn: () => api<GoalIntent[]>("/v2/goals"),
    enabled,
  });
}

export function useGoal(id: string | undefined) {
  return useQuery({
    queryKey: keys.goal(id ?? ""),
    queryFn: () => api<GoalDetail>(`/v2/goals/${id}`),
    enabled: Boolean(id),
  });
}

export function useEvents(enabled: boolean) {
  return useQuery({
    queryKey: keys.events,
    queryFn: () =>
      api<
        Array<{
          sequence: number;
          event_id: string;
          summary: string;
          event_kind: string;
          occurred_at_ms: number;
        }>
      >("/v2/events"),
    enabled,
  });
}

export function useRecovery(enabled: boolean) {
  return useQuery({
    queryKey: keys.recovery,
    queryFn: () => api<{ explanation: RecoveryExplanation }>("/v2/recovery"),
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

export function useInvalidateOnEvents(ready: boolean) {
  const client = useQueryClient();
  useEffect(() => {
    if (!ready) {
      return;
    }
    return connectEvents(() => {
      void client.invalidateQueries();
    });
  }, [client, ready]);
}

export function useSubmitGoal() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (goal: string) =>
      api<GoalIntent>("/v2/goals", { method: "POST", body: JSON.stringify({ goal }) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.goals }),
  });
}

export function usePause() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api("/v2/control/pause", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.overview }),
  });
}

export function useResume() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api("/v2/control/resume", { method: "POST", body: "{}" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.overview }),
  });
}

export function useCancelGoal() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (goalId: string) => api(`/v2/goals/${goalId}/cancel`, { method: "POST", body: "{}" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.goals }),
  });
}

export function useRespondApproval() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { request_id: string; decision: "approve" | "deny"; principal: string }) =>
      api("/v2/approvals/respond", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.overview }),
  });
}

export function useAddProject() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { root: string; display_name: string }) =>
      api<ProjectsResponse>("/v2/projects", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.projects }),
  });
}

export function useActivateProject() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) =>
      api(`/v2/projects/${projectId}/activate`, { method: "POST", body: "{}" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.projects }),
  });
}

export function useVerifyModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { runtime_path: string; model_path: string }) =>
      api("/v2/setup/model/verify", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.settings }),
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
