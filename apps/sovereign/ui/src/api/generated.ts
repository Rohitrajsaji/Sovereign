/** Generated from schemas/control-api-v2.json. Diff-checked by verify-ui.sh. */

export type SessionResponse = {
  authenticated: boolean;
  csrf_token: string;
  version?: string;
};

export type DoctorCheck = {
  id: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  fix_hint: string;
};

export type DoctorResponse = Array<DoctorCheck>;

export type OverviewResponse = {
  schema_version: number;
  service_phase: string;
  active_project: string | null;
  paused: boolean;
  detail?: string;
  last_outcome?: string;
  model_residency?: string;
  pressure_band?: string;
  goal_count?: number;
  approval_count?: number;
  unknown_action_count?: number;
  blocked_approvals?: Array<ApprovalRequest>;
  working?: boolean;
  pending_commands?: Array<PendingCommand>;
};

export type ApprovalRequest = {
  schema_version: number;
  request_id: string;
  action_id: string;
  plan_id: string;
  plan_revision: number;
  task_id: string;
  permission_class: string;
  execution_epoch: number;
  expires_at_ms: number;
  status: string;
};

export type ProjectRecord = {
  project_id: string;
  display_name: string;
  root: string;
  state_path: string;
  cas_root: string;
  created_at_ms: number;
  managed: boolean;
};

export type ProjectsResponse = {
  schema_version: number;
  active_project_id: string | null;
  projects: Array<ProjectRecord>;
};

export type ProjectOpenResponse = {
  cancelled: boolean;
  project?: ProjectRecord;
  projects?: ProjectsResponse;
};

export type GoalIntent = {
  schema_version: number;
  goal_id: string;
  natural_language_goal: string;
  status: string;
  submitted_at_ms: number;
};

export type GoalsResponse = Array<GoalView>;

export type ControlResponse = {
  schema_version: number;
  paused: boolean;
  reason?: string | null;
  changed_at_ms: number;
};

export type ErrorResponse = {
  error: string;
};

export type EventProjection = {
  sequence: number;
  event_id: string;
  entity_type: string;
  entity_id: string;
  event_kind: string;
  summary: string;
  occurred_at_ms: number;
};

export type EventsResponse = Array<EventProjection>;

export type RecoveryExplanation = {
  mutation_blocked: boolean;
  headline: string;
  explanation: string;
  next_steps: Array<string>;
};

export type ModelVerifyResponse = {
  ok: boolean;
  runtime_sha256: string;
  model_sha256: string;
  detail: string;
};

export type SettingsV1 = {
  schema_version: number;
  model_runtime?: string | null;
  model_path?: string | null;
  model_name?: string | null;
  chrome_path?: string | null;
  node_path?: string | null;
  execute_on_start: boolean;
  approval_principal: string;
  queued_model_id?: string | null;
};

export type GoalDetail = {
  intent: GoalIntent;
  plan_revisions: Array<unknown>;
  tasks: Array<unknown>;
  attempts: Array<unknown>;
  verifications: Array<unknown>;
  evidence: Array<unknown>;
  completion_decided_by: string;
  view?: GoalView;
};

export type ArtifactRead = {
  digest: string;
  utf8: boolean;
  text?: string | null;
  byte_len: number;
};

export type RecoveryResponse = {
  explanation: RecoveryExplanation;
};

export type GoalStep = {
  task_id: string;
  title: string;
  phase: "waiting" | "working" | "checking" | "done" | "failed" | "stopped";
};

export type GoalProgress = {
  phase: "received" | "queued" | "waiting" | "planning" | "building" | "checking" | "waiting_for_you" | "stopping" | "applying" | "done" | "failed" | "cancelled" | "not_applied" | "undone";
  headline: string;
  sentence: string;
  steps_done: number;
  steps_total: number;
  percent: number;
  terminal: boolean;
  memory?: MemoryNeed | null;
};

export type GoalOutcome = {
  schema_version: number;
  goal_id: string;
  kind: "failed" | "cancelled";
  reason_code: string;
  detail: string;
  plan_id?: string | null;
  plan_revision?: number | null;
  recorded_at_ms: number;
};

export type LandingRecord = {
  goal_id: string;
  status: "predates_landing" | "landed" | "nothing_to_land" | "blocked_by_local_changes" | "conflict" | "undone" | "failed";
  commit: string | null;
  undo_commit: string | null;
  changed_paths: Array<string>;
  detail: string | null;
  technical_detail: string | null;
  updated_at_ms: number;
};

export type GoalView = {
  schema_version: number;
  goal_id: string;
  natural_language_goal: string;
  status: string;
  submitted_at_ms: number;
  progress: GoalProgress;
  steps: Array<GoalStep>;
  outcome?: GoalOutcome | null;
  queue_position?: number | null;
  landing?: LandingRecord | null;
};

export type GoalActivity = {
  sequence: number;
  occurred_at_ms: number;
  text: string;
  tone: "info" | "success" | "warning" | "error";
};

export type GoalActivityResponse = Array<GoalActivity>;

export type PendingCommand = {
  ticket: number;
  kind: string;
  goal_id?: string | null;
  text?: string | null;
  accepted_at_ms: number;
};

export type QueuedCommandResponse = {
  accepted: boolean;
  applied: boolean;
  ticket: number;
  message: string;
};

export type MachineInfo = {
  supported: boolean;
  apple_silicon: boolean;
  memory_mib: number | null;
  free_disk_mib: number | null;
  problems: Array<string>;
};

export type DeveloperTools = {
  installed: boolean;
  detail: string;
};

export type ModelChoice = {
  id: string;
  display_name: string;
  size_bytes: number;
};

export type DownloadProgress = {
  phase: "idle" | "checking" | "downloading_runtime" | "downloading_model" | "verifying" | "done" | "failed" | "cancelled";
  bytes_done: number;
  bytes_total: number;
  percent: number;
  detail: string;
};

export type SetupStatus = {
  schema_version: number;
  machine: MachineInfo;
  developer_tools: DeveloperTools;
  model: ModelChoice | null;
  models: Array<ModelOption>;
  runtime_ready: boolean;
  model_ready: boolean;
  download: DownloadProgress;
  ready: boolean;
};

export type DownloadResponse = {
  download: DownloadProgress;
};

export type DeveloperToolsInstallResponse = {
  started: boolean;
  detail: string;
};

export type PreviewResponse = {
  available: boolean;
  url: string | null;
};

export type ProjectFile = {
  path: string;
  size_bytes: number;
};

export type ProjectFilesResponse = {
  files: Array<ProjectFile>;
  truncated: boolean;
};

export type ProjectFileContent = {
  path: string;
  size_bytes: number;
  binary: boolean;
  truncated: boolean;
  text: string;
};

export type MemoryNeed = {
  short_mib: number;
  can_start_anyway: boolean;
};

export type ModelOption = {
  id: string;
  display_name: string;
  summary: string;
  size_bytes: number;
  recommended_memory_mib: number;
  installed: boolean;
  selected: boolean;
  queued: boolean;
  fits: boolean;
  recommended: boolean;
};

export type ModelSelectResponse = {
  model_id: string;
  applies: "now" | "after_current";
};

export type ModelRemoveResponse = {
  model_id: string;
  removed: boolean;
};

export type StartAnywayResponse = {
  goal_id: string;
  lent_mib: number;
};
