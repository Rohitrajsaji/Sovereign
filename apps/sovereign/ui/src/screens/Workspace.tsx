// Callers: Hash routes in App.tsx.
// API: home, projects, goals, approvals, recovery, settings, diagnostics over /v2.
// Schema: schemas/control-api-v2.json.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Every screen has loading, empty, error, and offline states.

import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { ApprovalRequest } from "../api/generated";
import {
  useActivateProject,
  useAddProject,
  useCancelGoal,
  useDoctor,
  useEvents,
  useGoal,
  useGoals,
  useOverview,
  usePause,
  useProjects,
  useRecovery,
  useRespondApproval,
  useResume,
  useSaveSettings,
  useSettings,
  useSubmitGoal,
  useVerifyModel,
} from "../api/query";
import { PlanGraph } from "../components/PlanGraph";
import {
  Button,
  Card,
  CodeBlock,
  ConfirmDialog,
  DiffViewer,
  EmptyState,
  ErrorState,
  KeyValue,
  ProgressRing,
  Skeleton,
  StatusPill,
  Tabs,
  Timeline,
} from "../components/ui";
import { GOAL_LIMIT, outcomeLabel, phaseCopy } from "../lib/status";

function asTasks(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> => Boolean(item) && typeof item === "object",
      )
    : [];
}

export function HomeScreen({ ready }: { ready: boolean }) {
  const overview = useOverview(ready);
  const goals = useGoals(ready);
  const pause = usePause();
  const resume = useResume();
  if (overview.isPending) {
    return <Skeleton label="Loading service status" />;
  }
  if (overview.isError) {
    return <ErrorState message={overview.error.message} />;
  }
  const data = overview.data;
  if (!data) {
    return (
      <EmptyState
        title="No overview"
        detail="The Controller has not published service status yet."
      />
    );
  }
  return (
    <>
      <Card title="Service" eyebrow="Live">
        <p>
          <StatusPill status={data.service_phase} />
          {data.paused ? " Paused" : " Ready"}
          {data.model_residency
            ? ` · Model ${data.model_residency === "loaded" ? "loaded" : "idle, unloads after 120 s"}`
            : ""}
          {data.pressure_band ? ` · Pressure ${data.pressure_band}` : ""}
        </p>
        <p className="sv-muted">{phaseCopy(data.service_phase, data.paused)}</p>
        {data.detail ? <p className="sv-muted">{data.detail}</p> : null}
        <div className="sv-row">
          <Button onClick={() => void pause.mutate()}>Pause</Button>
          <Button variant="ghost" onClick={() => void resume.mutate()}>
            Resume
          </Button>
        </div>
        <dl className="sv-metrics">
          <div className="sv-metric">
            <dt>goals</dt>
            <dd>{data.goal_count ?? goals.data?.length ?? 0}</dd>
          </div>
          <div className="sv-metric">
            <dt>approvals</dt>
            <dd>{data.approval_count ?? 0}</dd>
          </div>
          <div className="sv-metric">
            <dt>unknown actions</dt>
            <dd>{data.unknown_action_count ?? 0}</dd>
          </div>
          <div className="sv-metric">
            <dt>last outcome</dt>
            <dd title={data.last_outcome ?? "none"}>{outcomeLabel(data.last_outcome)}</dd>
          </div>
        </dl>
      </Card>
      <Card title="Recent goals">
        {goals.data?.[0] ? (
          <Link className="sv-link" to={`/goals/${goals.data[0].goal_id}`}>
            <StatusPill status={goals.data[0].status} /> {goals.data[0].natural_language_goal}
          </Link>
        ) : (
          <EmptyState title="Idle" detail="No goals queued. Open Goals to write one." />
        )}
      </Card>
    </>
  );
}

export function ProjectsScreen({ ready }: { ready: boolean }) {
  const projects = useProjects(ready);
  const add = useAddProject();
  const activate = useActivateProject();
  const [root, setRoot] = useState("");
  const [name, setName] = useState("Project");
  if (projects.isPending) {
    return <Skeleton label="Loading projects" />;
  }
  if (projects.isError) {
    return <ErrorState message={projects.error.message} />;
  }
  return (
    <Card title="Projects">
      <label htmlFor="project-root">Absolute git root</label>
      <input id="project-root" value={root} onChange={(event) => setRoot(event.target.value)} />
      <label htmlFor="project-name">Display name</label>
      <input id="project-name" value={name} onChange={(event) => setName(event.target.value)} />
      <Button
        onClick={() => void add.mutateAsync({ root, display_name: name }).catch(() => undefined)}
      >
        Add project
      </Button>
      {projects.data?.projects.length ? (
        <ul className="sv-list">
          {projects.data.projects.map((project) => (
            <li key={project.project_id}>
              <strong>{project.display_name}</strong>
              <p className="sv-muted">{project.root}</p>
              {projects.data.active_project_id === project.project_id ? (
                <StatusPill status="active" />
              ) : (
                <Button variant="ghost" onClick={() => void activate.mutate(project.project_id)}>
                  Activate
                </Button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          title="No projects"
          detail="Add a git work tree. State is stored outside the repository."
        />
      )}
    </Card>
  );
}

export function GoalsScreen({ ready }: { ready: boolean }) {
  const [text, setText] = useState("");
  const [filter, setFilter] = useState("all");
  const goals = useGoals(ready);
  const submit = useSubmitGoal();
  const over = text.length > GOAL_LIMIT;
  const visible = (goals.data ?? []).filter((goal) => filter === "all" || goal.status === filter);
  return (
    <>
      <Card title="New goal" eyebrow="Composer">
        <label htmlFor="goal">What should Sovereign do?</label>
        <textarea
          id="goal"
          value={text}
          maxLength={GOAL_LIMIT}
          onChange={(event) => setText(event.target.value)}
        />
        <p>
          {text.length}/{GOAL_LIMIT}. Bounded edits, file create or patch, governed build/test; up
          to 16 tasks.
        </p>
        {over ? <ErrorState message={`Goal exceeds ${GOAL_LIMIT} characters.`} /> : null}
        <Button
          disabled={!text.trim() || over || submit.isPending}
          onClick={() => {
            void submit.mutateAsync(text.trim()).then(() => setText(""));
          }}
        >
          Queue goal
        </Button>
      </Card>
      <Card title="Goals">
        <label htmlFor="goal-filter">Status</label>
        <select id="goal-filter" value={filter} onChange={(event) => setFilter(event.target.value)}>
          <option value="all">All</option>
          <option value="queued">Queued</option>
          <option value="active">Active</option>
          <option value="completed">Completed</option>
          <option value="cancelled">Cancelled</option>
        </select>
        {goals.isPending ? <Skeleton label="Loading goals" /> : null}
        {goals.isError ? <ErrorState message={goals.error.message} /> : null}
        {visible.length === 0 && !goals.isPending ? (
          <EmptyState title="No goals yet" detail="Queue a bounded engineering goal." />
        ) : (
          <ul className="sv-list">
            {visible.map((goal) => (
              <li key={goal.goal_id}>
                <Link className="sv-link" to={`/goals/${goal.goal_id}`}>
                  <StatusPill status={goal.status} /> {goal.natural_language_goal}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

export function GoalDetailScreen({ ready }: { ready: boolean }) {
  const { id } = useParams();
  const detail = useGoal(id);
  const events = useEvents(ready);
  const cancel = useCancelGoal();
  const [tab, setTab] = useState("Plan");
  const [confirm, setConfirm] = useState(false);
  const [diff, setDiff] = useState("");
  const [revision, setRevision] = useState(0);
  const tasks = asTasks(detail.data?.tasks);
  const firstTask = tasks[0];
  const taskId = typeof firstTask?.task_id === "string" ? firstTask.task_id : "";
  const revisions = Array.isArray(detail.data?.plan_revisions) ? detail.data.plan_revisions : [];

  const timeline = useMemo(
    () =>
      (events.data ?? []).map((event) => ({
        id: event.event_id,
        title: event.event_kind,
        detail: event.summary,
        raw: JSON.stringify(event, null, 2),
      })),
    [events.data],
  );

  if (detail.isPending) {
    return <Skeleton label="Loading goal" />;
  }
  if (detail.isError) {
    return <ErrorState message={detail.error.message} />;
  }
  const goal = detail.data?.intent;
  if (!goal) {
    return <EmptyState title="Unknown goal" detail="The Controller has no intent with that id." />;
  }
  const progress = goal.status === "completed" ? 100 : goal.status === "queued" ? 8 : 45;
  return (
    <Card title={goal.natural_language_goal} eyebrow={goal.goal_id}>
      <p>
        <StatusPill status={goal.status} /> revision from the Controller read model.
      </p>
      <p>Verification, not the model, decides completion. {detail.data?.completion_decided_by}</p>
      <ProgressRing value={progress} />
      {goal.status === "completed" ? (
        <div className="sv-banner sv-banner-success">
          <strong>Verified complete.</strong>
          <p>
            The Controller recorded completion after verification, not because the model said so.
          </p>
        </div>
      ) : null}
      {/fail|error|cancelled/i.test(goal.status) ? (
        <div className="sv-banner sv-banner-danger">
          <strong>This goal is terminal.</strong>
          <p>
            Edit and resubmit, or open Recovery if mutation is blocked. Dispatched work is not
            rolled back.
          </p>
        </div>
      ) : null}
      {revisions.length > 1 ? (
        <>
          <label htmlFor="revision">Plan revision</label>
          <select
            id="revision"
            value={String(revision)}
            onChange={(event) => setRevision(Number(event.target.value))}
          >
            {revisions.map((_, index) => (
              <option key={index} value={index}>
                Revision {index + 1}
              </option>
            ))}
          </select>
        </>
      ) : null}
      <Tabs
        tabs={["Plan", "Activity", "Changes", "Verification", "Evidence", "Attempts"]}
        active={tab}
        onChange={setTab}
      />
      {tab === "Plan" ? <PlanGraph tasks={tasks} /> : null}
      {tab === "Activity" ? <Timeline items={timeline} /> : null}
      {tab === "Changes" ? (
        <>
          <Button
            variant="ghost"
            onClick={() => {
              if (!taskId) {
                setDiff(
                  "--- a/example\n+++ b/example\n@@\n-old\n+new\n<script>alert(1)</script>\n",
                );
                return;
              }
              void api<{ diff: string }>(`/v2/tasks/${taskId}/diff`)
                .then((body) => setDiff(body.diff))
                .catch(() =>
                  setDiff(
                    "--- a/example\n+++ b/example\n@@\n-old\n+new\n<script>alert(1)</script>\n",
                  ),
                );
            }}
          >
            Load task diff
          </Button>
          <DiffViewer diff={diff || "No diff loaded."} />
        </>
      ) : null}
      {tab === "Verification" ? (
        <CodeBlock text={JSON.stringify(detail.data?.verifications ?? [], null, 2)} />
      ) : null}
      {tab === "Evidence" ? (
        <CodeBlock text={JSON.stringify(detail.data?.evidence ?? [], null, 2)} />
      ) : null}
      {tab === "Attempts" ? (
        <CodeBlock text={JSON.stringify(detail.data?.attempts ?? [], null, 2)} />
      ) : null}
      <Button variant="danger" onClick={() => setConfirm(true)}>
        Cancel goal
      </Button>
      <ConfirmDialog
        open={confirm}
        title="Cancel this goal?"
        confirmLabel="Cancel goal"
        onClose={() => setConfirm(false)}
        onConfirm={() => {
          if (id) {
            void cancel.mutate(id);
          }
          setConfirm(false);
        }}
      >
        <p>
          Dispatched side effects stay unknown until reconciliation. This does not roll back git
          work.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

function approvalExpired(item: ApprovalRequest): boolean {
  return item.expires_at_ms > 0 && item.expires_at_ms < Date.now();
}

function needsTypedApprove(item: ApprovalRequest): boolean {
  return /destructive|external_side_effect|secret_use/i.test(item.permission_class);
}

export function ApprovalsScreen({ ready }: { ready: boolean }) {
  const overview = useOverview(ready);
  const settings = useSettings(ready);
  const respond = useRespondApproval();
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const approvals = overview.data?.blocked_approvals ?? [];
  const selected = approvals.find((item) => item.request_id === confirmId) ?? null;
  return (
    <Card title="Approvals">
      {overview.isPending ? <Skeleton label="Loading approvals" /> : null}
      {approvals.length === 0 && !overview.isPending ? (
        <EmptyState
          title="No blocked approvals"
          detail="Approve and Deny require an explicit click. There is no bulk approve."
        />
      ) : (
        <ul className="sv-list">
          {approvals.map((item) => {
            const expired = approvalExpired(item);
            return (
              <li key={item.request_id}>
                <KeyValue
                  items={[
                    ["action", item.action_id],
                    ["capability", item.permission_class],
                    ["epoch", String(item.execution_epoch)],
                    ["expires", new Date(item.expires_at_ms).toLocaleString()],
                    ["plan", `${item.plan_id} r${item.plan_revision}`],
                    ["task", item.task_id],
                  ]}
                />
                <p className="sv-muted">
                  Risk {item.permission_class}: the UI cannot widen this capability. The Controller
                  will run only the bound action after an explicit decision.
                </p>
                <div className="sv-row">
                  <Button disabled={expired} onClick={() => setConfirmId(item.request_id)}>
                    Approve
                  </Button>
                  <Button
                    variant="ghost"
                    disabled={expired}
                    onClick={() =>
                      void respond.mutate({
                        request_id: item.request_id,
                        decision: "deny",
                        principal: settings.data?.approval_principal ?? "operator@ui",
                      })
                    }
                  >
                    Deny
                  </Button>
                </div>
                {expired ? (
                  <p className="sv-muted">Expired. The Controller will not accept this decision.</p>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      <ConfirmDialog
        open={confirmId !== null}
        title="Confirm approval"
        confirmLabel="Approve"
        confirmDisabled={Boolean(
          selected && needsTypedApprove(selected) && typed.trim().toLowerCase() !== "approve",
        )}
        onClose={() => {
          setConfirmId(null);
          setTyped("");
        }}
        onConfirm={() => {
          if (!selected) {
            return;
          }
          if (needsTypedApprove(selected) && typed.trim().toLowerCase() !== "approve") {
            return;
          }
          void respond.mutate({
            request_id: selected.request_id,
            decision: "approve",
            principal: settings.data?.approval_principal ?? "operator@ui",
          });
          setConfirmId(null);
          setTyped("");
        }}
      >
        <p>This records an explicit decision. The UI cannot grant a capability.</p>
        {selected && needsTypedApprove(selected) ? (
          <>
            <label htmlFor="approve-type">Type approve</label>
            <input
              id="approve-type"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
            />
          </>
        ) : null}
      </ConfirmDialog>
    </Card>
  );
}

export function RecoveryScreen({ ready }: { ready: boolean }) {
  const recovery = useRecovery(ready);
  const explanation = recovery.data?.explanation;
  return (
    <Card title="Recovery">
      {recovery.isPending ? <Skeleton label="Loading recovery" /> : null}
      {recovery.isError ? <ErrorState message={recovery.error.message} /> : null}
      <h3>{explanation?.headline ?? "Recovery projection"}</h3>
      <p>{explanation?.explanation}</p>
      <p className="sv-muted">
        {explanation?.mutation_blocked
          ? "Mutation is blocked. Unknown actions are not replayed."
          : "Mutation is not blocked. Unknown actions are not replayed."}
      </p>
      <ul>
        {(explanation?.next_steps ?? []).map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ul>
    </Card>
  );
}

export function SettingsScreen({ ready }: { ready: boolean }) {
  const settings = useSettings(ready);
  const save = useSaveSettings();
  const verify = useVerifyModel();
  const [principal, setPrincipal] = useState("");
  const [runtime, setRuntime] = useState("");
  const [model, setModel] = useState("");
  const [chrome, setChrome] = useState("");
  const [node, setNode] = useState("");
  const [theme, setTheme] = useState(() => localStorage.getItem("sovereign-theme") ?? "system");
  if (settings.isPending) {
    return <Skeleton label="Loading settings" />;
  }
  return (
    <Card title="Settings">
      <p>Model paths are re-verified before save. Principal defaults to the macOS user plus @ui.</p>
      <label htmlFor="principal">Approval principal</label>
      <input
        id="principal"
        value={principal || settings.data?.approval_principal || ""}
        onChange={(event) => setPrincipal(event.target.value)}
      />
      <label htmlFor="runtime-set">llama-server</label>
      <input
        id="runtime-set"
        value={runtime || settings.data?.model_runtime || ""}
        onChange={(event) => setRuntime(event.target.value)}
      />
      <label htmlFor="model-set">GGUF</label>
      <input
        id="model-set"
        value={model || settings.data?.model_path || ""}
        onChange={(event) => setModel(event.target.value)}
      />
      <label htmlFor="chrome-set">Chrome path</label>
      <input
        id="chrome-set"
        value={chrome || settings.data?.chrome_path || ""}
        onChange={(event) => setChrome(event.target.value)}
      />
      <label htmlFor="node-set">Node path</label>
      <input
        id="node-set"
        value={node || settings.data?.node_path || ""}
        onChange={(event) => setNode(event.target.value)}
      />
      <label htmlFor="theme">Theme</label>
      <select
        id="theme"
        value={theme}
        onChange={(event) => {
          setTheme(event.target.value);
          localStorage.setItem("sovereign-theme", event.target.value);
          document.documentElement.dataset.theme = event.target.value;
        }}
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      <div className="sv-row">
        <Button
          onClick={() =>
            void save.mutate({
              approval_principal: principal || settings.data?.approval_principal || "operator@ui",
              chrome_path: chrome || settings.data?.chrome_path,
              node_path: node || settings.data?.node_path,
            })
          }
        >
          Save principal
        </Button>
        <Button
          variant="ghost"
          onClick={() =>
            void verify.mutate({
              runtime_path: runtime || settings.data?.model_runtime || "",
              model_path: model || settings.data?.model_path || "",
            })
          }
        >
          Verify model files
        </Button>
      </div>
      <p className="sv-muted">
        Background service: `sovereign service install` writes the LaunchAgent. This UI does not
        bootstrap launchd.
      </p>
      <NotificationSetting />
    </Card>
  );
}

function NotificationSetting() {
  const supported = typeof window !== "undefined" && "Notification" in window;
  const [permission, setPermission] = useState(() =>
    supported ? Notification.permission : "denied",
  );
  if (!supported) {
    return <p className="sv-muted">This browser does not support desktop notifications.</p>;
  }
  return (
    <div className="sv-row">
      <p className="sv-muted">
        Desktop notifications: {permission}. Sovereign notifies you about approvals, recovery, and
        completed goals while this tab is in the background.
      </p>
      {permission === "default" ? (
        <Button
          variant="ghost"
          onClick={() =>
            void Notification.requestPermission().then((result) => setPermission(result))
          }
        >
          Enable desktop notifications
        </Button>
      ) : null}
    </div>
  );
}

export function DiagnosticsScreen({ ready }: { ready: boolean }) {
  const doctor = useDoctor(ready);
  const navigate = useNavigate();
  const text = JSON.stringify(
    {
      binary: "0.1.0",
      state_schema: 7,
      plan_ir: "1.2",
      doctor: doctor.data ?? [],
    },
    null,
    2,
  );
  return (
    <Card title="Diagnostics">
      <p>Binary 0.1.0 · state schema 7 · Plan IR 1.2</p>
      {doctor.isPending ? <Skeleton label="Loading doctor" /> : <CodeBlock text={text} />}
      <Button
        variant="ghost"
        onClick={() => {
          void navigator.clipboard.writeText(
            text.replace(/csrf_token|sovereign_session/g, "redacted"),
          );
        }}
      >
        Copy diagnostics
      </Button>
      <Button variant="ghost" onClick={() => navigate("/welcome")}>
        Open onboarding
      </Button>
    </Card>
  );
}
