// Callers: the workspace's main column.
// API: `Conversation` renders each request and Sovereign's live reply: progress, approvals,
// results with Open preview and Undo, and failures with Try again.
// Schema: GoalView, ApprovalRequest from control-api-v2. Request text, step titles, and details
// are untrusted and rendered only as text nodes.

import { AlertTriangle, CheckCircle2, CircleSlash, RotateCcw, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { ApprovalRequest, GoalView } from "../api/generated";
import {
  isQueued,
  useApplyGoal,
  useCancelGoal,
  useRespondApproval,
  useSubmitGoal,
  useUndoGoal,
} from "../api/query";
import { clockTime, permissionPhrase, STAGES, stageIndex } from "../lib/words";
import { Button, Dialog, InlineError, ProgressBar } from "./ui";

type Feedback = { message: string } | null;

/** The one-line result of a command: queued messages from the service, or nothing. */
function feedbackFrom(value: unknown): Feedback {
  return isQueued(value) ? { message: value.message } : null;
}

function Stepper({ phase }: { phase: GoalView["progress"]["phase"] }) {
  const current = stageIndex(phase);
  return (
    <ol className="stepper" aria-label="Progress">
      {STAGES.map((stage, index) => {
        const state = index < current ? "done" : index === current ? "current" : "todo";
        return (
          <li key={stage} data-state={state} aria-current={state === "current" ? "step" : undefined}>
            {stage}
          </li>
        );
      })}
    </ol>
  );
}

function StepList({ goal }: { goal: GoalView }) {
  if (goal.steps.length === 0) {
    return null;
  }
  const mark = (phase: string) => {
    switch (phase) {
      case "done":
        return "✓";
      case "failed":
        return "✕";
      case "working":
      case "checking":
        return "•";
      default:
        return "○";
    }
  };
  return (
    <ul className="steps" aria-label="Steps">
      {goal.steps.map((step) => (
        <li key={step.task_id} data-phase={step.phase}>
          <span className="step-mark" aria-hidden="true">
            {mark(step.phase)}
          </span>
          <span>{step.title}</span>
          <span className="visually-hidden">({step.phase})</span>
        </li>
      ))}
    </ul>
  );
}

function ApprovalBox({
  approval,
  goal,
  principal,
}: {
  approval: ApprovalRequest;
  goal: GoalView;
  principal: string;
}) {
  const respond = useRespondApproval();
  const [feedback, setFeedback] = useState<Feedback>(null);
  const step = goal.steps.find((candidate) => candidate.task_id === approval.task_id);
  const decide = (decision: "approve" | "deny") =>
    respond.mutate(
      { request_id: approval.request_id, decision, principal },
      { onSuccess: (value) => setFeedback(feedbackFrom(value)) },
    );
  return (
    <div className="approval" role="group" aria-label="Sovereign needs your OK">
      <p>
        <strong>Sovereign wants to {permissionPhrase(approval.permission_class)}</strong>
        {step ? (
          <>
            {" "}
            for the step “<span>{step.title}</span>”.
          </>
        ) : (
          "."
        )}
      </p>
      <p className="subtle">It won't happen unless you allow it. This request expires at {clockTime(approval.expires_at_ms)}.</p>
      <div className="reply-actions">
        <Button variant="primary" busy={respond.isPending && respond.variables?.decision === "approve"} onClick={() => decide("approve")}>
          Allow
        </Button>
        <Button busy={respond.isPending && respond.variables?.decision === "deny"} onClick={() => decide("deny")}>
          Don't allow
        </Button>
      </div>
      {feedback ? <p className="inline-note">{feedback.message}</p> : null}
      <InlineError error={respond.error} />
    </div>
  );
}

function LiveReply({
  goal,
  approvals,
  principal,
  onDetails,
}: {
  goal: GoalView;
  approvals: ApprovalRequest[];
  principal: string;
  onDetails: () => void;
}) {
  const cancel = useCancelGoal();
  const [confirming, setConfirming] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const { progress } = goal;
  const pending = goal.goal_id.startsWith("pending-");
  const staged = stageIndex(progress.phase) >= 0;
  // Stopping work that began differs from cancelling a request still in line.
  const started = goal.status === "active_plan" || goal.status === "claimed_for_plan_compilation";
  const needsAttention = progress.phase === "waiting_for_you" || progress.phase === "waiting";
  const dot = needsAttention ? "dot-warning" : started ? "dot-working" : "";
  return (
    <div className="reply" aria-live="polite">
      <div className="reply-head">
        <span className={`dot ${dot}`} aria-hidden="true" />
        <h2>{progress.headline}</h2>
        {progress.steps_total > 0 ? (
          <span className="subtle">
            Step {Math.min(progress.steps_done + 1, progress.steps_total)} of {progress.steps_total}
          </span>
        ) : null}
      </div>
      {staged ? <Stepper phase={progress.phase} /> : null}
      {progress.percent > 0 ? <ProgressBar value={progress.percent} label="Request progress" /> : null}
      <p className="reply-sentence">{progress.sentence}</p>
      <StepList goal={goal} />
      {approvals.map((approval) => (
        <ApprovalBox key={approval.request_id} approval={approval} goal={goal} principal={principal} />
      ))}
      {pending ? null : (
        <div className="reply-actions">
          {progress.phase === "stopping" ? null : (
            <Button variant="danger" busy={cancel.isPending} onClick={() => setConfirming(true)}>
              {started ? "Stop" : "Cancel"}
            </Button>
          )}
          <button type="button" className="link-button" onClick={onDetails}>
            Details
          </button>
        </div>
      )}
      {feedback ? <p className="inline-note">{feedback.message}</p> : null}
      <InlineError error={cancel.error} />
      <Dialog
        open={confirming}
        onOpenChange={setConfirming}
        title={started ? "Stop this request?" : "Cancel this request?"}
        description={
          started
            ? "Sovereign stops working on it. Nothing in your project changes."
            : "It won't start. Nothing in your project changes."
        }
      >
        <div className="dialog-actions">
          <Button onClick={() => setConfirming(false)}>{started ? "Keep working" : "Keep it"}</Button>
          <Button
            variant="primary"
            onClick={() => {
              setConfirming(false);
              cancel.mutate(goal.goal_id, { onSuccess: (value) => setFeedback(feedbackFrom(value)) });
            }}
          >
            {started ? "Stop request" : "Cancel request"}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}

function FinishedReply({
  goal,
  onShowPreview,
  onDetails,
  onRetry,
}: {
  goal: GoalView;
  onShowPreview: () => void;
  onDetails: () => void;
  onRetry: (text: string) => void;
}) {
  const undo = useUndoGoal();
  const apply = useApplyGoal();
  const [feedback, setFeedback] = useState<Feedback>(null);
  const { progress, landing } = goal;
  const phase = progress.phase;
  const tone =
    phase === "done" ? "tone-success" : phase === "not_applied" ? "tone-warning" : phase === "failed" ? "tone-danger" : "tone-muted";
  const Icon =
    phase === "done" ? CheckCircle2 : phase === "not_applied" ? AlertTriangle : phase === "failed" ? XCircle : phase === "undone" ? RotateCcw : CircleSlash;
  const changed = phase === "done" ? (landing?.changed_paths ?? []) : [];
  return (
    <div className={`reply ${tone}`}>
      <div className="reply-head">
        <Icon size={16} aria-hidden="true" />
        <h2>{progress.headline}</h2>
      </div>
      <p className="reply-sentence">{progress.sentence}</p>
      {changed.length > 0 ? (
        <ul className="changed" aria-label="Changed files">
          {changed.map((path) => (
            <li key={path}>{path}</li>
          ))}
        </ul>
      ) : null}
      <div className="reply-actions">
        {phase === "done" ? (
          <Button variant="primary" onClick={onShowPreview}>
            Open preview
          </Button>
        ) : null}
        {phase === "done" && landing?.status === "landed" ? (
          <Button
            busy={undo.isPending}
            onClick={() => undo.mutate(goal.goal_id, { onSuccess: (value) => setFeedback(feedbackFrom(value)) })}
          >
            Undo
          </Button>
        ) : null}
        {phase === "not_applied" ? (
          <Button
            variant="primary"
            busy={apply.isPending}
            onClick={() => apply.mutate(goal.goal_id, { onSuccess: (value) => setFeedback(feedbackFrom(value)) })}
          >
            Apply
          </Button>
        ) : null}
        {phase === "failed" || phase === "cancelled" ? (
          <Button variant={phase === "failed" ? "primary" : "secondary"} onClick={() => onRetry(goal.natural_language_goal)}>
            Try again
          </Button>
        ) : null}
        <button type="button" className="link-button" onClick={onDetails}>
          Details
        </button>
      </div>
      {feedback ? <p className="inline-note">{feedback.message}</p> : null}
      <InlineError error={undo.error ?? apply.error} />
    </div>
  );
}

export function GoalTurn({
  goal,
  approvals,
  principal,
  onShowPreview,
  onDetails,
  onRetry,
}: {
  goal: GoalView;
  approvals: ApprovalRequest[];
  principal: string;
  onShowPreview: () => void;
  onDetails: (goalId: string) => void;
  onRetry: (text: string) => void;
}) {
  return (
    <article className="turn" aria-label={`Request: ${goal.natural_language_goal.slice(0, 80)}`}>
      <p className="request">{goal.natural_language_goal}</p>
      {goal.progress.terminal ? (
        <FinishedReply
          goal={goal}
          onShowPreview={onShowPreview}
          onDetails={() => onDetails(goal.goal_id)}
          onRetry={onRetry}
        />
      ) : (
        <LiveReply
          goal={goal}
          approvals={approvals}
          principal={principal}
          onDetails={() => onDetails(goal.goal_id)}
        />
      )}
    </article>
  );
}

/** Every request in the project, oldest first, kept scrolled to the newest while you read it. */
export function Conversation({
  goals,
  approvals,
  principal,
  onShowPreview,
  onDetails,
  onRetry,
}: {
  goals: GoalView[];
  approvals: ApprovalRequest[];
  principal: string;
  onShowPreview: () => void;
  onDetails: (goalId: string) => void;
  onRetry: (text: string) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const last = goals.at(-1);
  const lastKey = last ? `${goals.length}:${last.progress.phase}:${last.progress.percent}` : "";
  useEffect(() => {
    const element = scroller.current;
    if (!element || !lastKey) {
      return;
    }
    const nearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 240;
    if (nearBottom) {
      element.scrollTop = element.scrollHeight;
    }
  }, [lastKey]);
  const activeGoal = goals.find((goal) => goal.status === "active_plan");
  return (
    <div className="conversation" ref={scroller}>
      <div className="conversation-inner">
        {goals.map((goal) => (
          <GoalTurn
            key={goal.goal_id}
            goal={goal}
            approvals={goal === activeGoal ? approvals : []}
            principal={principal}
            onShowPreview={onShowPreview}
            onDetails={onDetails}
            onRetry={onRetry}
          />
        ))}
      </div>
    </div>
  );
}

/** Re-submits a request's own words. */
export function useRetry(onError: (message: string) => void) {
  const submit = useSubmitGoal();
  return (text: string) =>
    submit.mutate(text, {
      onError: (error) => onError(error instanceof Error ? error.message : String(error)),
    });
}
