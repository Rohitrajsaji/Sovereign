// Callers: the Settings dialog.
// API: `ModelSwitcher`: one card per pinned model with download, switch, and remove. Switching
// while a request runs asks whether to finish it first or stop it and start again.
// Schema: SetupStatus.models (ModelOption), POST /v2/setup/model/download, /v2/models/select,
// /v2/models/remove.

import { useEffect, useMemo, useState } from "react";
import type { GoalView, ModelOption } from "../api/generated";
import {
  useCancelGoal,
  useGoals,
  useRemoveModel,
  useSelectModel,
  useSetup,
  useStartDownload,
  useSubmitGoal,
} from "../api/query";
import { downloadLine, downloadRunning } from "../lib/words";
import { Button, InlineError, ProgressBar } from "./ui";

type Plan = { modelId: string; restart: GoalView | null; when: "now" | "after_current" };

function gigabytes(mib: number): string {
  return `${Math.round(mib / 1024)} GB`;
}

function sizeLine(model: ModelOption): string {
  return `${(model.size_bytes / 1e9).toFixed(1)} GB download · best with ${gigabytes(model.recommended_memory_mib)} of memory`;
}

export function ModelSwitcher() {
  const setup = useSetup(true);
  const goals = useGoals(true);
  const download = useStartDownload();
  const select = useSelectModel();
  const remove = useRemoveModel();
  const cancel = useCancelGoal();
  const submit = useSubmitGoal();
  const [asking, setAsking] = useState<string | null>(null);
  const [plan, setPlan] = useState<Plan | null>(null);
  const running = (goals.data ?? []).find((goal) => !goal.progress.terminal && !goal.goal_id.startsWith("pending-"));
  const models = useMemo(() => setup.data?.models ?? [], [setup.data?.models]);
  const progress = setup.data?.download;

  // Finish a switch once its download is in place.
  useEffect(() => {
    if (!plan) {
      return;
    }
    const target = models.find((model) => model.id === plan.modelId);
    if (!target?.installed || select.isPending) {
      return;
    }
    setPlan(null);
    select.mutate(
      { modelId: plan.modelId, when: plan.when },
      {
        onSuccess: () => {
          if (plan.restart) {
            const text = plan.restart.natural_language_goal;
            cancel.mutate(plan.restart.goal_id, { onSuccess: () => submit.mutate(text) });
          }
        },
      },
    );
  }, [plan, models, select, cancel, submit]);

  const begin = (model: ModelOption, restart: GoalView | null, when: "now" | "after_current") => {
    setAsking(null);
    setPlan({ modelId: model.id, restart, when });
    if (!model.installed) {
      download.mutate(model.id);
    }
  };

  const choose = (model: ModelOption) => {
    if (running) {
      setAsking(model.id);
    } else {
      begin(model, null, "now");
    }
  };

  if (setup.isPending) {
    return <p className="inline-note">Checking…</p>;
  }
  const downloading = plan !== null && downloadRunning(progress);
  return (
    <div className="model-list">
      {models.map((model) => {
        const busyHere = plan?.modelId === model.id;
        return (
          <div className={`model-card${model.selected ? " model-card-current" : ""}`} key={model.id}>
            <div className="model-card-head">
              <h4>{model.display_name}</h4>
              {model.selected ? <span className="badge">In use</span> : null}
              {model.queued ? <span className="badge">Starts with your next request</span> : null}
              {model.recommended && !model.selected ? <span className="badge badge-quiet">Suggested for this Mac</span> : null}
            </div>
            <p className="muted">{model.summary}</p>
            <p className="subtle">{sizeLine(model)}</p>
            {model.fits ? null : (
              <p className="subtle">This Mac has less memory than this model is best with, so requests may wait for memory.</p>
            )}
            {busyHere && downloading && progress ? (
              <>
                <ProgressBar value={progress.percent} label={`Downloading ${model.display_name}`} />
                <p className="subtle">{downloadLine(progress)}</p>
              </>
            ) : null}
            {asking === model.id && running ? (
              <div className="model-ask" role="group" aria-label="A request is running">
                <p>
                  A request is running: “{running.natural_language_goal}”. Switch to {model.display_name}…
                </p>
                <div className="choice-row">
                  <Button variant="primary" onClick={() => begin(model, null, "after_current")}>
                    After it finishes
                  </Button>
                  <Button onClick={() => begin(model, running, "now")}>Stop it and start again</Button>
                  <Button variant="ghost" onClick={() => setAsking(null)}>
                    Not now
                  </Button>
                </div>
              </div>
            ) : null}
            {model.selected || asking === model.id ? null : (
              <div className="choice-row">
                {model.queued ? null : (
                  <Button busy={busyHere && (downloading || select.isPending)} disabled={plan !== null && !busyHere} onClick={() => choose(model)}>
                    {model.installed ? "Use this model" : "Download and use"}
                  </Button>
                )}
                {model.installed && !model.queued ? (
                  <Button variant="ghost" busy={remove.isPending && remove.variables === model.id} onClick={() => remove.mutate(model.id)}>
                    Remove
                  </Button>
                ) : null}
              </div>
            )}
          </div>
        );
      })}
      {progress?.phase === "failed" && plan ? <p className="inline-error">{progress.detail}</p> : null}
      <InlineError error={download.error ?? select.error ?? remove.error ?? cancel.error ?? submit.error} />
    </div>
  );
}
