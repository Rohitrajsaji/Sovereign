// Callers: App shell when setup is not finished or there is no project yet.
// API: three steps: Welcome, Getting ready (Mac check, Command Line Tools, model download),
// and the first project (new, or an existing folder).
// Schema: SetupStatus, ProjectsResponse from control-api-v2.

import { CheckCircle2, CircleDashed, Lock, RotateCcw, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import type { SetupStatus } from "../api/generated";
import { useCancelDownload, useInstallDeveloperTools, useStartDownload } from "../api/query";
import { ProjectChooser } from "../components/ProjectChooser";
import { BrandMark, Button, InlineError, ProgressBar } from "../components/ui";
import { downloadLine, downloadRunning, formatBytes, formatMib } from "../lib/words";

const STEP_NAMES = ["Welcome", "Get ready", "First project"];

function Steps({ current }: { current: number }) {
  return (
    <ol className="onboarding-steps" aria-label="Setup steps">
      {STEP_NAMES.map((name, index) => (
        <li key={name} aria-current={index === current ? "step" : undefined}>
          {index + 1}. {name}
        </li>
      ))}
    </ol>
  );
}

function Welcome({ onNext }: { onNext: () => void }) {
  return (
    <>
      <div className="brand">
        <BrandMark />
        Sovereign
      </div>
      <h1>Build apps by describing them.</h1>
      <ul className="promises">
        <li>
          <Lock aria-hidden="true" />
          <div>
            <strong>Private</strong>
            <span className="muted">The AI runs on this Mac. What you type and make stays here.</span>
          </div>
        </li>
        <li>
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>Checked</strong>
            <span className="muted">Every change is tested before it reaches your project.</span>
          </div>
        </li>
        <li>
          <RotateCcw aria-hidden="true" />
          <div>
            <strong>Undoable</strong>
            <span className="muted">Every change is saved in your project's history. Undo takes one click.</span>
          </div>
        </li>
      </ul>
      <div className="onboarding-actions">
        <span />
        <Button variant="primary" size="lg" onClick={onNext}>
          Get started
        </Button>
      </div>
    </>
  );
}

function CheckIcon({ state }: { state: "ok" | "bad" | "todo" }) {
  if (state === "ok") {
    return <CheckCircle2 className="check-icon ok" aria-label="Done" />;
  }
  if (state === "bad") {
    return <XCircle className="check-icon bad" aria-label="Needs attention" />;
  }
  return <CircleDashed className="check-icon todo" aria-label="Not done yet" />;
}

function MacCheck({ setup }: { setup: SetupStatus }) {
  const { machine } = setup;
  const ok = machine.supported && machine.problems.length === 0;
  return (
    <li className="check">
      <CheckIcon state={ok ? "ok" : "bad"} />
      <div className="check-body">
        <strong>This Mac</strong>
        {ok ? (
          <span className="muted">
            {machine.apple_silicon ? "Apple silicon" : "Mac"} · {formatMib(machine.memory_mib)} memory ·{" "}
            {formatMib(machine.free_disk_mib)} free
          </span>
        ) : (
          machine.problems.map((problem) => (
            <span key={problem} className="muted">
              {problem}
            </span>
          ))
        )}
      </div>
      <span />
    </li>
  );
}

function ToolsCheck({ setup, onRecheck }: { setup: SetupStatus; onRecheck: () => void }) {
  const install = useInstallDeveloperTools();
  const installed = setup.developer_tools.installed;
  return (
    <li className="check">
      <CheckIcon state={installed ? "ok" : "todo"} />
      <div className="check-body">
        <strong>Apple's Command Line Tools</strong>
        <span className="muted">{setup.developer_tools.detail}</span>
        {install.isSuccess ? <span className="inline-note">{install.data.detail}</span> : null}
        <InlineError error={install.error} />
      </div>
      {installed ? (
        <span />
      ) : install.isSuccess ? (
        <Button onClick={onRecheck}>Check again</Button>
      ) : (
        <Button variant="primary" busy={install.isPending} onClick={() => install.mutate()}>
          Install
        </Button>
      )}
    </li>
  );
}

function ModelCheck({ setup }: { setup: SetupStatus }) {
  const start = useStartDownload();
  const cancel = useCancelDownload();
  const ready = setup.model_ready && setup.runtime_ready;
  const running = downloadRunning(setup.download);
  const model = setup.model;
  const blocked = !setup.machine.supported || setup.machine.problems.length > 0;
  const failed = setup.download.phase === "failed";
  return (
    <li className="check">
      <CheckIcon state={ready ? "ok" : failed ? "bad" : "todo"} />
      <div className="check-body">
        <strong>Local AI model{model ? ` · ${model.display_name}` : ""}</strong>
        {ready ? (
          <span className="muted">Ready. It runs on this Mac, even offline.</span>
        ) : running ? (
          <>
            <ProgressBar value={setup.download.percent} label="Model download" />
            <span className="muted" aria-live="polite">
              {downloadLine(setup.download)}
            </span>
          </>
        ) : failed || setup.download.phase === "cancelled" ? (
          <span className="muted">{setup.download.detail}</span>
        ) : (
          <span className="muted">
            A one-time download{model ? ` of ${formatBytes(model.size_bytes)}` : ""}. You can keep
            using your Mac while it downloads.
          </span>
        )}
        <InlineError error={start.error ?? cancel.error} />
      </div>
      {ready ? (
        <span />
      ) : running ? (
        <Button busy={cancel.isPending} onClick={() => cancel.mutate()}>
          Pause
        </Button>
      ) : (
        <Button variant="primary" busy={start.isPending} disabled={blocked} onClick={() => start.mutate()}>
          {setup.download.phase === "cancelled" ? "Resume" : failed ? "Try again" : "Download"}
        </Button>
      )}
    </li>
  );
}

function GettingReady({
  setup,
  onRecheck,
  onNext,
}: {
  setup: SetupStatus | undefined;
  onRecheck: () => void;
  onNext: () => void;
}) {
  return (
    <>
      <div>
        <h1>Getting ready</h1>
        <p className="muted">Sovereign checks your Mac and sets up its AI. This happens once.</p>
      </div>
      {setup ? (
        <ul className="checklist">
          <MacCheck setup={setup} />
          <ToolsCheck setup={setup} onRecheck={onRecheck} />
          <ModelCheck setup={setup} />
        </ul>
      ) : (
        <p className="inline-note" role="status">
          Checking your Mac…
        </p>
      )}
      <div className="onboarding-actions">
        <Button variant="ghost" onClick={onNext}>
          Set up later
        </Button>
        <Button variant="primary" size="lg" disabled={!setup?.ready} onClick={onNext}>
          Continue
        </Button>
      </div>
    </>
  );
}

function FirstProject({ onDone }: { onDone: () => void }) {
  return (
    <>
      <div>
        <h1>Your first project</h1>
        <p className="muted">A project is a folder where Sovereign builds your app.</p>
      </div>
      <ProjectChooser onDone={onDone} />
    </>
  );
}

export function Onboarding({
  setup,
  hasProjects,
  initialStep = 0,
  onRecheck,
  onDone,
}: {
  setup: SetupStatus | undefined;
  hasProjects: boolean;
  initialStep?: number;
  onRecheck: () => void;
  onDone: () => void;
}) {
  const [step, setStep] = useState(initialStep);
  return (
    <main className="onboarding">
      <section className="onboarding-card" aria-labelledby="onboarding-title">
        <Steps current={step} />
        <div id="onboarding-title" className="visually-hidden">
          Set up Sovereign
        </div>
        {step === 0 ? <Welcome onNext={() => setStep(1)} /> : null}
        {step === 1 ? (
          <GettingReady
            setup={setup}
            onRecheck={onRecheck}
            onNext={() => (hasProjects ? onDone() : setStep(2))}
          />
        ) : null}
        {step === 2 ? <FirstProject onDone={onDone} /> : null}
      </section>
    </main>
  );
}
