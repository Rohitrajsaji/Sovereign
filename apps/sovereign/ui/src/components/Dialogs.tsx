// Callers: the workspace sidebar.
// API: `SettingsDialog` (model, work, notifications, and an Advanced area), `HelpDialog`,
// `NewProjectDialog`.
// Schema: SetupStatus, SettingsV1, DoctorResponse, OverviewResponse.

import { useState } from "react";
import type { OverviewResponse, SetupStatus } from "../api/generated";
import { useDoctor, usePause, useResume, useSaveSettings, useSettings, useVerifyModel } from "../api/query";
import { ProjectChooser } from "./ProjectChooser";
import { Button, Dialog, InlineError } from "./ui";

function notificationState(): NotificationPermission | "unsupported" {
  return typeof window !== "undefined" && "Notification" in window ? Notification.permission : "unsupported";
}

function Diagnostics({ enabled }: { enabled: boolean }) {
  const doctor = useDoctor(enabled);
  if (doctor.isPending) {
    return <p className="inline-note">Checking…</p>;
  }
  return (
    <ul className="diagnostics" aria-label="Diagnostics">
      {(doctor.data ?? []).map((check) => (
        <li key={check.id}>
          <span
            className={`dot ${check.status === "pass" ? "dot-success" : check.status === "warn" ? "dot-warning" : "dot-danger"}`}
            aria-hidden="true"
          />
          <span>
            <strong>{check.id}</strong> <span className="visually-hidden">{check.status}</span>
            <span className="muted"> {check.detail}</span>
            {check.fix_hint && check.status !== "pass" ? <span className="subtle"> {check.fix_hint}</span> : null}
          </span>
        </li>
      ))}
    </ul>
  );
}

function OwnModelFiles() {
  const settings = useSettings(true);
  const verify = useVerifyModel();
  const [runtime, setRuntime] = useState("");
  const [model, setModel] = useState("");
  return (
    <form
      className="field"
      onSubmit={(event) => {
        event.preventDefault();
        verify.mutate({ runtime_path: runtime.trim(), model_path: model.trim() });
      }}
    >
      <span className="field-label">Use your own model files</span>
      <label className="subtle" htmlFor="runtime-path">
        llama-server program
      </label>
      <input
        id="runtime-path"
        className="input mono"
        placeholder={settings.data?.model_runtime ?? "/path/to/llama-server"}
        value={runtime}
        onChange={(event) => setRuntime(event.target.value)}
      />
      <label className="subtle" htmlFor="model-path">
        Model file (.gguf)
      </label>
      <input
        id="model-path"
        className="input mono"
        placeholder={settings.data?.model_path ?? "/path/to/model.gguf"}
        value={model}
        onChange={(event) => setModel(event.target.value)}
      />
      <div>
        <Button type="submit" busy={verify.isPending} disabled={!runtime.trim() || !model.trim()}>
          Check and use these files
        </Button>
      </div>
      {verify.data ? (
        <p className={verify.data.ok ? "inline-note" : "inline-error"} role="status">
          {verify.data.ok ? "Saved. Sovereign will use these files." : verify.data.detail}
        </p>
      ) : null}
      <InlineError error={verify.error} />
    </form>
  );
}

function ApprovalName() {
  const settings = useSettings(true);
  const save = useSaveSettings();
  const [name, setName] = useState("");
  return (
    <form
      className="field"
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate({ approval_principal: name.trim() });
      }}
    >
      <label className="field-label" htmlFor="approval-name">
        Name recorded with your approvals
      </label>
      <div className="choice-row">
        <input
          id="approval-name"
          className="input"
          placeholder={settings.data?.approval_principal ?? "operator@ui"}
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
        <Button type="submit" busy={save.isPending} disabled={!name.trim()}>
          Save
        </Button>
      </div>
      {save.isSuccess ? <p className="inline-note">Saved.</p> : null}
      <InlineError error={save.error} />
    </form>
  );
}

export function SettingsDialog({
  open,
  onOpenChange,
  setup,
  overview,
  onOpenSetup,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  setup: SetupStatus | undefined;
  overview: OverviewResponse | undefined;
  onOpenSetup: () => void;
}) {
  const pause = usePause();
  const resume = useResume();
  const [permission, setPermission] = useState(notificationState);
  const paused = overview?.paused ?? false;
  const ready = Boolean(setup?.model_ready && setup.runtime_ready);
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Settings">
      <section className="settings-section">
        <h3>Local AI model</h3>
        <div className="settings-row">
          <span className="muted">
            {setup?.model?.display_name ?? "Model"} ·{" "}
            {ready ? "Ready on this Mac" : "Not set up yet"}
          </span>
          <Button onClick={onOpenSetup}>{ready ? "Check setup" : "Set up"}</Button>
        </div>
      </section>
      <section className="settings-section">
        <h3>Work</h3>
        <div className="settings-row">
          <span className="muted">
            {paused ? "Paused. Sovereign won't start new work." : "Sovereign works on your requests one at a time."}
          </span>
          {paused ? (
            <Button busy={resume.isPending} onClick={() => resume.mutate()}>
              Resume work
            </Button>
          ) : (
            <Button busy={pause.isPending} onClick={() => pause.mutate()}>
              Pause work
            </Button>
          )}
        </div>
        <InlineError error={pause.error ?? resume.error} />
      </section>
      <section className="settings-section">
        <h3>Notifications</h3>
        <div className="settings-row">
          <span className="muted">
            {permission === "granted"
              ? "On. Sovereign tells you when a request finishes or needs you, even in another tab."
              : permission === "denied"
                ? "Blocked in your browser's settings for this page."
                : permission === "unsupported"
                  ? "This browser can't show notifications."
                  : "Get told when a request finishes or needs you."}
          </span>
          {permission === "default" ? (
            <Button
              onClick={() => {
                void Notification.requestPermission().then(setPermission);
              }}
            >
              Turn on
            </Button>
          ) : null}
        </div>
      </section>
      <section className="settings-section">
        <details className="advanced">
          <summary>Advanced</summary>
          <div className="faq">
            <Diagnostics enabled={open} />
            <OwnModelFiles />
            <ApprovalName />
          </div>
        </details>
      </section>
    </Dialog>
  );
}

export function HelpDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Help">
      <div className="faq">
        <section>
          <h3>What can I ask for?</h3>
          <p className="muted">
            Small apps that run in a web browser: a to-do list, a calculator, a budget tracker, a page for
            your club. Then ask for changes one at a time, like “make the buttons bigger” or “add a total
            at the bottom”.
          </p>
        </section>
        <section>
          <h3>Where is my work?</h3>
          <p className="muted">
            In the project's folder. New projects are in your home folder, under Sovereign Projects. The
            Preview tab shows the app; Files shows what's inside.
          </p>
        </section>
        <section>
          <h3>How do I undo a change?</h3>
          <p className="muted">
            Choose Undo on the result. Every change is saved in the project's history, so undoing never
            loses anything else.
          </p>
        </section>
        <section>
          <h3>Does anything leave my Mac?</h3>
          <p className="muted">
            No. The AI runs on your Mac. Sovereign only uses the internet once, to download the AI model
            during setup.
          </p>
        </section>
        <section>
          <h3>Sovereign isn't responding</h3>
          <p className="muted">
            Open Terminal and type <span className="mono">sovereign</span>. That restarts it and opens
            this page again.
          </p>
        </section>
      </div>
    </Dialog>
  );
}

export function NewProjectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="New project">
      <ProjectChooser onDone={() => onOpenChange(false)} />
    </Dialog>
  );
}
